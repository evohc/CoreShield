#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

const volatile int SPINNER_PID = 0;
const volatile int PROTECTED_CORE = 5; //core 6

struct shield_event {
    uint32_t pid;
    uint32_t origin_core;
    char process_name[16];
};

//cant use a simple array like monitor module due to data over write issues and more importantly memory issues in case of 
// a massive amount of hits, map would blow up in size and at the very minimum drop events.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} shield_ringbuf SEC(".maps");

/*Highest level hook we can get, system call entry point... i.e. *every* user mode system call is hooked the instant it switches over to kernel.
  For a demo this is fine, however in a real system this is a hard No.  Its too intrusive and adds micro-overhead to *every* unrelated system call.  

  It is utilized here because multiple attempts at alternative targeted hooks ran afoul of strict eBPF verifier memory boundaries. This approach remains 
  infinitely safer than deploying a kernel module, where a mistake in scheduler hooking would crash the machine.
*/
SEC("tracepoint/raw_syscalls/sys_enter")
int shield_affinity_interceptor(struct trace_event_raw_sys_enter *ctx) {
    if (ctx->id != 203) return 0; //  setaffinity system call number

    uint32_t pid = bpf_get_current_pid_tgid() >> 32; //shifts out lower 32-bit thread Id (TID) anf isolate the global process Id (TGID)

    if (pid != (uint32_t)SPINNER_PID) { //lock out all processes.
        unsigned long *user_mask_ptr = (unsigned long *)ctx->args[2];
        if (!user_mask_ptr) return 0;

        unsigned long current_mask_val = 0;

        //get desired CPU core and check if its our core...
        if (bpf_probe_read_user(&current_mask_val, sizeof(current_mask_val), user_mask_ptr) == 0) {
            if (current_mask_val & (1UL << PROTECTED_CORE)) {
                
                //report event to user mode.
                struct shield_event *shield_evt = bpf_ringbuf_reserve(&shield_ringbuf, sizeof(*shield_evt), 0);
                if (shield_evt) {
                    shield_evt->pid = pid;
                    shield_evt->origin_core = bpf_get_smp_processor_id();
                    bpf_get_current_comm(&shield_evt->process_name, sizeof(shield_evt->process_name));
                    bpf_ringbuf_submit(shield_evt, 0); 
                }         

                //move to core 0..
                /*
                create mask for core 6 e..g 00000000 00000000 00000000 00100000 [1UL << 5]
                invert it turning off our core e.g. 11111111 11111111 11111111 11011111 [~(1UL << 5)]
                current_mask_val & ....allows any other requested core to remain on ...e.g. A browser might reqest four cores and the 
                kernel scheduler balances threads across these 4 core. 
                */
                unsigned long modified_mask = current_mask_val & ~(1UL << PROTECTED_CORE);
                if (modified_mask == 0) modified_mask = 1UL << 0; 

                bpf_probe_write_user(user_mask_ptr, &modified_mask, sizeof(modified_mask));
            }
        }
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";