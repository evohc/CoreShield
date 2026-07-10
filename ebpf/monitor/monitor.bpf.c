//Compile once – run everywhere. exclusive to eBPF, when Clang compiles eBPF code, it appends a 
//specialized metadata section to the ELF binary containing relocation records...offers total safety compared to
//a classic kernel module whereby if it expects something at byte offset 152, it has to be at that offset. If you 
//load that driver for updated kernel where that same data field shifted the driver will read the wrong memory location
#include "../vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct intruder_details{
    uint64_t count;
    char process_names[16];
};

/* BPF_MAP_TYPE_ARRAY is globally shared across all CPUs. At first glance, hardware cache line 
   bouncing would appear to be a  bottleneck here (e.g., multiple cores writing to the same counter). 
   However, increment_core_stat() exits if CPU != 5, so core 5 is the only one that reads or writes 
   to this map. Cross-core contention and cache thrashing is eliminated.
*/
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3); //0=context switches, 1=soft interrupts,  2=hard interupts
    __type(key, uint32_t);
    __type(value, uint64_t);
} core_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH); 
    __uint(max_entries, 1024);
    __type(key, uint32_t);  //"intruder" pid
    __type(value, struct intruder_details); //count of how how times this pid attempted to jump on core 6
} intruder_map SEC(".maps");

const volatile int SPINNER_PID = 0; //allowed pid

static __always_inline void increment_core_stat(uint32_t stat_id){
    uint32_t cpu = bpf_get_smp_processor_id();
    if (cpu != 5) return; //core 6

    // Force the key onto the stack to ensure a clean pointer...otherwise verifier will complain...
    uint32_t key = stat_id;
    key &= 3;
    struct intruder_details *val = bpf_map_lookup_elem(&core_stats, &key);
    
    if (val) {
        //atomic built-in to be safe
        __sync_fetch_and_add(&val->count, 1);
    }
}

/*

Hyper-V vm hard interrupt mapping table:
  Following shows how Hyper-V para-virtualized hardware events surface in /proc/interrupts 
  versus the raw eBPF tracepoints required to catch them. Because standard 
  physical IRQ vectors are bypassed under a hypervisor, we explicitly target these 
  individual IPIs and synthetic callbacks to accurately capture Core 5 hardware jitter.

/proc/interrupts  | eBPF Hook (raw_tp/)        | Comment
----------------    --------------------------   ------------------------------------------------------------------------------------------------
HVS                 local_timer_entry	         Hyper-V Synthetic Timer, Heartbeat, host injects this pulse to maintain the VM's system clock
RES 	            reschedule_entry	         Scheduler, CPU core forces another to stop, check the run-queue for a higher-priority process
HYP                 call_function_single_entry	 Hypervisor Callback, I/O/VMBus, notify the Guest that outside data is ready,
HRE/PMI/DFR         x86_platform_ipi_entry	     x64 Platform/Hardware, HRE[Re-enlightenment]:VM is moved..N/A here
                                                                    PMI[Performance Monitoring]: CPU counters overflow
                                                                    DFR[Deferred Error]: non-fatal hardware errors
*/


//context switch hook
SEC("raw_tp/sched_switch")
int BPF_PROG(handle_context_switch, bool preempt, struct task_struct *prev, struct task_struct *next){
    
    uint32_t cpu = bpf_get_smp_processor_id(); //dont use next.  Helper API gets definite CPU hardware core that is performing the context switch.
    uint32_t pid = BPF_CORE_READ(next, pid);

    if (cpu != 5) return 0; 

    increment_core_stat(0);

    // Log the specifics to the intruder map
    if (pid != 0 && pid != SPINNER_PID) {
        struct intruder_details *details = bpf_map_lookup_elem(&intruder_map, &pid);
        if(details){
            __sync_fetch_and_add(&details->count, 1);
        }else{
            struct intruder_details initial = { .count = 1 };
            
            //bpf_get_current_comm dosnt seem to work under high stress....
            bpf_probe_read_kernel_str(&initial.process_names, sizeof(initial.process_names), next->comm);
            bpf_map_update_elem(&intruder_map, &pid, &initial, BPF_ANY);
        }
    }
    
    return 0;
}

//soft interrupt hook
SEC("raw_tp/softirq_entry")
int BPF_PROG(handle_softirq, unsigned int vec_nr){   
    increment_core_stat(1);
    return 0;
}

/* On a standard bare-metal Linux OS, NICs and system timers send signals directly to the CPU's APIC. 
   These fire standard Linux hard interrupts via irq_handler_entry. 

   However, inside a Hyper-V VM, the host hypervisor virtualizes and intercepts these hardware interrupts. 
   Instead of the usual APIC vectors, Hyper-V utilizes Inter-Processor Interrupts (IPIs) and direct hypervisor 
   synthetic callbacks (like local_timer_entry and call_function_single_entry) via the VMBus architecture.   
   Consequently, irq_handler_entry hook will remain silent in this environment.
*/

SEC("raw_tp/irq_handler_entry")
int BPF_PROG(handle_hardirq, int irq, struct irqaction *action){    
    increment_core_stat(2);
    return 0;
}

SEC("raw_tp/local_timer_entry")
int BPF_PROG(handle_local_timer, int vector) {
    increment_core_stat(2);
    return 0;
 }

SEC("raw_tp/reschedule_entry") 
int BPF_PROG(handle_reschedule_entry, int vector) {
    increment_core_stat(2);
    return 0;
 }

SEC("raw_tp/call_function_single_entry") 
int BPF_PROG(handle_call_function_single_entry, int vector) { 
    increment_core_stat(2);
    return 0;
 }

SEC("raw_tp/x86_platform_ipi_entry") 
int BPF_PROG(handle_x86_platform_ipi_entry, int vector) {
    increment_core_stat(2);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";