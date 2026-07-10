

# core-shield: eBPF CPU core monitoring in virtual machines

An eBPF-driven CPU core isolation and monitor demo project designed to protect critical execution threads (e.g., high-frequency trading execution loops) from user-space intrusions, kernel worker pollution, and paravirtualized hypervisor jitter. Hyper-V was the hypervisor of choice here, so this project is centered around its constructs, but a similar paradigm applies to other hypervisors like VMware vSphere. Note that Hyper-V, while installed alongside the Windows OS, is a Type 1 hypervisor. The Hyper-V hypervisor slides directly onto the bare metal, and the original Windows operating system is effectively booted on top of it, transforming it into a special, privileged virtual machine called the root partition.

eBPF has advantages over compiled kernel modules, offering superior safety, stability, and observability. Loading a classic driver introduces operational risks: a single bad pointer assignment, an unchecked array bound, or a race condition can trigger a kernel panic. Conversely, eBPF programs must pass through the strict, in-kernel eBPF verifier before they are allowed to execute. The verifier mathematically guarantees that the code cannot deadlock, cannot access unallocated memory regions, contains no infinite loops, and will not destabilize the system.

The original idea was to build a fully custom eBPF scheduler via `sched_ext`However, writing a task scheduler was far more difficult than I thought and after a few days of massive frustration this leaner option was chosen. 

## 1. Background

In a physical, bare-metal setup, hardware interrupts are physical electrical signals routed to dedicated CPUs. In a paravirtualized environment, interrupts are no longer physical; they are synthetic interrupts injected into the guest vCPU by the host hypervisor through the VMCS (Virtual Machine Control Structure). In simple terms, the guest Linux OS is fully virtualization-aware. When the host wants to sync time with a core, it writes a message directly into the VMCS memory space and triggers a virtual notification. The guest Linux kernel has paravirtualized drivers built right into its core, such as `hv_vmbus` that are actively listening for these messages. These driver frameworks are written directly by Microsoft and upstreamed into the official Linux kernel source code to facilitate optimized guest performance on underlying Windows hosts.

Under this paravirtualized architecture, hypervisor jitter manifests primarily as:

-   **HVS** (Hyper-V Synthetic Timer Ticks)
    
-   **HYP** (Hypervisor Asynchronous Callbacks)
    
`scx-shield` hooks directly into the guest kernel's low-level execution tracepoints via dual eBPF modules to capture real-time core jitter metrics and actively enforce thread residency.
A common misconception is that native Linux boot parameters provide an impenetrable boundary for dedicated tasks. The kernel utilizes standard administrative optimizations, including:

-   `isolcpus` – Removes a core from the pool of CPUs used for automated, asynchronous OS load balancing.
    
-   `nohz_full` (No HZ Full) – Instructs the kernel to stop the scheduling timer tick only if a single task maintains sole residency of the core. If a second task manages to get onto the core, the timer tick will resume in order to switch between the two tasks.
    
-   `rcu_nocbs` (Read-Copy Update No Callbacks) – A mechanism to deallocate memory at a later time via a callback. Normally, the core that triggered the deletion is the one that has to run that callback. If a CPU core is trying to run a critical, uninterrupted task, forcing it to stop and clean up memory creates a spike in latency. `rcu_nocbs` allows a different core to offload and run this cleanup work.
    
However, `isolcpus` is a suggestion to the scheduler's automatic load-balancer, not a firewall. While it successfully redirects ambient, non-targeted background tasks (like `systemd`), it explicitly respects manual overrides. When a user-space binary, a third-party daemon, or an intensive automation script executes a manual affinity assignment, it invokes the `sched_setaffinity()` system call directly. The Linux scheduler treats this as an absolute command, bypassing `isolcpus` restrictions and forcing the "intruder" onto the isolated core. This action instantly reactivates scheduling timer ticks (`nohz_full` drops out), evicts the critical thread, and invalidates L1/L2 caches.

## 2. System Components

-   **`monitor.bpf.o`:** Hooks directly into low-level tracepoints (`context_switch`, `softirq_entry`, `local_timer_entry`, `reschedule_entry`, `call_function_single_entry`, `x86_platform_ipi_entry`) to monitor and count every micro-disruption on the protected core.
    
-   **`shield.bpf.o`:** Intercepts the `sys_enter_sched_setaffinity` gateway. It checks if the protected core is the target configuration, dynamically updates the bitmask before the scheduler acts, and forwards the offender's metadata via a lockless ring buffer.
    
-   **Rust Controller Application:** Manages eBPF lifecycles, patches read-only global data variables into the BPF bytecode before verification, and outputs real-time data.
    

## 3. Testing

Core 5 (the last core on a 6-core machine) is the protected core here. To examine the intricacies of native parameters and evaluate the shield module, three tests were conducted.  There is one critical process, a spinner process running in a tight loop that aims for complete, uninterrupted hardware operation.

The following vectors were used to simulate infrastructure load for Scenarios 2 and 3:

-   **Stress Load:** 5x CPU hogs, 2x intensive asynchronous I/O loops, and a 128MB virtual memory thrashing loop bound via `taskset -c 5`.
    
-   **Intruder Load:** A compiled Rust binary executing manual affinity overrides and basic system calls.
    

### Scenario 1: Baseline (monitor)
```
================== Monitor Summary =================
Context switches:  0              
Soft irqs:         80             
Hard irqs/vectors: 115            

================== Shield Summary ==================
Total intruders blocked: 0
```
Standard parameter configurations (`isolcpus=5`, `nohz_full=5`, `rcu_nocbs=5`) were set. Steady-state telemetry captured over a 60-second baseline window proves the elimination of local Linux operating system noise, registering zero thread-eviction context switches and a bare-minimum deferred processing footprint of just 1.33 Hz in Soft IRQs.

The 1.33 Hz soft irq and 1.91 Hz hard irq metrics represent the physical baseline limit imposed by the paravirtualized architecture. While the hard irqs are a direct hypervisor 'tax', consisting of a steady-state clock synchronization heartbeat injected every ~500ms from the physical Hyper-V host via the VMCS—the soft irqs represent the minor, unavoidable deferred kernel housekeeping triggered in their wake. This proves that while the local OS scheduler can be tamed from user-space, virtualization forces an architectural baseline noise floor that cannot be bypassed by software optimization alone.

From this 60-second baseline test, we can calculate the exact profile of time stolen from the spinner by the hypervisor layer. Assuming a conservative kernel interrupt handling and eBPF processing duration of 3μs per event:

$$195 \text{ interruptions} \times 3\,\mu\text{s} = 585\,\mu\text{s} \text{ total stolen time}$$

Over the course of a full 60-second run (60,000,000μs), the hypervisor and kernel combined stole a total of 585 microseconds from the spinner. This proves that even under virtualization constraints, our optimized baseline limits stolen CPU time to just 0.000975% ($\frac{585\,\mu\text{s}}{60,000,000\,\mu\text{s}} \times 100$), ensuring the spinner maintains 99.999% absolute hardware ownership over the test window.

### Scenario 2: Unshielded (monitor)
```
================== Monitor Summary ==================
Context switches:  178580         
Soft irqs:         1037           
Hard irqs:         32927          

Pid: 11161    | Name: stress           | Switches: 7846
Pid: 11157    | Name: stress           | Switches: 6627
Pid: 11158    | Name: stress           | Switches: 7694
Pid: 11162    | Name: stress           | Switches: 7053
Pid: 11159    | Name: stress           | Switches: 55365
Pid: 11154    | Name: taskset          | Switches: 2
Pid: 11155    | Name: stress           | Switches: 7588
Pid: 11096    | Name: kworker/5:1H     | Switches: 15752
Pid: 11156    | Name: stress           | Switches: 55607
Pid: 11166    | Name: intruder         | Switches: 2
Pid: 11160    | Name: stress           | Switches: 7277

================== Shield Summary ==================
Total intruders blocked: 0
```
While native kernel-level isolation parameters successfully shield a dedicated CPU core from ambient background noise, this is not the case against intentional user-space affinity overrides. Running the stress and intruder binaries exposes a bypass of `isolcpus`. Because the Linux scheduler explicitly respects explicit `sched_setaffinity()` system calls, the core's baseline of zero context switches was drastically increased to 178,580 context switches.

This collapse of thread residency triggered a 1,200% surge in soft irqs to handle deferred virtual memory system call overhead. The intense I/O and memory pressure forced the kernel to break its own isolation boundaries, waking up its high-priority internal helper thread—`kworker/5:1H`—which logged 15,752 context switches on Core 5 to process page allocations and hardware-state transitions in kernel-space. Furthermore, because multiple tasks were now actively competing for execution slots, the kernel immediately deactivated adaptive-tickless mode, forcing a large 286x spike in hard irqs (32,927 hits) to drive the scheduling timer tick.

We use the same conservative estimate of 3μs of CPU overhead per hardware and software interrupt event. However, we must also account for the context switches. A context switch on a modern x86_64 processor running under a hypervisor involves saving/restoring CPU registers, shifting page tables, and handling scheduler logic. This is significantly more expensive than a simple interrupt hook, costing roughly 5μs of direct overhead (not including the massive indirect latency penalty of destroying L1/L2 cache locality).

-   **Soft IRQs:** $1,037 \text{ hits} \times 3\,\mu\text{s} = 3,111\,\mu\text{s}$
    
-   **Hard IRQs:** $32,927 \text{ hits} \times 3\,\mu\text{s} = 98,781\,\mu\text{s}$
    
-   **Context Switches:** $178,580 \text{ switches} \times 5\,\mu\text{s} = 892,900\,\mu\text{s}$
    

$$\text{Total Stolen Time} = 3,111\,\mu\text{s} + 98,781\,\mu\text{s} + 892,900\,\mu\text{s} = 994,792\,\mu\text{s}$$

$$\text{Core Residency Efficiency} = \frac{60,000,000\,\mu\text{s} - 994,792\,\mu\text{s}}{60,000,000\,\mu\text{s}} \times 100 = 98.34\%$$

The critical thread’s core ownership dropped from 99.999% down to 98.34%.

### Scenario 3: Shield (monitor + shield)
```
================== Monitor Summary ==================
Context switches:  0              
Soft irqs:         59             
Hard irqs:         118            

================== Shield Summary ==================
Total intruders blocked: 2
 -> Blocked pid: 11219  | Binary: taskset      | Intercepted on core: 0
 -> Blocked pid: 11230  | Binary: intruder     | Intercepted on core: 2
```
Initialized in combined mode under the exact same conditions executed in Scenario 2, the results demonstrate a deterministic defense of the spinner process. By intercepting explicit system calls inside the `sys_sched_setaffinity` gateway before execution threads could migrate, the eBPF shield successfully deflected the primary taskset driver (PID 11219) on Core 0 and the custom Rust intruder binary (PID 11230) on Core 2.

By stripping Core 5 from their targeted CPU bitmasks in-flight, the entire wave of downstream CPU stressors, memory thrashers, and high-priority `kworker` threads were quarantined to unisolated cores. Consequently, Core 5's telemetry returned to a baseline state: registering zero context switches and forcing both soft irqs (0.98 Hz) and hard irqs (1.96 Hz) back down to their native, unavoidable Hyper-V virtualization baseline.

## 4. Findings

-   Passive kernel isolation parameters (`isolcpus`) provide an adequate initial shield against ambient OS load balancing, but are fundamentally bypassed by targeted affinity system calls.
    
-   Once an "intruder" penetrates the boundary, the kernel strips out adaptive-tickless optimization (`nohz_full`), reactivating high-frequency scheduler hardware clock interrupts and pulling in internal helper threads like `kworker`.
    
-   Implementing an active eBPF syscall interceptor allows the system to enforce an active gateway policy. By scrubbing target bitmasks in kernel-space before the scheduler processes them, `scx-shield` establishes an ironclad barrier, keeping core execution perfectly quiet and optimized even inside unstable, multi-tenant virtualized environments. _Note: The actual implementation here intercepts the global syscall entry vector due to structural limitations encountered with specific tracepoint context matching inside the eBPF verifier._

> Demos are included in /assets.    

## 5. 🤖 The Role of AI Here

Ultimately, the logic implemented in this repository is run of the mill, making standard use of modern eBPF facilities. Where AI truly shone in this project was in bridging the significant knowledge gap regarding Hyper-V internal architectures and synthetic interrupt injection behaviors within guest virtual machines.

The most useful engineering utility achieved during development was the rapid, continuous iteration of alternative shield interception methodologies. Battling the constraints of the eBPF verifier across different hook implementations was drastically accelerated by Gemini. Even though a higher-level gateway hook was ultimately used for demonstration purposes, the rapid feedback loop provided an invaluable velocity boost in mapping out complex, low-level subsystem dependencies.