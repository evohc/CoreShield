use core_affinity::CoreId;
use std::process;

fn main() {
    let target_core = CoreId { id: 5 };
    if core_affinity::set_for_current(target_core) {
        println!("Runing on core 6.");
    } else {
        panic!("Error, could not pin to Core 6.");
    }

    println!(
        "Master process spinner is running. PID is {}",
        process::id()
    );

    loop {
        std::hint::spin_loop();
    }
}
