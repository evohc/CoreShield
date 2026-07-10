use core_affinity::CoreId;
use gethostname::gethostname;
use std::process;
fn main() {
    let target_core = CoreId { id: 5 };
    if core_affinity::set_for_current(target_core) {
        println!("Runing on core 6.");
    } else {
        panic!("Error, could not pin to Core 6.");
    }

    println!("Intruder process is running. PID is {}", process::id());

    let os_hostname = gethostname();

    match os_hostname.into_string() {
        Ok(hostname) => println!("Hostname is: {}", hostname),
        Err(_) => eprintln!("error..."),
    }

    println!("Intruder process finished");
}
