use anyhow::{Context, Result};
use core_affinity::CoreId;
use std::env;
use std::ffi::OsStr;
use std::thread;
use std::time::Duration;
use sysinfo::{Pid, System};
mod ebpf_modules;

pub fn get_spinner_pid() -> Option<Pid> {
    System::new_all()
        .processes_by_name(OsStr::new("spinner"))
        .next()
        .map(|process| process.pid())
}

pub fn print_usage() {
    println!("Usage: sudo ./scheduler-shield [OPTIONS]");
    println!("\nOptions:");
    println!("  --time <secs> Set the active testing window duration (Default: 20)");
    println!("  --mode <type> Specify loaded eBPF modules: 'both', 'monitor', 'shield'");
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() == 1 {
        print_usage();
        std::process::exit(1);
    }

    let mut runtime_secs = 20;
    let mut mode = "both";

    let mut arg_index = 1;
    while arg_index < args.len() {
        match args[arg_index].as_str() {
            "--time" => {
                let time_str = args
                    .get(arg_index + 1)
                    .context("Missing value for --time arg. Usage: --time <seconds>")?;
                runtime_secs = time_str.parse().context("Use whole number for seconds.")?;
                arg_index += 2;
            }
            "--mode" => {
                let mode_arg = args
                    .get(arg_index + 1)
                    .context("Missing value for --mode arg. Usage: --mode <both|monitor|shield>")?;

                if mode_arg == "both" || mode_arg == "monitor" || mode_arg == "shield" {
                    mode = mode_arg;
                } else {
                    eprintln!("Error: mode '{}'.", mode_arg);
                    println!("Use either 'both', 'monitor' or 'shield'.");
                    std::process::exit(1);
                }
                arg_index += 2;
            }
            _ => {
                print_usage();
                std::process::exit(0);
            }
        }
    }

    if core_affinity::set_for_current(CoreId { id: 0 }) {
        println!("Pinned to core 0.");
    } else {
        eprintln!("Error, could not pin process to core 0.");
        std::process::exit(1);
    }

    let spinner_pid = get_spinner_pid()
        .context("spinner process was not found.")?
        .as_u32();
    println!("Spinner pid is {}.", spinner_pid);

    let mut exe_path = env::current_exe()?;
    exe_path.pop();
    exe_path.pop();
    exe_path.pop();

    let mut monitor = ebpf_modules::MonitorModule::new(&exe_path);
    let mut shield = ebpf_modules::ShieldModule::new(&exe_path);

    let run_monitor = mode == "both" || mode == "monitor";
    let run_shield = mode == "both" || mode == "shield";

    if run_monitor {
        monitor.load_and_attach(spinner_pid)?;
    }
    if run_shield {
        shield.load_and_attach(spinner_pid)?;
    }

    println!(
        "\neBPF module(s) initialized. Running under mode '{}' for {} seconds...",
        mode, runtime_secs
    );
    thread::sleep(Duration::from_secs(runtime_secs));

    if run_monitor {
        monitor.print_summary()?;
    }

    if run_shield {
        shield.consume_pending_events(); //flush ring buffer
        shield.print_summary();
        shield.shutdown();
    }

    Ok(())
}
