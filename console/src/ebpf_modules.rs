use anyhow::{Context, Result};
use libbpf_rs::{Link, ObjectBuilder};
use std::path::PathBuf;
use std::time::Duration;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MonitorIntruder {
    pub count: u64,
    pub process_name: [u8; 16],
}

#[derive(Clone, Debug, PartialEq)]
pub struct ShieldIntruder {
    pub pid: u32,
    pub origin_core: u32,
    pub process_name: String,
}

pub struct MonitorModule<'a> {
    object_path: PathBuf,
    links: Vec<Link>,
    start_stats: [u64; 3],
    // Lifetime tag tells  compiler that the external libbpf_rs::Map data source
    // outlives this struct instance, preventing dangling pointers.
    stats_map: Option<&'a libbpf_rs::Map>,
    intruder_map: Option<&'a libbpf_rs::Map>,
}

impl<'a> MonitorModule<'a> {
    pub fn new(base_path: &PathBuf) -> Self {
        Self {
            object_path: base_path.join("ebpf/monitor/monitor.bpf.o"),
            links: Vec::new(),
            start_stats: [0; 3],
            stats_map: None,
            intruder_map: None,
        }
    }

    pub fn load_and_attach(&mut self, spinner_pid: u32) -> Result<()> {
        println!("\nAttempting to load: {}", self.object_path.display());

        let mut builder = ObjectBuilder::default();
        let mut open_obj = builder
            .open_file(&self.object_path)
            .context("Failed to open eBPF monitor object file")?;

        if let Some(rodata) = open_obj.map_mut("monitor.rodata") {
            let data = rodata
                .initial_value_mut() //get a raw, mutable slice into .rodata memory inside the as of yet un-loaded bytecode.
                .context("Failed to get monitor.rodata buffer")?;
            data[..4].copy_from_slice(&spinner_pid.to_ne_bytes());
            println!("Patched monitor.rodata with spinner pid: {}", spinner_pid);
        }

        // Cannot store loaded_obj inside this struct because that creates a type of circular dependency
        // (stats_map pointing back to loaded_obj). Because Rust uses raw bitwise copies  for moves
        // moving the struct would change loaded_obj's address, leaving stats_map pointing to corrupted
        // stack memory. Box::leak puts it safely on heap. (no C++ move constructor semantics!)
        // In this instance its fine to let OS clean it up...

        let loaded_obj: &'static mut libbpf_rs::Object = Box::leak(Box::new(
            open_obj
                .load()
                .context("Kernel verifier rejected the eBPF monitor code")?,
        ));

        for prog in loaded_obj.progs_iter_mut() {
            println!(
                "Binding eBPF program routine to kernel hook: {}",
                prog.name()
            );
            let link = prog
                .attach()
                .with_context(|| format!("Failed to bind to {}.", prog.name()))?;
            self.links.push(link);
        }

        let stats_map = loaded_obj
            .map("core_stats")
            .context("Failed to find 'core_stats' map")?;

        let intru_map = loaded_obj
            .map("intruder_map")
            .context("Failed to find 'intruder_map' map")?;

        self.start_stats = self.read_cpu_stats(stats_map);
        self.stats_map = Some(stats_map);
        self.intruder_map = Some(intru_map);

        Ok(())
    }

    fn read_cpu_stats(&self, map: &libbpf_rs::Map) -> [u64; 3] {
        let mut stats = [0u64; 3];
        for i in 0..3 {
            let key = (i as u32).to_ne_bytes();
            if let Ok(Some(val_bytes)) = map.lookup(&key, libbpf_rs::MapFlags::empty()) {
                let fixed_bytes: [u8; 8] = val_bytes.as_slice().try_into().unwrap_or([0; 8]);
                stats[i] = u64::from_ne_bytes(fixed_bytes);
            }
        }
        stats
    }

    pub fn print_summary(&self) -> Result<()> {
        println!("\n================== Monitor Summary ==================");
        let current_map = self.stats_map.context("Monitor map corrupted...")?;
        let end_stats = self.read_cpu_stats(current_map);

        println!(
            "Context switches:  {:<15}",
            end_stats[0] - self.start_stats[0]
        );
        println!(
            "Soft irqs:         {:<15}",
            end_stats[1] - self.start_stats[1]
        );
        println!(
            "Hard irqs:         {:<15}\n",
            end_stats[2] - self.start_stats[2]
        );

        let intrud_map = self.intruder_map.context("Intruder lookup map corrupted")?;
        let mut keys = intrud_map.keys();

        while let Some(key_bytes) = keys.next() {
            let pid = u32::from_ne_bytes(key_bytes.as_slice().try_into().unwrap_or([0; 4]));
            if let Ok(Some(val_bytes)) = intrud_map.lookup(&key_bytes, libbpf_rs::MapFlags::empty())
            {
                if val_bytes.len() >= 24 {
                    let stats: MonitorIntruder =
                        unsafe { std::ptr::read(val_bytes.as_ptr() as *const _) };
                    let name = std::str::from_utf8(&stats.process_name)
                        .unwrap_or("unknown")
                        .trim_matches(char::from(0));

                    println!(
                        "Pid: {:<8} | Name: {:<16} | Switches: {}",
                        pid, name, stats.count
                    );
                }
            }
        }
        Ok(())
    }
}

pub struct ShieldModule {
    object_path: PathBuf,
    links: Vec<Link>,
    ring_buffer: Option<libbpf_rs::RingBuffer<'static>>,
    intruders: Vec<ShieldIntruder>,
}

impl ShieldModule {
    pub fn new(base_path: &PathBuf) -> Self {
        Self {
            object_path: base_path.join("ebpf/shield/shield.bpf.o"),
            links: Vec::new(),
            ring_buffer: None,
            intruders: Vec::new(),
        }
    }

    pub fn load_and_attach(&mut self, spinner_pid: u32) -> Result<()> {
        println!("\nAttempting to load: {}", self.object_path.display());

        let mut builder = ObjectBuilder::default();
        let mut open_obj = builder
            .open_file(&self.object_path)
            .context("Failed to open eBPF shield object file")?;

        if let Some(rodata) = open_obj.map_mut("shield.rodata") {
            let data = rodata
                .initial_value_mut()
                .context("Failed to get shield.rodata buffer")?;
            data[..4].copy_from_slice(&spinner_pid.to_ne_bytes());
            println!("Patched shield.rodata with spinner pid: {}", spinner_pid);
        }

        let loaded_obj = Box::leak(Box::new(
            open_obj
                .load()
                .context("Kernel verifier rejected the eBPF shield code")?,
        ));

        for prog in loaded_obj.progs_iter_mut() {
            println!(
                "Binding eBPF program routine to kernel hook: {}",
                prog.name()
            );
            let link = prog
                .attach()
                .with_context(|| format!("Failed to bind to {}.", prog.name()))?;
            self.links.push(link);
        }

        let ringbuf_map = loaded_obj
            .map("shield_ringbuf")
            .context("Missing 'shield_ringbuf' map")?;
        let mut rb_builder = libbpf_rs::RingBufferBuilder::new();

        // Get a raw pointer to our vector, this bypasses the borrow checker and allows closures to write so we can
        // output results at end.
        let intruders_ptr = &mut self.intruders as *mut Vec<ShieldIntruder>;

        rb_builder.add(ringbuf_map, move |data: &[u8]| {
            if data.len() >= 24 {
                let pid = u32::from_ne_bytes(data[0..4].try_into().unwrap());
                let origin_core = u32::from_ne_bytes(data[4..8].try_into().unwrap());
                let process_name_raw = &data[8..24];
                let process_name = std::str::from_utf8(process_name_raw)
                    .unwrap_or("unknown")
                    .trim_matches(char::from(0))
                    .to_string();

                //No need to print in realtime

                unsafe {
                    let intruders = &mut *intruders_ptr;
                    if !intruders.iter().any(|x| x.pid == pid) {
                        intruders.push(ShieldIntruder {
                            pid,
                            origin_core,
                            process_name,
                        });
                    }
                }
            }
            0
        })?;

        self.ring_buffer = Some(
            rb_builder
                .build()
                .context("Failed to build RingBuffer handler")?,
        );
        Ok(())
    }

    pub fn consume_pending_events(&mut self) {
        if let Some(ref rb) = self.ring_buffer {
            let _ = rb.poll(Duration::from_secs(0));
        }
    }

    pub fn print_summary(&self) {
        println!("\n================== Shield Summary ==================");
        println!("Total intruders blocked: {}", self.intruders.len());
        for attacker in &self.intruders {
            println!(
                " -> Blocked pid: {:<6} | Binary: {:<12} | Intercepted on core: {}",
                attacker.pid, attacker.process_name, attacker.origin_core
            );
        }
    }

    pub fn shutdown(&mut self) {
        self.ring_buffer = None;
    }
}
