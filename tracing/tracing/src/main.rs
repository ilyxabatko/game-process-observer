use aya::{
    Btf, include_bytes_aligned,
    maps::{HashMap, ring_buf::RingBuf},
};
use log::info;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::{
    signal,
    time::{Duration, sleep},
};
use tracing_common::{EventHeader, EventKind, SysEnterEvent, SysMmapEvent};

use crate::loader::Programs;

mod loader;
mod util;

/// Holds the binary data of all the eBPF programs
const BPF_ELF: &[u8] = {
    let bytes = include_bytes_aligned!("../../target/bpfel-unknown-none/debug/tracing");
    bytes
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/tracing"
    )))?;

    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    let programs = Programs::with_ebpf(&mut ebpf).with_elf_info(BPF_ELF)?;
    let btf = Btf::from_sys_fs()?;

    for (_, mut program) in programs.map {
        if !program.enabled {
            warn!("Program {} is disabled", &program.program_name);
            continue;
        }

        info!(
            "Loading and attaching: {}, {:?}",
            &program.program_name,
            program.program.prog_type()
        );
        program.load(&btf)?;
        if let Err(error) = program.attach() {
            debug!("Error attaching program {}: {error}", &program.program_name);
        }
    }

    let mut pid_allow: HashMap<_, u32, u8> = HashMap::try_from(ebpf.map_mut("PID_ALLOW").unwrap())?;
    pid_allow.insert(std::process::id(), 1, 0)?;
    let mut ring_buffer = RingBuf::try_from(ebpf.map_mut("EVENTS").unwrap()).unwrap();

    // TODO: use async fd polling like here: https://github.com/zz85/profile-bee/blob/c311ffa6833ee408ee62cf75d23620480e0a97ee/profile-bee/bin/profile-bee.rs#L232-L260
    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                println!("Exiting...");
                break;
            }
            _ = sleep(Duration::from_millis(5)) => {
               if let Some(item) = ring_buffer.next() {
                   let ptr = item.as_ptr();
                   let len = item.len();

                   let header = unsafe { &*(ptr as *const EventHeader) };
                   match header.kind {
                       kind if kind == EventKind::SysEnter as u16 => {
                            let event: &SysEnterEvent = unsafe { &*item.as_ptr().cast() };
                            info!("SysEnter event: {:?}", &event);
                       }
                       kind if kind == EventKind::SysMmap as u16 => {
                            let event: &SysMmapEvent = unsafe { &*item.as_ptr().cast() };
                            info!("SysMmap Event: {:?}", &event);
                       }
                       other => {
                           warn!("Unknown event kind: {} (len = {})", other, len);
                       }
                   }
               }
            }
        }
    }

    Ok(())
}
