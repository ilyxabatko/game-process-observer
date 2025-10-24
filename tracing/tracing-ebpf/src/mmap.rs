use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::tracepoint,
    programs::TracePointContext,
};
use tracing_common::{EventHeader, EventKind, MmapArgs, SysMmapEvent};

use crate::maps::{EVENTS, PID_ALLOW, PidKey};

#[tracepoint(name = "sys_enter_mmap", category = "syscalls")]
pub fn sys_enter_mmap(ctx: TracePointContext) -> u32 {
    match try_sys_enter_mmap(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_sys_enter_mmap(ctx: &TracePointContext) -> Result<(), i32> {
    let pid = bpf_get_current_pid_tgid() as u32;
    if !is_allowed_pid(pid) {
        return Ok(());
    }

    // Reading syscall args directly from tracepoint context
    // offset 16 is after "__syscall_nr"
    let args: MmapArgs = unsafe { ctx.read_at(16).map_err(|_| -1)? };
    let timestamp = unsafe { bpf_ktime_get_ns() };

    let event = SysMmapEvent {
        header: EventHeader {
            ts_ns: timestamp,
            pid,
            kind: EventKind::SysMmap as u16,
            _pad: 0,
        },
        args,
    };

    unsafe {
        submit(event);
    }

    Ok(())
}

fn is_allowed_pid(pid: u32) -> bool {
    unsafe { PID_ALLOW.get(&PidKey { pid }).is_some() }
}

#[inline]
unsafe fn submit(event: SysMmapEvent) {
    if let Some(mut buffer) = EVENTS.reserve::<SysMmapEvent>(0) {
        buffer.write(event);
        buffer.submit(0);
    }
}
