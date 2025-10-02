use crate::maps::{EVENTS, PID_ALLOW, PidKey};
use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::tracepoint,
    programs::TracePointContext,
};
use tracing_common::{EventHeader, EventKind, SysEnterEvent};

#[repr(C, packed)]
pub struct TracePointHeader {
    pub common_type: u16,
    pub common_flags: u8,
    pub common_preempt_count: u8,
    pub common_pid: i32,
}

#[repr(C, packed)]
pub struct SysEnter {
    pub header: TracePointHeader,
    pub id: i64,
    pub args: [u64; 6],
}

#[tracepoint(name = "sys_enter", category = "raw_syscalls")]
pub fn sys_enter(ctx: TracePointContext) -> u32 {
    match try_sys_enter(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_sys_enter(ctx: &TracePointContext) -> Result<(), i32> {
    let pid = bpf_get_current_pid_tgid() as u32;
    if !is_allowed_pid(pid) {
        return Ok(());
    }

    let data: SysEnter = unsafe { ctx.read_at(0).map_err(|_| -1)? };
    let id = data.id as u32;
    let timestamp = unsafe { bpf_ktime_get_ns() };
    let event = SysEnterEvent {
        header: EventHeader {
            ts_ns: timestamp,
            pid,
            kind: EventKind::SysEnter as u16,
            _pad: 0,
        },
        id,
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
unsafe fn submit(event: SysEnterEvent) {
    if let Some(mut buffer) = EVENTS.reserve::<SysEnterEvent>(0) {
        buffer.write(event);
        buffer.submit(0);
    }
}
