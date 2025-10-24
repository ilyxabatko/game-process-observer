use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_user},
    macros::{kprobe, kretprobe, map},
    maps::HashMap,
    programs::{ProbeContext, RetProbeContext},
};
use tracing_common::{EventHeader, EventKind, TcpArgs, TcpConnEvent};

use crate::maps::{EVENTS, PID_ALLOW, PidKey};

const AF_INET: u16 = 2;
const _AF_INET6: u16 = 10;

#[map(name = "TCP_ARGS")]
static TCP_ARGS: HashMap<u32, ConnectArgs> = HashMap::with_max_entries(4096, 0);

#[repr(C)]
pub struct SockaddrIn {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: u32,
    _pad: u64,
}

// stashing this at connection entry
#[repr(C)]
struct ConnectArgs {
    fd: i32,
    uservaddr: u64, // pointer
    address_len: i32,
}

#[kprobe(function = "__sys_connect")]
pub fn enter_connect(ctx: ProbeContext) -> u32 {
    let pid = bpf_get_current_pid_tgid() as u32;
    if !is_allowed_pid(pid) {
        return 0;
    }

    let fd: i32 = ctx.arg(0).unwrap_or_default();
    let uservaddr: u64 = ctx.arg::<*const SockaddrIn>(1).unwrap_or(core::ptr::null()) as u64;
    let address_len: i32 = ctx.arg(2).unwrap_or_default();

    let args = ConnectArgs {
        fd,
        uservaddr,
        address_len,
    };

    let _ = TCP_ARGS.insert(&pid, &args, 0);

    0
}

#[kretprobe(function = "__sys_connect")]
pub fn exit_connect(_ctx: RetProbeContext) -> u32 {
    let pid = bpf_get_current_pid_tgid() as u32;
    if !is_allowed_pid(pid) {
        return 0;
    }

    let args = match unsafe { TCP_ARGS.get(&pid) } {
        Some(a) => a,
        None => return 0,
    };
    let _ = TCP_ARGS.remove(&pid);

    // IPv4 only for now
    let uservaddr_ptr = args.uservaddr as *const SockaddrIn;
    if uservaddr_ptr.is_null() || args.address_len < core::mem::size_of::<SockaddrIn>() as i32 {
        return 0;
    }

    // read user socket address
    let socket_address_in: SockaddrIn = unsafe {
        match bpf_probe_read_user(uservaddr_ptr) {
            Ok(sin) => sin,
            Err(_) => return 0,
        }
    };

    if socket_address_in.sin_family != AF_INET {
        return 0;
    }

    let tcp_args = TcpArgs {
        source_address: 0,
        destination_address: socket_address_in.sin_addr,
        source_port: 0,
        destination_port: socket_address_in.sin_port as u32,
    };

    let timestamp = unsafe { bpf_ktime_get_ns() };
    let event = TcpConnEvent {
        header: EventHeader {
            ts_ns: timestamp,
            pid,
            kind: EventKind::TcpConn as u16,
            _pad: 0,
        },
        args: tcp_args,
    };

    unsafe {
        submit(event);
    }

    0
}

fn is_allowed_pid(pid: u32) -> bool {
    unsafe { PID_ALLOW.get(&PidKey { pid }).is_some() }
}

#[inline]
unsafe fn submit(event: TcpConnEvent) {
    if let Some(mut buffer) = EVENTS.reserve::<TcpConnEvent>(0) {
        buffer.write(event);
        buffer.submit(0);
    }
}
