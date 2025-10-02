use aya_ebpf::macros::map;
use aya_ebpf::maps::{HashMap, RingBuf};

#[repr(C)]
pub struct PidKey {
    pub pid: u32,
}

#[map(name = "PID_ALLOW")]
pub static PID_ALLOW: HashMap<PidKey, u8> = HashMap::with_max_entries(1024, 0);

#[map(name = "EVENTS")]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0); // 1 MB
