#![no_std]

#[repr(u16)]
pub enum EventKind {
    SysEnter = 1,
}

#[repr(C)]
#[derive(Debug)]
pub struct EventHeader {
    pub ts_ns: u64,
    pub pid: u32,
    pub kind: u16, // EventKind
    pub _pad: u16,
}

#[repr(C)]
#[derive(Debug)]
pub struct SysEnterEvent {
    pub header: EventHeader,
    pub id: u32, // syscall id
}
