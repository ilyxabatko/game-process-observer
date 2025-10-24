#![no_std]

#[repr(u16)]
pub enum EventKind {
    SysEnter = 1,
    SysMmap = 2,
    TcpConn = 3,
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

#[repr(C)]
#[derive(Debug)]
pub struct MmapArgs {
    pub address: u64,
    pub len: u64,
    pub prot: u64,
    pub flag: u64,
    pub fd: u64,
    pub offset: u64,
}

#[repr(C)]
#[derive(Debug)]
pub struct SysMmapEvent {
    pub header: EventHeader,
    pub args: MmapArgs,
}

#[repr(C)]
#[derive(Debug)]
pub struct TcpArgs {
    pub source_address: u32,      // IPv4
    pub destination_address: u32, // IPv4
    pub source_port: u32,
    pub destination_port: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct TcpConnEvent {
    pub header: EventHeader,
    pub args: TcpArgs,
}
