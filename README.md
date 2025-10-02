# Game Process Observer
This is an **eBPF-based Process Observer** that passively monitors a target process (PID you control) to collect different trace data, process it and build baselines and surface anomalies (e.g. unusual syscalls, unexpected library calls, suspicious ptrace attempts, etc).

## Goals
The main (current) goals of the project are:
 - gain knowledge about Linux OS, its kernel and eBPF programs;
 - gain knowledge about eBPF role in Linux game anti-cheats;
 - build a demo tracing tool to catch different kinds of anomalies that target a selected process;

## Structure
TODO

## Milestones
TODO

## Build and Run
### Prerequisites
1. stable rust toolchains: `rustup toolchain install stable`
2. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
3. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)
4. [TEMP] CD into the "tracing" folder and run the program from it (`cd tracing/`)

### Run
Run the program with:

```shell
RUST_LOG=info cargo run --release --config 'target."cfg(all())".runner="sudo -E"'
```

## Current Program's Stage
At the current stage, the program is a simple syscall tracer for one process (this program's process):
```
[INFO  tracing] event: SysEnterEvent { header: EventHeader { ts_ns: 13839584701300, pid: 34918, kind: 1, _pad: 0 }, id: 9 }
[INFO  tracing] event: SysEnterEvent { header: EventHeader { ts_ns: 13839584712421, pid: 34918, kind: 1, _pad: 0 }, id: 9 }
[INFO  tracing] event: SysEnterEvent { header: EventHeader { ts_ns: 13839584765248, pid: 34918, kind: 1, _pad: 0 }, id: 13 }
[INFO  tracing] event: SysEnterEvent { header: EventHeader { ts_ns: 13839584767938, pid: 34918, kind: 1, _pad: 0 }, id: 13 }
[INFO  tracing] event: SysEnterEvent { header: EventHeader { ts_ns: 13839584785515, pid: 34918, kind: 1, _pad: 0 }, id: 1 }
[INFO  tracing] event: SysEnterEvent { header: EventHeader { ts_ns: 13839584790854, pid: 34918, kind: 1, _pad: 0 }, id: 202 }
```

Later, it'll be expanded.

## Misc
The project is under an active development. Any help/criticism is appreciated.
