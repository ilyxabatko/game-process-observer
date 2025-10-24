# Game Process Observer
This is an **eBPF-based Process Observer** that passively monitors a target process (PID you control) to collect different trace data, process it and build baselines and surface anomalies (e.g. unusual syscalls, unexpected library calls, suspicious ptrace attempts, etc).

## Goals
The main (current) goal of the project is:
 - gain knowledge about Linux OS, its kernel and eBPF programs;

## Build and Run
### Prerequisites
1. stable rust toolchains: `rustup toolchain install stable`
2. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
3. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

### Build - first one has to build an ELF file:
1. CD into `tracing/tracing-ebf`
2. Build an ELF object:
```shell
RUSTFLAGS='-C linker=bpf-linker -C link-arg=--btf --cfg bpf_target_arch="x86_64" -C panic=abort' cargo +nightly build -Z build-std=core --target bpfel-unknown-none
```

### Run
(Current approach) CD into `tracing` folder and **run** the program with:

```shell
RUST_LOG=info cargo run --release --config 'target."cfg(all())".runner="sudo -E"'
```

## Misc
The project is under development. Any help/criticism is appreciated.
