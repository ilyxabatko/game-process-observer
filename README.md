# Game Process Observer
This is an **eBPF-based Process Observer** that passively monitors a target process (PID you control) to collect different trace data and logs it.

# Goal
The main goal of this project was to get familiar with eBPF and Aya-rs and get my hands it.

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
CD into `tracing` folder and **run** the program with:

```shell
RUST_LOG=info cargo run --release --config 'target."cfg(all())".runner="sudo -E"'
```
