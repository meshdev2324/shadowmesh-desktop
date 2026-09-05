# ShadowMesh Daemon Performance & Benchmarking Guide

This document outlines the procedures for measuring and optimizing the performance of the ShadowMesh Rust daemon.

## 1. Automated Benchmarking (Criterion)

We use `criterion` for high-precision micro-benchmarks.

### Running Benchmarks
To run all daemon-specific benchmarks:
```bash
cargo bench -p shadowmesh-daemon
```

### Key Benchmark Suites
- **`ipc_performance`**: Measures latency and throughput of the Unix Domain Socket transport and JSON command processing.
- **`tunnel_lifecycle`**: Measures the latency of the orchestration logic (mocked external processes).
- **`runtime_overhead`**: Measures internal async task spawning, mutex contention in logging, and config I/O.

---

## 2. CPU Profiling (Flamegraphs)

Flamegraphs visualize where the CPU spends its time, helping identify hotspots and inefficient code paths.

### Prerequisites
Install `cargo-flamegraph`:
```bash
cargo install cargo-flamegraph
```

### Generating a Flamegraph
Run a specific benchmark with profiling enabled:
```bash
cargo flamegraph --bench ipc_performance
```
The output `flamegraph.svg` can be opened in any web browser.

> [!TIP]
> Focus on the width of the bars. Wider bars indicate functions that consume more CPU cycles. Look for unexpected deep stacks in the JSON parsing or mutex locking phases.

---

## 3. Memory Profiling (Heaptrack)

`heaptrack` captures every memory allocation and deallocation to detect leaks and fragmentation.

### Prerequisites
Install `heaptrack`:
```bash
sudo apt install heaptrack
```

### Analyzing Allocations
Run the release binary (or a benchmark) through heaptrack:
```bash
heaptrack target/release/deps/ipc_performance-<hash>
```
After the run completes, analyze the results with:
```bash
heaptrack_gui heaptrack.shadowmesh-daemon.<pid>.gz
```

> [!IMPORTANT]
> The daemon uses `jemalloc` by default. `heaptrack` will reveal how jemalloc manages the heap and if any components are causing excessive fragmentation during high-frequency IPC load.

---

## 4. Key Performance Targets

| Metric | Target (Idle) | Target (Setup) |
| :--- | :--- | :--- |
| **Memory (RSS)** | < 15 MB | < 25 MB |
| **CPU Usage** | < 0.1% | Peak < 5% |
| **IPC Latency** | < 500 μs | N/A |
| **Cold Start** | N/A | < 150 ms (excl. network) |

---

## 5. Development Workflow Integration

1.  **Baseline**: Run `cargo bench` before making any performance-sensitive changes.
2.  **Profiling**: Use `cargo flamegraph` if you notice a regression in benchmarks.
3.  **Audit**: Run `heaptrack` periodically to ensure no regression in memory footprint during long-running sessions.
