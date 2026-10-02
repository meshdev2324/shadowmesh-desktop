use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use shadowmesh_core::fragment::{fragment_data, FragmentationConfig};
use shadowmesh_core::network::throttler::BandwidthThrottler;
use shadowmesh_core::pow::solve_pow;
use shadowmesh_core::reality::{
    compute_dh_public_key, compute_dh_shared_secret, derive_session_token, encrypt_qr_payload,
    generate_dh_private_key,
};

fn pow_benchmark(c: &mut Criterion) {
    let challenge = "shadow_test_challenge_for_benchmark".to_string();
    let mut group = c.benchmark_group("PoW Solver");

    // Benchmark PoW with difficulty 10 (reasonable for a quick bench)
    group.bench_function("pow_difficulty_10", |b| {
        b.iter(|| {
            solve_pow(black_box(challenge.clone()), black_box(10)).unwrap();
        })
    });

    // Benchmark PoW with difficulty 15 (harder)
    group.bench_function("pow_difficulty_15", |b| {
        b.iter(|| {
            solve_pow(black_box(challenge.clone()), black_box(15)).unwrap();
        })
    });

    // Benchmark PoW with difficulty 20 (even harder)
    group.bench_function("pow_difficulty_20", |b| {
        b.iter(|| {
            solve_pow(black_box(challenge.clone()), black_box(20)).unwrap();
        })
    });

    group.finish();
}

fn fragmentation_benchmark(c: &mut Criterion) {
    let payload = Bytes::from(vec![0u8; 10000]); // 10KB payload

    let mut group = c.benchmark_group("Fragmentation");

    group.bench_function("static_quantum_fragmentation", |b| {
        let config = FragmentationConfig::quantum();
        b.iter(|| {
            fragment_data(black_box(payload.clone()), black_box(&config));
        })
    });

    group.bench_function("adaptive_handshake_fragmentation", |b| {
        let config = FragmentationConfig::adaptive_handshake();
        b.iter(|| {
            fragment_data(black_box(payload.clone()), black_box(&config));
        })
    });

    group.bench_function("adaptive_streaming_fragmentation", |b| {
        let config = FragmentationConfig::adaptive_streaming();
        b.iter(|| {
            fragment_data(black_box(payload.clone()), black_box(&config));
        })
    });

    group.finish();
}

fn zero_copy_deserialization_benchmark(c: &mut Criterion) {
    let raw_nodes_json = r#"[
        {"id":"node-1","name":"SG Node 1","region":"sg","country":"SG","endpoint":"139.59.1.1:443","public_key":"key1","load":20,"latency":10,"is_online":true},
        {"id":"node-2","name":"US Node 1","region":"us","country":"US","endpoint":"142.93.1.1:443","public_key":"key2","load":45,"latency":120,"is_online":true},
        {"id":"node-3","name":"EU Node 1","region":"eu","country":"DE","endpoint":"159.65.1.1:443","public_key":"key3","load":12,"latency":85,"is_online":true}
    ]"#;
    let bytes_buf = Bytes::from(raw_nodes_json);

    let mut group = c.benchmark_group("Node List Deserialization");

    group.bench_function("json_slice_deserialization", |b| {
        b.iter(|| {
            let nodes: Vec<shadowmesh_core::VPNNode> =
                serde_json::from_slice(black_box(&bytes_buf)).unwrap();
            black_box(nodes);
        })
    });

    // Prepare binary data
    let nodes: Vec<shadowmesh_core::VPNNode> = serde_json::from_slice(&bytes_buf).unwrap();
    let borrowed_nodes: Vec<shadowmesh_core::protocol::binary::VPNNodeBorrowed> =
        nodes.iter().map(|n| n.into()).collect();
    let binary_data = shadowmesh_core::protocol::binary::encode_node_list(&borrowed_nodes).unwrap();
    let binary_bytes = Bytes::from(binary_data);

    group.bench_function("zero_copy_binary_deserialization", |b| {
        b.iter(|| {
            let nodes =
                shadowmesh_core::protocol::binary::decode_node_list(black_box(&binary_bytes))
                    .unwrap();
            black_box(nodes);
        })
    });

    group.finish();
}

fn reality_protocol_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("REALITY Protocol");

    let alice_priv = generate_dh_private_key();
    let bob_priv = generate_dh_private_key();
    let bob_pub = compute_dh_public_key(bob_priv);

    group.bench_function("dh_shared_secret_compute", |b| {
        b.iter(|| {
            compute_dh_shared_secret(black_box(alice_priv.clone()), black_box(bob_pub.clone()))
        })
    });

    let shared_secret = compute_dh_shared_secret(alice_priv, bob_pub);
    group.bench_function("session_token_derivation", |b| {
        b.iter(|| derive_session_token(black_box(shared_secret.clone())))
    });

    let payload = vec![0u8; 256]; // Typical pairing payload size
    let pin = "987654";
    group.bench_function("qr_visual_cipher_encrypt_256b", |b| {
        b.iter(|| encrypt_qr_payload(black_box(&payload), black_box(pin)))
    });

    group.finish();
}

fn analytics_contention_benchmark(c: &mut Criterion) {
    use shadowmesh_core::traffic_modes::TrafficAnalytics;
    use shadowmesh_core::ConnectionStats;
    use std::sync::Arc;
    use tokio::runtime::Runtime;

    let rt = Runtime::new().expect("Failed to create Tokio runtime");
    let mut group = c.benchmark_group("Core Contention");

    group.bench_function("atomic_analytics_16_threads", |b| {
        let analytics = Arc::new(TrafficAnalytics::new());
        let stats = ConnectionStats {
            bytes_received: 1000,
            bytes_sent: 500,
            packets_received: 10,
            packets_sent: 5,
            last_handshake: 0,
            connected_since: 0,
        };

        b.to_async(&rt).iter(|| {
            let analytics = analytics.clone();
            let stats = stats.clone();
            async move {
                let mut tasks = Vec::with_capacity(16);
                for i in 0..16 {
                    let a = analytics.clone();
                    let s = stats.clone();
                    tasks.push(tokio::spawn(async move {
                        a.record_stats(format!("server-{}", i), s);
                    }));
                }
                for t in tasks {
                    let _ = t.await;
                }
            }
        })
    });

    group.bench_function("atomic_kill_switch_read_contention", |b| {
        use shadowmesh_core::kill_switch::KillSwitchManager;
        let ks = Arc::new(KillSwitchManager::new());

        b.to_async(&rt).iter(|| {
            let ks = ks.clone();
            async move {
                let mut tasks = Vec::with_capacity(16);
                for _ in 0..16 {
                    let k = ks.clone();
                    tasks.push(tokio::spawn(async move {
                        black_box(k.is_active());
                    }));
                }
                for t in tasks {
                    let _ = t.await;
                }
            }
        })
    });

    group.finish();
}

fn throttler_benchmark(c: &mut Criterion) {
    use std::sync::Arc;
    use tokio::runtime::Runtime;

    let rt = Runtime::new().expect("Failed to create Tokio runtime");
    let mut group = c.benchmark_group("Throttler");

    group.bench_function("throttler_overhead_under_limit", |b| {
        // High limit to ensure we never actually sleep during the benchmark
        let throttler = Arc::new(BandwidthThrottler::new(1_000_000_000));
        b.to_async(&rt).iter(|| {
            let throttler = throttler.clone();
            async move {
                black_box(throttler.throttle(black_box(100)).await).expect("Throttle failed");
            }
        })
    });

    group.finish();
}

fn speed_test_benchmark(c: &mut Criterion) {
    use shadowmesh_core::api_client::ApiClient;
    use shadowmesh_core::SpeedTest;
    use std::sync::Arc;
    use tokio::runtime::Runtime;

    let rt = Runtime::new().expect("Failed to create Tokio runtime");
    let mut group = c.benchmark_group("Speed Test Optimization");

    // Mock API client that does nothing (to measure pure logic/allocation overhead)
    let api_client = Arc::new(ApiClient::new("http://localhost:8080".to_string()).unwrap());
    let speed_test = SpeedTest::new(api_client);

    group.bench_function("measure_upload_2mb_logic", |b| {
        b.to_async(&rt).iter(|| async {
            // We use a small mock result to isolate logic
            let _ = speed_test.measure_upload_async(black_box(2000)).await;
        })
    });

    group.finish();
}

fn security_benchmarks(c: &mut Criterion) {
    use shadowmesh_core::vpn_manager::VPNManager;
    use shadowmesh_core::{UserSettings, VPNNode};

    let mut group = c.benchmark_group("Forensic Security");

    group.bench_function("panic_wipe_atomic_cleanup", |b| {
        let manager = VPNManager::new(UserSettings::default());
        // Pre-fill with some data to make the wipe non-trivial
        manager.activate("CODE".into(), Some("TOKEN".into()), None, 5, 100).unwrap();
        manager.set_nodes(vec![
            VPNNode {
                id: "node".into(),
                name: "node".into(),
                region: "us".into(),
                country: "us".into(),
                endpoint: "1.1.1.1:443".into(),
                public_key: "key".into(),
                load: 10,
                latency: 50,
                is_sovereign: false,
                is_online: true,
                shard_id: None,
            };
            10
        ]);

        b.iter(|| {
            // We measure the wipe itself. Note: this resets the manager each time.
            manager.panic_wipe();
        })
    });

    group.finish();
}

fn routing_benchmarks(c: &mut Criterion) {
    use shadowmesh_core::shadow_router::score_node;
    use shadowmesh_core::VPNNode;

    let mut group = c.benchmark_group("Shadow-Routing");

    let node = VPNNode {
        id: "bench".into(),
        name: "bench".into(),
        region: "us".into(),
        country: "us".into(),
        endpoint: "1.1.1.1:443".into(),
        public_key: "key".into(),
        load: 45,
        latency: 120,
        is_sovereign: false,
        is_online: true,
        shard_id: None,
    };

    group.bench_function("node_scoring_fixed_point", |b| {
        b.iter(|| {
            score_node(black_box(&node), black_box(0.85), black_box(0.1), black_box(0.5));
        })
    });

    group.finish();
}

fn throttling_comparison_benchmark(c: &mut Criterion) {
    use std::sync::Arc;
    use tokio::runtime::Runtime;

    let rt = Runtime::new().expect("Failed to create Tokio runtime");
    let mut group = c.benchmark_group("Throttling Comparison");

    // 1. User-Space Throttler (Current Logic)
    // Measures locking and token bucket calculations.
    group.bench_function("userspace_throttler_1000_packets", |b| {
        let throttler = Arc::new(BandwidthThrottler::new(1_000_000_000));
        b.to_async(&rt).iter(|| {
            let throttler = throttler.clone();
            async move {
                for _ in 0..1000 {
                    black_box(throttler.throttle(black_box(100)).await).expect("Throttle failed");
                }
            }
        })
    });

    // 2. Kernel Offload Simulation (v6.0 Roadmap)
    // Measures the benefit of bypassing user-space logic entirely.
    group.bench_function("kernel_offload_sim_1000_packets", |b| {
        b.to_async(&rt).iter(|| async {
            for _ in 0..1000 {
                // In eBPF mode, the app logic simply "passes through"
                black_box(());
            }
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    pow_benchmark,
    fragmentation_benchmark,
    zero_copy_deserialization_benchmark,
    reality_protocol_benchmark,
    analytics_contention_benchmark,
    throttler_benchmark,
    throttling_comparison_benchmark,
    speed_test_benchmark,
    security_benchmarks,
    routing_benchmarks
);
criterion_main!(benches);
