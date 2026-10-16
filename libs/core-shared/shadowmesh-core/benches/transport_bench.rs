//! Benchmarks for the transport cryptographic paths.
//!
//! # What this is for
//!
//! Not for reporting numbers. For catching **regressions that would hurt users
//! on a throttled mobile link**, which is the environment this product runs in.
//! A VPN's per-packet cost is paid on every packet, on a phone radio, often
//! while the OS is throttling the app for battery.
//!
//! That makes AES-GCM on small packets the interesting case, not bulk
//! throughput: a 64-byte packet pays full setup cost for very little data, and
//! that is the common shape for DNS and keepalives.
//!
//! Benchmarks are not asserted in CI. A wall-clock threshold would fail on
//! shared runners and train people to ignore the gate. The value is a recorded
//! baseline to diff against when a change is suspected - see
//! `docs/perf-baseline.md`.
//!
//! GPL-free: measures our own code against primitives already in the tree.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use shadowmesh_core::protocol::ss2022_nonce::NonceCounter;
use shadowmesh_core::protocol::ss2022_stream::{read_chunk, seal_chunk, MAX_CHUNK_LEN};
use shadowmesh_core::transport::shadowsocks2022::{
    decode_psk, derive_identity_subkey, derive_session_subkey, open, random_nonce, random_salt,
    seal, Shadowsocks2022Method,
};
use shadowmesh_core::transport::tls_trust;

const METHODS: [Shadowsocks2022Method; 3] = [
    Shadowsocks2022Method::Aes128Gcm,
    Shadowsocks2022Method::Aes256Gcm,
    Shadowsocks2022Method::ChaCha20Poly1305,
];

fn psk(m: Shadowsocks2022Method) -> Vec<u8> {
    (0..m.psk_len() as u8).collect()
}

fn subkey(m: Shadowsocks2022Method) -> Vec<u8> {
    derive_session_subkey(m, &psk(m), &random_salt(m)).unwrap()
}

/// Packet sizes chosen to bracket what a tunnel actually carries: DNS replies
/// and keepalives at the small end, TCP segments in the middle, and the SS2022
/// chunk ceiling at the top.
const SIZES: [usize; 4] = [64, 512, 1400, MAX_CHUNK_LEN];

fn bench_seal(c: &mut Criterion) {
    let mut group = c.benchmark_group("ss2022/seal");
    for m in METHODS {
        let key = subkey(m);
        for size in SIZES {
            let payload = vec![0x5Au8; size];
            group.throughput(Throughput::Bytes(size as u64));
            group.bench_function(format!("{m:?}/{size}"), |b| {
                b.iter(|| {
                    let nonce = random_nonce();
                    black_box(
                        seal(
                            black_box(m),
                            black_box(&key),
                            black_box(&nonce),
                            b"hdr",
                            black_box(&payload),
                        )
                        .unwrap(),
                    )
                })
            });
        }
    }
    group.finish();
}

fn bench_open(c: &mut Criterion) {
    let mut group = c.benchmark_group("ss2022/open");
    for m in METHODS {
        let key = subkey(m);
        for size in SIZES {
            let payload = vec![0x5Au8; size];
            let nonce = random_nonce();
            let sealed = seal(m, &key, &nonce, b"hdr", &payload).unwrap();
            group.throughput(Throughput::Bytes(size as u64));
            group.bench_function(format!("{m:?}/{size}"), |b| {
                b.iter(|| {
                    black_box(
                        open(
                            black_box(m),
                            black_box(&key),
                            black_box(&nonce),
                            b"hdr",
                            black_box(&sealed),
                        )
                        .unwrap(),
                    )
                })
            });
        }
    }
    group.finish();
}

/// Session setup is the cost of *connecting*, and it runs on the critical path
/// of every reconnect - which matters on a flaky mobile network that flaps.
fn bench_key_derivation(c: &mut Criterion) {
    let mut group = c.benchmark_group("ss2022/derivation");
    for m in METHODS {
        let key_material = psk(m);
        let salt = random_salt(m);
        group.bench_function(format!("session_subkey/{m:?}"), |b| {
            b.iter(|| {
                black_box(
                    derive_session_subkey(black_box(m), black_box(&key_material), black_box(&salt))
                        .unwrap(),
                )
            })
        });
        group.bench_function(format!("identity_subkey/{m:?}"), |b| {
            b.iter(|| {
                black_box(
                    derive_identity_subkey(
                        black_box(m),
                        black_box(&key_material),
                        black_box(&salt),
                    )
                    .unwrap(),
                )
            })
        });
    }
    group.bench_function("decode_psk/aes-256", |b| {
        let encoded = {
            // Round-trip a key through base64 so the benchmark measures the real
            // decode, not a hand-written literal.
            let raw = psk(Shadowsocks2022Method::Aes256Gcm);
            raw.iter().map(|b| format!("{b:02x}")).collect::<String>()
        };
        b.iter(|| {
            black_box(decode_psk(black_box(Shadowsocks2022Method::Aes256Gcm), black_box(&encoded)))
        })
    });
    group.finish();
}

/// Framing includes the length-field seal, which is a second AEAD operation per
/// frame. Worth measuring separately, because it is overhead a naive
/// implementation would not notice.
fn bench_framing(c: &mut Criterion) {
    let mut group = c.benchmark_group("ss2022/framing");
    for m in METHODS {
        let key = subkey(m);
        for size in [64usize, 1400] {
            let payload = vec![0x11u8; size];
            group.bench_function(format!("write/{m:?}/{size}"), |b| {
                b.iter(|| {
                    let mut counter = NonceCounter::default();
                    black_box(
                        seal_chunk(
                            black_box(m),
                            black_box(&key),
                            &mut counter,
                            black_box(&payload),
                        )
                        .unwrap(),
                    )
                })
            });
            let frame = seal_chunk(m, &key, &mut NonceCounter::default(), &payload).unwrap();
            group.bench_function(format!("read/{m:?}/{size}"), |b| {
                b.iter_batched(
                    || bytes::BytesMut::from(&frame[..]),
                    |mut fresh| {
                        let mut counter = NonceCounter::default();
                        black_box(
                            read_chunk(
                                black_box(m),
                                black_box(&key),
                                &mut counter,
                                black_box(&mut fresh),
                            )
                            .unwrap()
                            .unwrap(),
                        )
                    },
                    criterion::BatchSize::SmallInput,
                )
            });
        }
    }
    group.finish();
}

/// Policy resolution runs per connection, so it must be free.
fn bench_tls_policy(c: &mut Criterion) {
    let mut group = c.benchmark_group("tls_trust/resolve");
    group.bench_function("system_roots", |b| {
        b.iter(|| black_box(tls_trust::resolve(false, None).unwrap()))
    });
    group.bench_function("pinned", |b| {
        b.iter(|| black_box(tls_trust::resolve(true, Some("aabbccdd")).unwrap()))
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_seal,
    bench_open,
    bench_key_derivation,
    bench_framing,
    bench_tls_policy
);
criterion_main!(benches);
