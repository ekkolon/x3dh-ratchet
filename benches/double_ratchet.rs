use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use rand_core::OsRng;
use signal_protocol::double_ratchet::DoubleRatchet;
use signal_protocol::keys::{IdentityKeyPair, SecretKey};
use signal_protocol::x3dh::{PreKeyState, initiate};

fn setup_ratchet() -> (DoubleRatchet, DoubleRatchet) {
    let alice_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);

    let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
    let bundle = bob_prekeys.public_bundle();

    let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bundle).unwrap();
    let bob_x3dh = signal_protocol::x3dh::respond(
        &mut bob_prekeys,
        &bob_identity,
        &alice_x3dh.initial_message,
    )
    .unwrap();

    let bob_dh = SecretKey::generate(&mut OsRng);
    let alice_ratchet =
        DoubleRatchet::init_sender(&mut OsRng, &alice_x3dh, bob_dh.public_key()).unwrap();
    let bob_ratchet = DoubleRatchet::init_receiver(bob_x3dh.shared_secret, bob_dh);

    (alice_ratchet, bob_ratchet)
}

fn bench_encryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("encryption");

    let (mut alice, _) = setup_ratchet();
    let message = vec![0u8; 1024];

    group.bench_function("encrypt_1kb", |b| {
        b.iter(|| black_box(alice.encrypt(&message, b"").unwrap()));
    });

    group.finish();
}

fn bench_decryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("decryption");

    let (mut alice, _) = setup_ratchet();
    let message = vec![0u8; 1024];
    let _encrypted = alice.encrypt(&message, b"").unwrap();

    group.bench_function("decrypt_1kb", |b| {
        let mut alice_setup = setup_ratchet().0;
        let _encrypted_fresh = alice_setup.encrypt(&message, b"").unwrap();
        let mut _bob_setup = setup_ratchet().1;

        b.iter(|| {
            // Need fresh message each time
            let (mut a, mut b) = setup_ratchet();
            let enc = a.encrypt(&message, b"").unwrap();
            black_box(b.decrypt(&enc, b"").unwrap())
        });
    });

    group.finish();
}

fn bench_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput");

    for size in [128, 1024, 4096, 16384, 65536] {
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("encrypt", size), &size, |b, &size| {
            let (mut alice, _) = setup_ratchet();
            let message = vec![0u8; size];

            b.iter(|| black_box(alice.encrypt(&message, b"").unwrap()));
        });

        group.bench_with_input(BenchmarkId::new("decrypt", size), &size, |b, &size| {
            let message = vec![0u8; size];

            b.iter(|| {
                let (mut alice, mut bob) = setup_ratchet();
                let encrypted = alice.encrypt(&message, b"").unwrap();
                black_box(bob.decrypt(&encrypted, b"").unwrap())
            });
        });
    }

    group.finish();
}

fn bench_message_sequence(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_sequence");

    group.bench_function("10_messages", |b| {
        b.iter(|| {
            let (mut alice, mut bob) = setup_ratchet();
            let message = vec![0u8; 256];

            for _ in 0..10 {
                let encrypted = alice.encrypt(&message, b"").unwrap();
                bob.decrypt(&encrypted, b"").unwrap();
            }
        });
    });

    group.bench_function("100_messages", |b| {
        b.iter(|| {
            let (mut alice, mut bob) = setup_ratchet();
            let message = vec![0u8; 256];

            for _ in 0..100 {
                let encrypted = alice.encrypt(&message, b"").unwrap();
                bob.decrypt(&encrypted, b"").unwrap();
            }
        });
    });

    group.finish();
}

fn bench_bidirectional(c: &mut Criterion) {
    let mut group = c.benchmark_group("bidirectional");

    group.bench_function("ping_pong_10", |b| {
        b.iter(|| {
            let (mut alice, mut bob) = setup_ratchet();
            let message = vec![0u8; 256];

            for _ in 0..5 {
                let enc = alice.encrypt(&message, b"").unwrap();
                bob.decrypt(&enc, b"").unwrap();

                let enc = bob.encrypt(&message, b"").unwrap();
                alice.decrypt(&enc, b"").unwrap();
            }
        });
    });

    group.finish();
}

fn bench_out_of_order(c: &mut Criterion) {
    let mut group = c.benchmark_group("out_of_order");

    group.bench_function("skip_5_messages", |b| {
        b.iter(|| {
            let (mut alice, mut bob) = setup_ratchet();
            let message = vec![0u8; 256];

            // Encrypt 6 messages
            let mut encrypted = Vec::new();
            for _ in 0..6 {
                encrypted.push(alice.encrypt(&message, b"").unwrap());
            }

            // Decrypt in order: 5, 0, 1, 2, 3, 4
            bob.decrypt(&encrypted[5], b"").unwrap();
            for message in encrypted.iter().take(5) {
                bob.decrypt(message, b"").unwrap();
            }
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_encryption,
    bench_decryption,
    bench_throughput,
    bench_message_sequence,
    bench_bidirectional,
    bench_out_of_order
);

criterion_main!(benches);
