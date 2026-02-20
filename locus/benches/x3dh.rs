use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use rand_core::OsRng;
use x3dh_ratchet::double_ratchet::DoubleRatchet;
use x3dh_ratchet::keys::{IdentityKeyPair, SecretKey};
use x3dh_ratchet::x3dh::{PreKeyState, initiate, respond};

fn bench_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_generation");

    group.bench_function("identity_keypair", |b| {
        b.iter(|| black_box(IdentityKeyPair::generate(&mut OsRng)));
    });

    group.bench_function("prekey_state_100", |b| {
        let identity = IdentityKeyPair::generate(&mut OsRng);
        b.iter(|| black_box(PreKeyState::generate_with_count(&mut OsRng, &identity, 100)));
    });

    group.finish();
}

fn bench_x3dh_handshake(c: &mut Criterion) {
    let mut group = c.benchmark_group("x3dh_handshake");

    let alice_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
    let bundle = bob_prekeys.public_bundle();

    group.bench_function("initiate", |b| {
        b.iter(|| black_box(initiate(&mut OsRng, &alice_identity, &bundle).unwrap()));
    });

    group.bench_function("respond", |b| {
        b.iter(|| {
            // ✅ FIX: Generate fresh state AND fresh init_result per iteration
            let mut state = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
            let bundle = state.public_bundle();
            let init_result = initiate(&mut OsRng, &alice_identity, &bundle).unwrap();

            black_box(respond(&mut state, &bob_identity, &init_result.initial_message).unwrap())
        });
    });

    group.bench_function("full_handshake", |b| {
        b.iter(|| {
            let alice = IdentityKeyPair::generate(&mut OsRng);
            let bob_identity = IdentityKeyPair::generate(&mut OsRng);
            let mut bob_state = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
            let bundle = bob_state.public_bundle();

            let init = initiate(&mut OsRng, &alice, &bundle).unwrap();
            let resp = respond(&mut bob_state, &bob_identity, &init.initial_message).unwrap();

            black_box((init, resp))
        });
    });

    group.finish();
}

fn bench_signature_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("signature_verification");

    let identity = IdentityKeyPair::generate(&mut OsRng);
    let prekeys = PreKeyState::generate(&mut OsRng, &identity).unwrap();
    let bundle = prekeys.public_bundle();

    group.bench_function("verify_bundle_signature", |b| {
        b.iter(|| {
            bundle.verify_signature().unwrap();
            black_box(())
        });
    });

    group.finish();
}

fn bench_different_opk_counts(c: &mut Criterion) {
    let mut group = c.benchmark_group("opk_generation");

    for count in [10, 50, 100, 500, 1000] {
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &count| {
            let identity = IdentityKeyPair::generate(&mut OsRng);
            b.iter(|| {
                black_box(PreKeyState::generate_with_count(
                    &mut OsRng, &identity, count,
                ))
            });
        });
    }

    group.finish();
}

/// Benchmark X3DH operations in isolation
fn bench_x3dh_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("x3dh_operations");

    let identity = IdentityKeyPair::generate(&mut OsRng);
    let prekeys = PreKeyState::generate(&mut OsRng, &identity).unwrap();
    let bundle = prekeys.public_bundle();

    group.bench_function("bundle_creation", |b| {
        b.iter(|| black_box(prekeys.public_bundle()));
    });

    group.bench_function("bundle_verification", |b| {
        b.iter(|| {
            bundle.verify_signature().unwrap();
            black_box(())
        });
    });

    group.bench_function("dh_operations_4x", |b| {
        let eph = SecretKey::generate(&mut OsRng);
        b.iter(|| {
            let dh1 = identity.secret_key().diffie_hellman(&bundle.signed_prekey);
            let dh2 = eph.diffie_hellman(&bundle.identity_key);
            let dh3 = eph.diffie_hellman(&bundle.signed_prekey);
            let dh4 = bundle
                .one_time_prekey
                .as_ref()
                .map(|opk| eph.diffie_hellman(&opk.1));
            black_box((dh1, dh2, dh3, dh4))
        });
    });

    group.finish();
}

/// Benchmark Double Ratchet initialization
fn bench_ratchet_init(c: &mut Criterion) {
    let mut group = c.benchmark_group("ratchet_init");

    let alice_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);
    let mut bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity).unwrap();
    let bundle = bob_prekeys.public_bundle();

    let alice_x3dh = initiate(&mut OsRng, &alice_identity, &bundle).unwrap();
    let bob_x3dh = respond(&mut bob_prekeys, &bob_identity, &alice_x3dh.initial_message).unwrap();
    let bob_dh = SecretKey::generate(&mut OsRng);

    group.bench_function("init_sender", |b| {
        b.iter(|| {
            black_box(DoubleRatchet::init_sender(
                &mut OsRng,
                &alice_x3dh,
                bob_dh.public_key(),
            ))
        });
    });

    group.bench_function("init_receiver", |b| {
        b.iter(|| {
            let bob_dh_local = SecretKey::generate(&mut OsRng);
            black_box(DoubleRatchet::init_receiver(
                bob_x3dh.shared_secret.clone(),
                bob_dh_local,
            ))
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_key_generation,
    bench_x3dh_handshake,
    bench_signature_verification,
    bench_different_opk_counts,
    bench_x3dh_operations,
    bench_ratchet_init,
);

criterion_main!(benches);
