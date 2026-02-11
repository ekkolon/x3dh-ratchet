use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rand_core::OsRng;
use signal_protocol::keys::IdentityKeyPair;
use signal_protocol::x3dh::{initiate, respond, PreKeyState};

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

    // Setup
    let alice_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_identity = IdentityKeyPair::generate(&mut OsRng);
    let bob_prekeys = PreKeyState::generate(&mut OsRng, &bob_identity);
    let bundle = bob_prekeys.public_bundle();

    group.bench_function("initiate", |b| {
        b.iter(|| black_box(initiate(&mut OsRng, &alice_identity, &bundle).unwrap()));
    });

    group.bench_function("respond", |b| {
        let init_result = initiate(&mut OsRng, &alice_identity, &bundle).unwrap();

        b.iter(|| {
            let mut state = PreKeyState::generate(&mut OsRng, &bob_identity);
            black_box(respond(&mut state, &bob_identity, &init_result.initial_message).unwrap())
        });
    });

    group.bench_function("full_handshake", |b| {
        b.iter(|| {
            let alice = IdentityKeyPair::generate(&mut OsRng);
            let bob_identity = IdentityKeyPair::generate(&mut OsRng);
            let mut bob_state = PreKeyState::generate(&mut OsRng, &bob_identity);
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
    let prekeys = PreKeyState::generate(&mut OsRng, &identity);
    let bundle = prekeys.public_bundle();

    group.bench_function("verify_bundle_signature", |b| {
        b.iter(|| black_box(bundle.verify_signature().unwrap()));
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

criterion_group!(
    benches,
    bench_key_generation,
    bench_x3dh_handshake,
    bench_signature_verification,
    bench_different_opk_counts
);

criterion_main!(benches);
