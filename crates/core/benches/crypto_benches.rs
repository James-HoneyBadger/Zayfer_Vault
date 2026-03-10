use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use hb_zayfer_core::format::{encrypt_bytes, decrypt_bytes, SymmetricAlgorithm};
use hb_zayfer_core::kdf::{derive_key, generate_salt, KdfParams};

fn bench_kdf(c: &mut Criterion) {
    let mut group = c.benchmark_group("kdf");

    let passphrase = b"correct horse battery staple";
    let salt = [0x42u8; 16];

    let presets = [
        ("argon2id-default", KdfParams::default()),
        ("argon2id-low", KdfParams::argon2id(16 * 1024, 2, 1)),
        ("scrypt-default", KdfParams::scrypt(15, 8, 1)),
    ];

    for (name, params) in presets {
        group.bench_with_input(BenchmarkId::from_parameter(name), &params, |b, p| {
            b.iter(|| {
                let key = derive_key(black_box(passphrase), black_box(&salt), black_box(p))
                    .expect("derive_key should succeed");
                black_box(key);
            });
        });
    }

    group.finish();
}

fn bench_encrypt_decrypt_bytes(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypt_decrypt_bytes");

    let sizes = [1024usize, 64 * 1024, 1024 * 1024];

    for size in sizes {
        let plaintext = vec![0xAB; size];
        // Pre-derive a symmetric key for benchmarking (skip KDF cost)
        let key = generate_salt(32); // random 32-byte symmetric key

        group.bench_with_input(BenchmarkId::new("encrypt_aes", size), &size, |b, _| {
            b.iter(|| {
                let (nonce, ct) = encrypt_bytes(
                    black_box(&plaintext),
                    black_box(&key),
                    black_box(SymmetricAlgorithm::Aes256Gcm),
                )
                .expect("encrypt_bytes AES should succeed");
                black_box((nonce, ct));
            });
        });

        // Pre-encrypt for decrypt benchmarks
        let (nonce_aes, ct_aes) =
            encrypt_bytes(&plaintext, &key, SymmetricAlgorithm::Aes256Gcm).unwrap();

        group.bench_with_input(BenchmarkId::new("decrypt_aes", size), &size, |b, _| {
            b.iter(|| {
                let decrypted = decrypt_bytes(
                    black_box(&nonce_aes),
                    black_box(&ct_aes),
                    black_box(&key),
                    black_box(SymmetricAlgorithm::Aes256Gcm),
                )
                .expect("decrypt_bytes AES should succeed");
                black_box(decrypted);
            });
        });

        group.bench_with_input(BenchmarkId::new("encrypt_chacha", size), &size, |b, _| {
            b.iter(|| {
                let (nonce, ct) = encrypt_bytes(
                    black_box(&plaintext),
                    black_box(&key),
                    black_box(SymmetricAlgorithm::ChaCha20Poly1305),
                )
                .expect("encrypt_bytes ChaCha should succeed");
                black_box((nonce, ct));
            });
        });

        let (nonce_chacha, ct_chacha) =
            encrypt_bytes(&plaintext, &key, SymmetricAlgorithm::ChaCha20Poly1305).unwrap();

        group.bench_with_input(BenchmarkId::new("decrypt_chacha", size), &size, |b, _| {
            b.iter(|| {
                let decrypted = decrypt_bytes(
                    black_box(&nonce_chacha),
                    black_box(&ct_chacha),
                    black_box(&key),
                    black_box(SymmetricAlgorithm::ChaCha20Poly1305),
                )
                .expect("decrypt_bytes ChaCha should succeed");
                black_box(decrypted);
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_kdf, bench_encrypt_decrypt_bytes);
criterion_main!(benches);
