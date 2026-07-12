//! Criterion benchmark for the keccak Merkle engine.
//!
//! Measures tree construction and proof verification — the operations behind
//! every attestation build and claim. Building is O(n) hashes; verification is
//! O(log n) hashes, dominated by keccak-256 throughput.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use passkeyauth_core::merkle::{verify, MerkleTree};
use std::hint::black_box;

fn leaves(n: usize) -> Vec<[u8; 32]> {
    (0..n)
        .map(|i| {
            let mut l = [0u8; 32];
            l[..8].copy_from_slice(&(i as u64).to_le_bytes());
            l
        })
        .collect()
}

fn bench_merkle(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle");
    for &n in &[16usize, 256, 4096] {
        let ls = leaves(n);
        group.bench_with_input(BenchmarkId::new("build", n), &ls, |b, ls| {
            b.iter(|| MerkleTree::from_leaves(black_box(ls.clone())))
        });
        let tree = MerkleTree::from_leaves(ls.clone());
        let (siblings, bits) = tree.proof(n / 2).unwrap();
        let root = tree.root();
        let leaf = ls[n / 2];
        group.bench_with_input(BenchmarkId::new("verify", n), &n, |b, _| {
            b.iter(|| {
                verify(
                    black_box(leaf),
                    black_box(&siblings),
                    black_box(bits),
                    black_box(root),
                )
            })
        });
    }
    group.finish();
}

criterion_group!(benches, bench_merkle);
criterion_main!(benches);
