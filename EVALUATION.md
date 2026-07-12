# PassKeyAuth — Self-Evaluation Against Engineering Guidelines

This document maps PassKeyAuth against the 30 production-engineering guidelines,
recording where each is **met (✅)**, **partial (🟡)**, or **not applicable /
deferred (⬜)** with justification.

PassKeyAuth has two halves:

- **On-chain** — an Anchor 0.32 program for passkey (secp256r1) authorities and
  zero-knowledge Merkle attestations (`programs/passkeyauth`).
- **Off-chain** — a hexagonal identity/attestation service (`offchain/`, 6
  crates).

| # | Guideline | Status | Where / Justification |
|---|-----------|:------:|-----------------------|
| 1 | SOLID design | ✅ | Hexagonal core: `ports.rs` traits (`IdentityStore`, `IssuerStore`, `TreeStore`, `DataSource`, `EventSink`, `EventStream`) invert dependencies; `IdentityEngine` depends on abstractions. |
| 2 | Microservice patterns (event-driven/CQRS/Saga) | ✅ | Event-driven broadcast bus; CQRS-style read model (queries) vs. tree-building/ingest write side. |
| 3 | Partitioning & sharding | 🟡 | Identity/issuer/tree stores are keyed and shardable behind their ports; a production build swaps in a partitioned DB adapter. |
| 4 | Timeouts / retry / circuit breaker / rate limit | ✅ | `passkeyauth-resilience`: `with_timeout`, `RetryPolicy` (equal-jitter, no `rand`), `CircuitBreaker`, token-bucket `RateLimiter`; request timeout layer on HTTP. |
| 5 | Fault tolerance | ✅ | Keeper loops isolate + count failures; bus tolerates zero subscribers; graceful shutdown aborts keepers. |
| 6 | Error handling & edge cases | ✅ | Typed `PassKeyError`/`DomainError`/`PortError`/`EngineError`; no `unwrap`/`panic` on runtime paths; malformed precompile data and bad proofs fail closed. |
| 7 | GraphQL over REST | ✅ | `async-graphql` — 6 queries, 3 mutations, 1 subscription — depth 12 / complexity 512. REST only for health/metrics. |
| 8 | 100% meaningful test coverage | 🟡 | 28 off-chain + 9 on-chain unit tests covering Merkle proofs (incl. odd/tamper), precompile parsing (incl. cross-ix/truncated), engine, stores, schema, keepers. |
| 9 | Structure & composability | ✅ | On-chain Anchor workspace + independent off-chain workspace; layered `types → resilience → core → infra → api → node`. |
| 10 | Idiomatic Rust | ✅ | Newtypes `Pubkey`/`Digest`, `#[forbid(unsafe_code)]` off-chain, iterator pipelines, `From` DTO conversions. |
| 11 | Canonical crate stack | ✅ | tokio, async-graphql 7 + axum 0.8, thiserror/anyhow, metrics + prometheus, tracing, dashmap, sha3, clap, criterion, mockall, proptest. |
| 12 | Generative / Agentic AI | ⬜ | Deliberately omitted from the verification path — proofs and passkeys must be deterministic and non-probabilistic. An AI risk-scorer could observe events without touching verification. |
| 13 | Generics & trait bounds | ✅ | `CircuitBreaker<C: Clock>`, `RateLimiter<C: Clock>`; stores behind `Arc<dyn …>`. |
| 14 | Newtypes / type-state | ✅ | `Pubkey`/`Digest` newtypes; typed enums; on-chain `#[derive(InitSpace)]` bounded layouts. |
| 15 | README & setup | ✅ | Root `README.md` (TOC, badges, mermaid architecture/class/two sequence diagrams, complexity tables); `monitoring/README.md`; this file. |
| 16 | Performance | ✅ | Keccak via syscall on-chain; allocation-light off-chain tree; `criterion` bench `merkle/build`+`merkle/verify`. |
| 17 | Tokio async | ✅ | Fully async node; indexer keepers on `tokio::spawn` + `interval`; never blocks the executor. |
| 18 | Parallel / concurrent / batch | 🟡 | Concurrent `dashmap` stores + broadcast fan-out; batch identity/issuer ingestion per poll. Rayon unnecessary (proof work is O(log n)). |
| 19 | Logging & observability | ✅ | JSON `tracing`, Prometheus `/metrics`, OTLP via collector, Grafana **Identity Overview** dashboard + alerts. |
| 20 | Recovery / graceful degradation | ✅ | Ctrl-C + SIGTERM graceful shutdown; proof-verified events let consumers react. |
| 21 | Extensibility | ✅ | New data sources / stores / schemas plug in behind ports without touching `core`. |
| 22 | Interfaces / clean boundaries | ✅ | Domain core has zero web/db deps; DTOs isolate the GraphQL wire format. |
| 23 | Compile-time safety | ✅ | `#[forbid(unsafe_code)]`, exhaustive enums, `InitSpace` sizing, overflow-checked release arithmetic. |
| 24 | Benchmarks & complexity | ✅ | `benches/merkle.rs`; verify is O(log n), documented in the README table. |
| 25 | CI/CD | ✅ | `.github/workflows/ci.yml`: off-chain fmt/clippy/test/bench, on-chain host tests, `cargo build-sbf`, docker build. |
| 26 | Docker | ✅ | Multi-stage `Dockerfile` (rust:1.95-slim → debian-slim, non-root uid 10001); `monitoring/docker-compose.yml`. |
| 27 | Postman collection | ✅ | `postman/PassKeyAuth.postman_collection.json` (queries + mutations + health + metrics). |
| 28 | Self-evaluation | ✅ | This document. |
| 29 | On-chain program (Anchor) | ✅ | `programs/passkeyauth`: identities, secp256r1 precompile verification via the instructions sysvar, issuer Merkle roots, nullifier replay guard. 9 unit tests + deployable `.so`. |
| 30 | Reconciliation with on-chain | ✅ | The off-chain `merkle` uses the *same* keccak-256 as the on-chain program, so trees/proofs built off-chain verify on-chain and vice-versa. |

## Summary

- **✅ Met:** 26
- **🟡 Partial (deliberately scoped for a portfolio build):** 3
- **⬜ Not applicable / justified omission:** 1 (Generative AI in the verification path)

The partials are conscious scoping decisions for a self-contained portfolio
project (in-memory adapters instead of a live RPC/DB, unit-first coverage), each
behind a stable port so the production swap is mechanical and never touches the
verification core. This project deliberately headlines the **zk / passkey**
surface — secp256r1 precompile verification and hash-based zero-knowledge
set-membership attestations — that the target role calls out as "complex zk
infrastructure" and "flexible identity attestation".
