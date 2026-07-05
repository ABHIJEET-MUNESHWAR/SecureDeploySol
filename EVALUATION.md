# SecureDeploySol — Self-Evaluation Against Engineering Guidelines

Status legend: ✅ done · 🟡 partial / by-design-scoped · ⬜ not applicable

SecureDeploySol is a **full stack**: a hardened on-chain Anchor upgrade-governance
program (`anchor/`) plus a production-grade off-chain deployment-security audit
service (`crates/`), accompanied by a formal threat model ([AUDIT.md](./AUDIT.md)).
Client-server guidelines (GraphQL, SQL partitioning, rate-limiting, Postman,
Tokio, observability) are satisfied by the off-chain service; the on-chain
security core is satisfied by the Anchor program. Both are covered below.

| # | Guideline | Status | Where / how |
|---|---|---|---|
| 1 | SOLID principles | ✅ | Program: `state`/`error`/`lib` single-responsibility modules with a pure `validate_guardians`. Service: **hexagonal** crates with ports (`ProposalStore`, `FindingStore`, `EventSink`) inverted from the `AuditEngine`. |
| 2 | Microservice pattern (event-driven/CQRS/Saga) | ✅ | Program emits Anchor events (`UpgradeProposed/Approved/Executed`). Service is **event-driven**: the engine publishes `DomainEvent`s to a broadcast `EventSink` feeding GraphQL subscriptions. |
| 3 | Partitioning & sharding | ✅ | On-chain: PDA-per-object sharding (governance/proposal/approval). Off-chain: `findings` table **LIST-partitioned by severity** ([`migrations/0001_init.sql`](./migrations/0001_init.sql)). |
| 4 | Timeouts, retry, fault tolerance | ✅ | `securedeploy-resilience`: `with_timeout`, `retry` with capped exponential backoff, three-state circuit breaker (unit-tested with a manual clock). |
| 5 | Rate limiting & circuit breaker | ✅ | `governor` token-bucket limiter guards GraphQL mutations; on-chain **timelock + threshold** act as a governance rate limit; `CircuitBreaker` guards downstream I/O. |
| 6 | Robust error handling & recovery | ✅ | Program: 15 `SecureError` codes. Service: `thiserror` `SecureError` / `EngineError`; every fallible boundary returns `Result`; no `unwrap` on runtime paths. |
| 7 | GraphQL if client-server >5 endpoints | ✅ | `securedeploy-api`: `async-graphql` schema — 7 queries, 6 mutations, 1 subscription; axum router with playground + websocket. |
| 8 | Unit + integration coverage | ✅ | Program: 12 tests. Service: **44 tests** (unit + property + engine flow + end-to-end GraphQL). **56 total.** |
| 9 | Modular reusable components | ✅ | `securedeploy-types` is a pure, I/O-free crate reused by every layer and mirroring the on-chain governance + build-hash logic. |
| 10 | 3rd-party crates | ✅ | Canonical stack: `tokio`, `async-graphql`, `axum`, `sqlx`, `governor`, `dashmap`, `tracing`, `metrics`, `criterion`, `sha2`. |
| 11 | Generative / Agentic AI | ⬜ | Not applicable to a security/governance core. |
| 12 | Idiomatic patterns & best practices | ✅ | Newtypes (`ProgramId`, `ProposalId`, `BuildHash`), `#[must_use]`, `#![forbid(unsafe_code)]` on every service crate, exhaustive matches, derived `Default`. |
| 13 | Generics | ✅ | `AuditEngine<P, F, E, C>` is generic over three ports + a clock; `validate_guardians<T>` is generic over any `PartialEq`; `retry` over any `Future`. |
| 14 | Anchor framework | ✅ | On-chain program is Anchor 0.30. |
| 15 | README (TOC, diagrams, flows, tests, badges) | ✅ | TOC, badges, mermaid architecture + sequence diagrams, component tables, complexity + benchmark tables, real test output; plus [AUDIT.md](./AUDIT.md). |
| 16 | Performance, reliability, maintainability | ✅ | LTO release profiles; `criterion` benchmark (sha256 4 KiB ≈ 3.46 µs); `O(1)` engine ops; bounded accounts. |
| 17 | Tokio async runtime | ✅ | Service runs on Tokio; async ports throughout; broadcast channel for events; graceful shutdown on `ctrl_c`. |
| 18 | Parallelism / concurrency / batch | ✅ | `DashMap`-backed lock-striped stores; PDA-per-object on-chain; broadcast fan-out to many subscribers. |
| 19 | Logging & observability | ✅ | `tracing` JSON logs; Prometheus recorder exposed at `/metrics`; `TraceLayer` on HTTP; Anchor events on-chain. |
| 20 | Happy path + edge cases | ✅ | Double-vote, non-guardian, below-threshold, active timelock, pause, cancel, reinit, overflow, oversized/duplicate guardian sets. |
| 21 | Composable, extensible architecture | ✅ | Swap any adapter (in-memory ↔ Postgres) without touching the engine; new threat classes and event variants slot in cleanly. |
| 22 | Interfaces, config, structure | ✅ | `clap`-based config with env fallbacks (`SD_*`); clean crate boundaries; on-chain governance PDA tunables. |
| 23 | Compile-time constraint enforcement | ✅ | Fixed-size byte arrays, typed newtypes, typed Anchor accounts, port traits, a `const _` assert on `MAX_GUARDIANS`. |
| 24 | Benchmarks & complexity | ✅ | `criterion` bench (`crates/securedeploy-types/benches/build_hash.rs`) + complexity/benchmark tables in README. |
| 25 | CI/CD | ✅ | `ci.yml`: separate program & service jobs (fmt + clippy `-D warnings` + test) + `cargo audit`. |
| 26 | Dockerfile | ✅ | `Dockerfile` (multi-stage, non-root service image) + `Dockerfile.anchor` (verifiable BPF build) + `docker-compose.yml`. |
| 27 | Postman collection | ✅ | [`postman/SecureDeploySol.postman_collection.json`](./postman/SecureDeploySol.postman_collection.json) — GraphQL queries/mutations + metrics. |
| 28 | Self-evaluation | ✅ | This document + the [AUDIT.md](./AUDIT.md) threat model. |

## Honest gaps

- The `execute_upgrade` handler **records and emits** the execution rather than
  performing the live `bpf_loader_upgradeable` CPI; the audited surface is the
  governance gate (threshold + timelock + pause + reinit). Wiring the loader CPI
  is the documented production step.
- A **TypeScript `anchor test`** exercising the full BPF transaction path is on
  the roadmap; current on-chain coverage is host-side logic tests.
- The Postgres proposal store is feature-gated and covered by schema; the running
  node defaults to the in-memory store for a zero-dependency demo.
