//! # passkeyauth-core — hexagonal domain core for the identity service
//!
//! Pure Merkle-attestation logic and ports, independent of any web/DB
//! framework. Adapters live in `passkeyauth-infra`; the GraphQL surface lives in
//! `passkeyauth-api`.
#![forbid(unsafe_code)]

pub mod config;
pub mod engine;
pub mod events;
pub mod merkle;
pub mod ports;

pub use config::EngineConfig;
pub use engine::{EngineError, IdentityEngine};
pub use events::AttestationEvent;
pub use ports::{
    DataSource, EventSink, EventStream, IdentityStore, IssuerStore, PortError, TreeStore,
};
