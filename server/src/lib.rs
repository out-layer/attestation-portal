//! Library surface of the `attestation-server` crate.
//!
//! The binary (`main.rs`) is the running portal; this lib re-exports the pieces that are useful to
//! call directly from examples / tests / future tooling. Right now that is the Phase 2 verify
//! pipeline (`verify`), so an ops tool (`examples/verify_one.rs`) can run `verify_cvm` against a real
//! CVM cert without spinning up the HTTP server. Keeping `verify` here (instead of inline in
//! `main.rs`) does not change the binary's behavior — `main.rs` consumes the exact same module.

pub mod page;
pub mod verify;
