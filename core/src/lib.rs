//! ARES deterministic core — PLAT-1 scaffold.
//!
//! This crate is a placeholder so the Rust workspace builds. The real engine
//! (regex -> AST -> taint -> local judge) plus `poc` and `fork-validator` land
//! in ENG-1, split into workspace crates: mapper, cli, poc, fork-validator, trident.
//!
//! Invariant (CLAUDE.md golden rule #2): the detection path is DETERMINISTIC —
//! no LLM, no network, no randomness. Same input -> identical output.

/// Placeholder marker; replaced by the real engine in ENG-1.
pub const SCAFFOLD: &str = "ares-core: PLAT-1 scaffold";
