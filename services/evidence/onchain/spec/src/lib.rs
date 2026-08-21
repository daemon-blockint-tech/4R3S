//! Byte-level specification for the `evidence_registry` Solana program.
//!
//! One definition of every constant, offset and preimage that the program, the
//! Python bundler and the TypeScript oracle all have to agree on. Zero
//! dependencies, so the whole thing compiles and tests on the host target with
//! no Solana toolchain present.
//!
//! # What the program does, and does not do
//!
//! It stores a 32-byte root. It does **not** verify Merkle proofs. Proof
//! verification is a client operation: the program cannot see the leaves, and
//! there is no on-chain party who benefits from re-deriving a root it has no
//! inputs for. An anchor's job is to timestamp 32 bytes against a clock the
//! submitter does not control, and that is all.
//!
//! A consequence worth stating, because it removes an objection rather than
//! answering it: on-chain hashing cost is a non-issue. One `sol_sha256` syscall
//! over a 132-byte preimage, roughly 100 compute units. The tree shape is chosen
//! on correctness grounds alone.
//!
//! # The version gate is the domain tag
//!
//! There is no `schema_version` field on chain, and that is deliberate. The
//! root is useless without the leaves -- an anchored root with no retrievable
//! bundle is 32 bytes of noise -- so any reader who can check an anchor is
//! already holding the bundle, which states its own `schema` and
//! `leaf_encoding`. Duplicating that on chain would cost rent forever to record
//! something the reader necessarily already has. A change to the leaf encoding
//! bumps [`merkle::DOMAIN`], which changes every hash in the scheme.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod commitment;
pub mod discriminator;
pub mod layout;
pub mod merkle;
pub mod seeds;
