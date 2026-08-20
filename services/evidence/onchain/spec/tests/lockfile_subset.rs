//! Enforces that this crate's lockfile is a strict subset of `core/Cargo.lock`.
//!
//! # Why this test is the most important one in the crate
//!
//! `cargo-deny` runs in `.github/workflows/ci.yml` pinned to
//! `manifest-path: core/Cargo.toml`, and `cargo-audit` runs in `core-ci.yml` with
//! `working-directory: core`. Neither can see a crate outside that tree. So on
//! paper, everything under `services/evidence/onchain/` has **no** licence check,
//! no ban check, no source check and no vulnerability check.
//!
//! This test converts that hole into a checkable property. If every
//! `name` + `version` pair in this crate's lockfile already appears in core's,
//! then this crate cannot introduce a dependency that core's gates have not
//! already cleared -- without touching either gate, and without adding a second
//! cargo-deny invocation to the repo's hottest workflow file.
//!
//! It is a *necessary* condition, not a sufficient one: it says nothing about a
//! crate core itself should not have. It is however the whole of what can be
//! guaranteed from outside core's manifest.
//!
//! # Consequence: no dependabot entry for this manifest
//!
//! A bump here would break the invariant until core bumped the same crate,
//! producing permanently-red PRs. `.github/dependabot.yml` deliberately has no
//! entry for this path; that absence is the design, not an oversight.

use std::collections::BTreeSet;
use std::path::PathBuf;

/// One `[[package]]` entry: the pair that identifies a resolved dependency.
type Package = (String, String);

fn parse_lockfile(path: &PathBuf) -> BTreeSet<Package> {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read lockfile {}: {e}", path.display()));

    let mut packages = BTreeSet::new();
    // A hand-rolled scan rather than a TOML dependency: the file format is two
    // fixed keys inside a repeated table, and adding a `toml` crate here would
    // itself have to satisfy the invariant this test enforces.
    for block in text.split("[[package]]").skip(1) {
        let mut name = None;
        let mut version = None;
        for line in block.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("name = \"") {
                name = rest.strip_suffix('"').map(str::to_owned);
            } else if let Some(rest) = line.strip_prefix("version = \"") {
                version = rest.strip_suffix('"').map(str::to_owned);
            }
            // Stop at the end of the table so a later key cannot be misread.
            if line.starts_with('[') && !line.starts_with("[[") {
                break;
            }
        }
        match (name, version) {
            (Some(n), Some(v)) => {
                packages.insert((n, v));
            }
            // A [[package]] table without both keys means the format changed
            // under us. Fail rather than silently skipping entries -- a parser
            // that quietly reads nothing would make this test pass vacuously.
            other => panic!("lockfile entry missing name or version: {other:?}"),
        }
    }
    assert!(
        !packages.is_empty(),
        "parsed zero packages from {} -- the lockfile format changed and this \
         test would otherwise pass vacuously",
        path.display()
    );
    packages
}

fn repo_root() -> PathBuf {
    // services/evidence/onchain/spec -> repo root
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../..")
        .canonicalize()
        .expect("cannot resolve the repository root")
}

#[test]
fn this_lockfile_is_a_strict_subset_of_the_core_workspace_lockfile() {
    let root = repo_root();
    let core = parse_lockfile(&root.join("core/Cargo.lock"));
    let spec = parse_lockfile(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock"));

    // This crate itself is obviously not in core's lockfile.
    let this_crate = (
        env!("CARGO_PKG_NAME").to_owned(),
        env!("CARGO_PKG_VERSION").to_owned(),
    );

    let extra: Vec<_> = spec
        .iter()
        .filter(|p| **p != this_crate && !core.contains(*p))
        .collect();

    assert!(
        extra.is_empty(),
        "these dependencies are NOT already resolved in core/Cargo.lock:\n{extra:#?}\n\n\
         cargo-deny (ci.yml, pinned to core/Cargo.toml) and cargo-audit (core-ci.yml, \
         working-directory: core) cannot see this crate, so the only thing keeping its \
         dependencies gated is that core has already cleared every one of them. Pin the \
         version above to whatever core resolves, or add the dependency to core first."
    );
}

#[test]
fn the_core_lockfile_is_large_enough_to_be_the_real_one() {
    // Guards against the path resolution above silently finding a stub or an
    // empty file, which would make the subset check pass for the wrong reason.
    let core = parse_lockfile(&repo_root().join("core/Cargo.lock"));
    assert!(
        core.len() > 100,
        "core/Cargo.lock resolved to only {} packages -- that is not the engine \
         workspace lockfile, so the subset assertion above is not testing what it claims",
        core.len()
    );
}

#[test]
fn this_crate_declares_no_runtime_dependencies() {
    // The whole reason the crate is split out of the anchor workspace: with zero
    // [dependencies], `cargo test` here never has to resolve the
    // anchor-lang -> solana-program graph, so it is immune to Solana toolchain
    // drift by construction rather than by luck.
    let manifest =
        std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("cannot read own Cargo.toml");

    // Walk section headers rather than splitting on the substring: the manifest's
    // own comment explaining the absence contains the literal text
    // "[dependencies]", and an earlier version of this test counted that comment
    // as a section and failed for the wrong reason.
    let mut in_runtime_deps = false;
    let mut entries = 0usize;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_runtime_deps = trimmed == "[dependencies]";
            continue;
        }
        if in_runtime_deps && !trimmed.is_empty() && !trimmed.starts_with('#') {
            entries += 1;
        }
    }

    assert_eq!(
        entries, 0,
        "a [dependencies] section with {entries} entr(y/ies) appeared in this \
         crate's manifest. Runtime dependencies here would be compiled into the \
         on-chain program, and would leave this crate's tests exposed to the \
         dependency resolution the split exists to avoid."
    );
}
