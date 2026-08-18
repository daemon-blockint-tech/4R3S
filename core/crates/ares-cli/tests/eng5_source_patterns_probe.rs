//! ENG-5 Tier 2 probe, not a regression test.
//!
//! Before moving `benchmark/patterns.rs`'s richer 34-field `SourcePatterns`
//! into `ares-mapper` so `local_judge.rs` could read it, check cheaply
//! whether any of those 34 fields ever fire on the EVAL-3 corpus at all.
//! Those fields are written for whole-protocol-scale exploits (Axelar,
//! Dexalot, Pump Science, MetaDAO — see the doc comments in patterns.rs),
//! and the corpus staged by `eval/stage_ares_core_targets.py` is mostly
//! single-file snippets — the same shape of mismatch that made
//! `is_large_dex` (`instructions.len() > 100`) fire on nothing all night.
//! If these also fire on nothing, the move has no payoff to earn regardless
//! of how cleanly it's done. See docs/ENG-5-MEASUREMENT.md, "Tier 2 attempt".
//!
//! Needs a staged corpus that isn't committed (`eval/data/` is gitignored):
//!   python eval/fetch_datasets.py --out-dir eval/data
//!   python eval/fetch_sealevel_attacks.py --out-dir eval/data
//!   python eval/fetch_neodyme_workshop.py --out-dir eval/data
//!   python eval/build_incident_repros.py --out-dir eval/data
//!   python eval/stage_ares_core_targets.py --ground-truth eval/data/ground_truth.csv \
//!     --corpus-dir eval/data/corpus --staging-root eval/data/staging
//! Skips cleanly (prints why, does not fail) when that staging directory is
//! absent, so a clean checkout without the corpus staged still passes.
//!
//! Run with: cargo test -p ares-v3 --test eng5_source_patterns_probe -- --nocapture

use ares_v3::commands::benchmark::patterns::scan_source_patterns;
use ares_mapper::MapperAgent;
use std::path::Path;

/// Every field on the richer `SourcePatterns`, paired with its own value for
/// one target. No reflection in Rust, so this is written out by hand rather
/// than derived — verified against patterns.rs's own field list directly.
fn field_values(p: &ares_v3::commands::benchmark::patterns::SourcePatterns) -> [(&'static str, bool); 34] {
    [
        ("has_account_info_unchecked", p.has_account_info_unchecked),
        ("has_check_annotation", p.has_check_annotation),
        ("has_try_from_slice", p.has_try_from_slice),
        ("has_manual_lamport_drain", p.has_manual_lamport_drain),
        ("has_init_with_unchecked_admin", p.has_init_with_unchecked_admin),
        ("has_init_with_fixed_seeds", p.has_init_with_fixed_seeds),
        ("has_cpi_context_new_variable", p.has_cpi_context_new_variable),
        ("has_cpi_after_state_read", p.has_cpi_after_state_read),
        ("has_state_set_then_cpi_then_state_set", p.has_state_set_then_cpi_then_state_set),
        ("has_pda_without_constraint", p.has_pda_without_constraint),
        ("has_invoke_helper_call", p.has_invoke_helper_call),
        ("has_mutable_account_with_signer_no_link", p.has_mutable_account_with_signer_no_link),
        ("has_token_account_without_authority", p.has_token_account_without_authority),
        ("has_any_init_with_fixed_seeds", p.has_any_init_with_fixed_seeds),
        ("has_unchecked_numeric_cast", p.has_unchecked_numeric_cast),
        ("has_init_global_unconstrained", p.has_init_global_unconstrained),
        ("has_duplicate_mutable_pair", p.has_duplicate_mutable_pair),
        ("has_cpi_new_with_signer", p.has_cpi_new_with_signer),
        ("has_pda_as_cpi_signer_no_link", p.has_pda_as_cpi_signer_no_link),
        ("has_check_on_seeded_no_has_one", p.has_check_on_seeded_no_has_one),
        ("has_same_type_mutable_pair", p.has_same_type_mutable_pair),
        ("has_init_if_needed_no_guard", p.has_init_if_needed_no_guard),
        ("has_custom_math_macro_cast", p.has_custom_math_macro_cast),
        ("has_post_cpi_stale_field_read", p.has_post_cpi_stale_field_read),
        ("has_mutable_unchecked_account_pair", p.has_mutable_unchecked_account_pair),
        ("has_remaining_accounts_cpi", p.has_remaining_accounts_cpi),
        ("has_hardcoded_endpoint_id", p.has_hardcoded_endpoint_id),
        ("has_typed_program_field", p.has_typed_program_field),
        ("has_unchecked_escrow_invoke_signed", p.has_unchecked_escrow_invoke_signed),
        ("has_settings_field_write_gap", p.has_settings_field_write_gap),
        ("has_unchecked_token_manager_cpi", p.has_unchecked_token_manager_cpi),
        ("has_raw_rust_unchecked_calls", p.has_raw_rust_unchecked_calls),
        ("has_bytemuck_unsafe_cast", p.has_bytemuck_unsafe_cast),
        ("has_solitaire_raw_info", p.has_solitaire_raw_info),
    ]
}

#[tokio::test]
async fn eng5_probe_richer_source_patterns_on_eval_corpus() {
    let staging_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../eval/data/staging");
    let manifest_path = staging_root.join("staging_manifest.json");

    if !manifest_path.exists() {
        println!(
            "SKIP: no staged corpus at {manifest_path:?} -- see this file's module doc for setup"
        );
        return;
    }

    let manifest: std::collections::BTreeMap<String, String> =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap())
            .expect("staging_manifest.json should be valid JSON");

    let mut counts: std::collections::BTreeMap<&'static str, usize> =
        field_values(&Default::default())
            .iter()
            .map(|(name, _)| (*name, 0usize))
            .collect();
    let mut targets_processed = 0usize;
    let mut targets_failed = 0usize;

    for safe_name in manifest.keys() {
        let target_path = staging_root.join(safe_name);
        let mut mapper = MapperAgent::new(&target_path);
        let graph = match mapper.analyze().await {
            Ok(g) => g,
            Err(e) => {
                // Resilience over strictness: this is a diagnostic sweep, and
                // one unparseable target should not hide the signal from the
                // other 158 the way a hard failure here would.
                eprintln!("skip {safe_name}: mapper analysis failed: {e}");
                targets_failed += 1;
                continue;
            }
        };
        let patterns = scan_source_patterns(&graph);
        for (name, value) in field_values(&patterns) {
            if value {
                *counts.get_mut(name).unwrap() += 1;
            }
        }
        targets_processed += 1;
    }

    println!("\n=== ENG-5 Tier 2 probe: richer SourcePatterns on {targets_processed} staged target(s) ({targets_failed} failed) ===\n");
    let mut any_nonzero = false;
    for (name, count) in &counts {
        if *count > 0 {
            any_nonzero = true;
        }
        println!("  {name:44} {count}");
    }
    println!();
    if any_nonzero {
        println!(
            "RESULT: at least one field fired -- but a nonzero count alone does not mean it's \
            useful for SUPPRESSION. Check each nonzero field's own doc comment in patterns.rs: \
            most describe a vulnerable pattern (used elsewhere to ADD a category, e.g. in \
            benchmark/categories.rs) rather than a safe one (used to REMOVE a category, like \
            has_typed_program_field/has_hardcoded_endpoint_id). Suppressing on a \
            vulnerability-confirming signal is backwards -- see docs/ENG-5-MEASUREMENT.md, \
            \"Tier 2 attempt\", idea 4, for what this probe found on 2026-08-18."
        );
    } else {
        println!("RESULT: every field fired zero times -- same dead end as is_large_dex; moving the struct would have no payoff on this corpus.");
    }

    assert!(
        targets_processed > 0,
        "processed zero targets -- staging manifest exists but nothing in it resolved; check {staging_root:?}"
    );
}
