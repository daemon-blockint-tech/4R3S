//! Deterministic IDL parsing for PoC instruction-data generation (POC-1).
//!
//! Turns an Anchor (or native IDL-equivalent) instruction into the real bytes a
//! generated `solana-program-test` harness needs: the 8-byte Anchor discriminator
//! followed by Borsh-encoded, safe (zero/empty) default arguments. Pure and
//! deterministic — no LLM, no network, no randomness (core crate rule). This is
//! the "wiring" half of POC-1: `poc.rs` renders these bytes into the harness in
//! place of the previous placeholder `&[]`.

use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::Path;

/// A parsed IDL — only the fields POC-1 consumes.
#[derive(Debug, Clone, Deserialize)]
pub struct Idl {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub instructions: Vec<IdlInstruction>,
}

/// One instruction from an IDL's `instructions[]` array.
#[derive(Debug, Clone, Deserialize)]
pub struct IdlInstruction {
    pub name: String,
    #[serde(default)]
    pub accounts: Vec<IdlAccount>,
    #[serde(default)]
    pub args: Vec<IdlArg>,
}

/// An account entry. `writable`/`signer` are accepted as aliases for the newer
/// Anchor IDL spelling of `isMut`/`isSigner`.
#[derive(Debug, Clone, Deserialize)]
pub struct IdlAccount {
    #[serde(default)]
    pub name: String,
    #[serde(default, rename = "isMut", alias = "writable")]
    pub is_mut: bool,
    #[serde(default, rename = "isSigner", alias = "signer")]
    pub is_signer: bool,
}

/// An argument. `ty` is kept as a raw JSON value because Anchor arg types can be
/// a plain string (`"u64"`) or a composite object (`{"vec": "u8"}`).
#[derive(Debug, Clone, Deserialize)]
pub struct IdlArg {
    #[serde(default)]
    pub name: String,
    #[serde(default, rename = "type")]
    pub ty: serde_json::Value,
}

/// Load and parse an IDL file. Returns `None` on a missing or unparseable file
/// (the caller then falls back to placeholder/unwired PoC data).
pub fn load_idl(path: &Path) -> Option<Idl> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

/// Select the IDL instruction a finding concerns.
///
/// Prefers an exact or snake-case-insensitive match on `function` (the
/// finding's `location.function`); falls back to the sole instruction when the
/// IDL defines exactly one; otherwise returns `None` (PoC stays unwired).
pub fn select_instruction<'a>(idl: &'a Idl, function: Option<&str>) -> Option<&'a IdlInstruction> {
    if let Some(f) = function {
        let target = to_snake_case(f);
        if let Some(ix) = idl
            .instructions
            .iter()
            .find(|i| i.name == f || to_snake_case(&i.name) == target)
        {
            return Some(ix);
        }
    }
    if idl.instructions.len() == 1 {
        return idl.instructions.first();
    }
    None
}

/// Anchor instruction discriminator: `sha256("global:" + snake_case(name))[..8]`.
///
/// The IDL instruction name is camelCase, but Anchor derives the discriminator
/// from the snake_case handler name, so the name is converted first.
pub fn anchor_discriminator(instruction_name: &str) -> [u8; 8] {
    let mut hasher = Sha256::new();
    hasher.update(b"global:");
    hasher.update(to_snake_case(instruction_name).as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

/// Build the instruction data: discriminator followed by zero/empty-default args.
///
/// Returns `(bytes, complete)`. `complete` is `false` when an argument type could
/// not be safely encoded (composite/unknown type); the discriminator and all
/// encodable args are still emitted, so the caller can mark the PoC "partial".
pub fn instruction_data(ix: &IdlInstruction) -> (Vec<u8>, bool) {
    let mut bytes = anchor_discriminator(&ix.name).to_vec();
    let mut complete = true;
    for arg in &ix.args {
        match zero_default_encoding(&arg.ty) {
            Some(mut encoded) => bytes.append(&mut encoded),
            None => complete = false,
        }
    }
    (bytes, complete)
}

/// Borsh encoding of a safe zero/empty default for a primitive type string.
/// Returns `None` for composite/unknown types (never bakes in a live value).
fn zero_default_encoding(ty: &serde_json::Value) -> Option<Vec<u8>> {
    let name = ty.as_str()?;
    let width = match name {
        "u8" | "i8" | "bool" => 1,
        "u16" | "i16" => 2,
        "u32" | "i32" | "f32" => 4,
        "u64" | "i64" | "f64" => 8,
        "u128" | "i128" => 16,
        "publicKey" | "pubkey" | "Pubkey" => 32,
        // Borsh length-prefixes strings and byte vectors with a u32; an empty
        // value is four zero bytes.
        "string" | "String" | "bytes" => 4,
        _ => return None,
    };
    Some(vec![0u8; width])
}

/// Render bytes as a Rust `&[u8]` slice literal, e.g. `&[0xaf, 0x6d]`.
pub fn byte_slice_literal(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "&[]".to_string();
    }
    let inner = bytes
        .iter()
        .map(|b| format!("0x{:02x}", b))
        .collect::<Vec<_>>()
        .join(", ");
    format!("&[{}]", inner)
}

/// Convert camelCase / PascalCase to snake_case to match Anchor's discriminator
/// preimage.
pub fn to_snake_case(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 4);
    for (i, ch) in name.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if i != 0 {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snake_case_converts_camel() {
        assert_eq!(to_snake_case("logMessage"), "log_message");
        assert_eq!(to_snake_case("cpi"), "cpi");
        assert_eq!(to_snake_case("Initialize"), "initialize");
        assert_eq!(to_snake_case("updateUserData"), "update_user_data");
    }

    #[test]
    fn discriminator_matches_anchor_initialize() {
        // Canonical Anchor discriminator for `initialize`. If this ever fails,
        // re-verify the preimage format against a real `anchor build` artifact.
        assert_eq!(
            anchor_discriminator("initialize"),
            [175, 175, 109, 31, 13, 152, 155, 237]
        );
    }

    #[test]
    fn discriminator_is_snake_insensitive_and_8_bytes() {
        let camel = anchor_discriminator("logMessage");
        let snake = anchor_discriminator("log_message");
        assert_eq!(camel, snake);
        assert_eq!(camel.len(), 8);
    }

    #[test]
    fn parses_fixture_shape_and_encodes_u64_arg() {
        let json = r#"{
            "version": "0.0.0",
            "name": "arbitrary_cpi_insecure",
            "instructions": [
                {
                    "name": "cpi",
                    "accounts": [{ "name": "source", "isMut": true, "isSigner": false }],
                    "args": [{ "name": "amount", "type": "u64" }]
                }
            ]
        }"#;
        let idl: Idl = serde_json::from_str(json).unwrap();
        let ix = select_instruction(&idl, Some("cpi")).unwrap();
        assert_eq!(ix.name, "cpi");
        assert_eq!(ix.accounts.len(), 1);
        assert!(ix.accounts[0].is_mut);
        assert!(!ix.accounts[0].is_signer);

        let (data, complete) = instruction_data(ix);
        assert!(complete);
        assert_eq!(data.len(), 8 + 8); // discriminator + u64
        assert!(data[8..].iter().all(|&b| b == 0)); // zero-default u64
    }

    #[test]
    fn selects_sole_instruction_without_function() {
        let json = r#"{ "name": "p", "instructions": [
            { "name": "only", "accounts": [], "args": [] } ] }"#;
        let idl: Idl = serde_json::from_str(json).unwrap();
        assert_eq!(select_instruction(&idl, None).unwrap().name, "only");
    }

    #[test]
    fn ambiguous_without_function_is_none_but_named_resolves() {
        let json = r#"{ "name": "p", "instructions": [
            { "name": "a", "accounts": [], "args": [] },
            { "name": "b", "accounts": [], "args": [] } ] }"#;
        let idl: Idl = serde_json::from_str(json).unwrap();
        assert!(select_instruction(&idl, None).is_none());
        assert_eq!(select_instruction(&idl, Some("b")).unwrap().name, "b");
    }

    #[test]
    fn byte_literal_formats() {
        assert_eq!(byte_slice_literal(&[0xaf, 0x01]), "&[0xaf, 0x01]");
        assert_eq!(byte_slice_literal(&[]), "&[]");
    }

    #[test]
    fn unknown_arg_type_marks_incomplete() {
        let json = r#"{ "name": "p", "instructions": [
            { "name": "x", "accounts": [], "args": [
                { "name": "cfg", "type": { "defined": "Config" } } ] } ] }"#;
        let idl: Idl = serde_json::from_str(json).unwrap();
        let ix = select_instruction(&idl, None).unwrap();
        let (data, complete) = instruction_data(ix);
        assert!(!complete);
        assert_eq!(data.len(), 8); // discriminator only
    }
}
