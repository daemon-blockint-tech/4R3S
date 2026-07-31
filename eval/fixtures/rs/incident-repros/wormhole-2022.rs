// Stylized, didactic reproduction inspired by the publicly documented root cause
// of the Wormhole bridge exploit (Feb 2022, ~$326M). NOT a working program, NOT a
// replay of the real bridge -- see eval/mappings/incident-repros.json for the
// full disclaimer and the acknowledged-stretch category mapping.
//
// Real bug: a deprecated verify_signatures path never checked that the
// referenced "prior instruction" actually invoked the native secp256k1
// program, letting an attacker forge a "verified" guardian signature set.

pub fn verify_signatures(
    guardian_set: &GuardianSetAccount,
    // Raw, unchecked account -- NOT Anchor's typed Sysvar<Instructions> wrapper,
    // NOT loaded via a checked accessor like load_instruction_at_checked.
    instructions_sysvar: &AccountInfo,
    signature_set: &mut SignatureSetAccount,
) -> ProgramResult {
    // Reads whatever the caller claims is "the preceding secp256k1 instruction"
    // out of the raw sysvar bytes, with no check that:
    //   (1) instructions_sysvar.key == sysvar::instructions::ID
    //   (2) the referenced instruction's program_id == secp256k1_program::ID
    //   (3) the recovered pubkeys actually match guardian_set's guardian list
    let claimed_secp_ix = read_instruction_at(instructions_sysvar, guardian_set.index - 1);

    // Some instruction existed at that index -- that's the entire check.
    if claimed_secp_ix.is_some() {
        signature_set.verified = true; // forged "verified" state, no real signature checked
    }
    Ok(())
}
