// Stylized, didactic reproduction inspired by the publicly documented root cause
// of the Cashio protocol exploit (Mar 2022, ~$52M). NOT a working program, NOT a
// replay of the real protocol -- see eval/mappings/incident-repros.json for the
// full disclaimer.
//
// Real bug: the mint instruction accepted fake/uninitialized "bank"/"crate"
// collateral-chain accounts without verifying they were the correct, linked,
// expected-type accounts, letting an attacker mint tokens against fabricated
// collateral.

pub fn mint_ecash(
    // Plain, untyped AccountInfo -- NOT Anchor's typed Account<'info, Bank>,
    // so no owner check and no discriminator/type-tag check happens implicitly.
    bank: &AccountInfo,
    crate_token: &AccountInfo,
    user_token_account: &AccountInfo,
    amount: u64,
) -> ProgramResult {
    // Manual deserialization of attacker-suppliable bytes -- no bank.owner ==
    // crate::ID check, no discriminator check.
    let bank_data = Bank::try_from_slice(&bank.data.borrow())?;

    // MISSING: no check that bank_data.crate_token_key == *crate_token.key,
    // i.e. no verification that `bank` and `crate_token` are actually the
    // linked, correct pair rather than two unrelated attacker-created accounts.

    // Trusts bank_data.collateral_value unconditionally to authorize minting.
    if amount <= bank_data.collateral_value {
        mint_tokens_to(user_token_account, amount)?;
    }
    Ok(())
}
