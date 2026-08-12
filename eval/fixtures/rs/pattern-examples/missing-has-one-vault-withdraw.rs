// Realistic pattern example — NOT a specific named incident repro, unlike the
// fixtures in ../incident-repros/. A missing `has_one` check isn't usually
// tied to one dollar-amount hack; it's a common vulnerability class, the same
// one Trail of Bits' own Solana pitfalls post documents (the exact reference
// already cited in this repo's anchor-constraint-gap catalog entry:
// https://blog.trailofbits.com/2023/04/11/solana-common-pitfalls/) and
// Neodyme's workshop teaches directly (Level 1/2, "Personal Vault" /
// "Secure Personal Vault" — the fix from one level to the next is adding
// exactly this kind of ownership/authority constraint).
//
// Shaped like a real, complete instruction rather than a minimal synthetic
// snippet: a vault program's withdraw instruction, where `authority` must
// sign, but nothing ever checks that `authority` is *this specific vault's*
// authority — any valid signer can drain any vault.

use anchor_lang::prelude::*;

#[program]
pub mod vault_program {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        require!(vault.balance >= amount, VaultError::InsufficientFunds);

        vault.balance -= amount;
        // ... transfer `amount` lamports/tokens to ctx.accounts.authority ...

        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    // Must sign — but signing proves *a* valid keypair authorized this,
    // not that this keypair is *this vault's* authority. Without has_one
    // (or an equivalent constraint) tying `authority` to `vault.authority`,
    // any account holder can withdraw from any vault by simply naming their
    // own pubkey as `authority` and someone else's vault as `vault`.
    pub authority: Signer<'info>,

    #[account(mut)]
    pub vault: Account<'info, VaultAccount>,
}

#[account]
pub struct VaultAccount {
    pub authority: Pubkey,
    pub balance: u64,
}

#[error_code]
pub enum VaultError {
    #[msg("insufficient vault balance")]
    InsufficientFunds,
}
