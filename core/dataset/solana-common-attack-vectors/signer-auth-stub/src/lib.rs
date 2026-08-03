use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let authority = next_account_info(accounts_iter)?;
    let vault = next_account_info(accounts_iter)?;

    // VULNERABILITY: signer-authorization — no check for authority.is_signer
    // An attacker can call this without signing
    **vault.try_borrow_mut_lamports()? = vault.lamports().checked_sub(1000).unwrap_or(0);

    msg!("Withdrawn 1000 lamports from vault by {}", authority.key);
    Ok(())
}
