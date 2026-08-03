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
    let account = next_account_info(accounts_iter)?;
    let destination = next_account_info(accounts_iter)?;

    // VULNERABILITY: close-account — missing lamport reclaim validation
    // Attacker can revive the account if discriminator isn't zeroed
    let lamports = account.lamports();
    **destination.try_borrow_mut_lamports()? = destination.lamports().checked_add(lamports).unwrap_or(u64::MAX);
    **account.try_borrow_mut_lamports()? = 0;

    msg!("Account closed, {} lamports transferred", lamports);
    Ok(())
}
