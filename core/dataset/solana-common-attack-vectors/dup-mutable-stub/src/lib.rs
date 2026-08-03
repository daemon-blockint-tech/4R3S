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
    let account_a = next_account_info(accounts_iter)?;
    let account_b = next_account_info(accounts_iter)?;

    // VULNERABILITY: duplicate-mutable-accounts — no check that account_a.key != account_b.key
    // Attacker can pass same account twice, causing double-mutation
    **account_a.try_borrow_mut_lamports()? = account_a.lamports().checked_add(100).unwrap_or(u64::MAX);
    **account_b.try_borrow_mut_lamports()? = account_b.lamports().checked_add(100).unwrap_or(u64::MAX);

    msg!("Accounts mutated");
    Ok(())
}
