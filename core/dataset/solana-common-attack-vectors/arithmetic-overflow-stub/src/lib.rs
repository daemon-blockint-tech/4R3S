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
    instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let vault = next_account_info(accounts_iter)?;

    // VULNERABILITY: arithmetic-overflow — unchecked arithmetic on user-controlled values
    let amount = u64::from_le_bytes(instruction_data[0..8].try_into().unwrap_or([0; 8]));

    // This can overflow/underflow in release mode
    let new_balance = vault.lamports() + amount;
    **vault.try_borrow_mut_lamports()? = new_balance;

    msg!("Added {} lamports", amount);
    Ok(())
}
