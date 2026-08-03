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
    let vault = next_account_info(accounts_iter)?;

    // VULNERABILITY: ownership-check — reading account data without verifying owner
    // An attacker can pass a fake account with forged data
    let lamports = vault.lamports();
    let data = vault.data.borrow();

    msg!("Vault lamports: {}", lamports);
    msg!("Vault data length: {}", data.len());
    Ok(())
}
