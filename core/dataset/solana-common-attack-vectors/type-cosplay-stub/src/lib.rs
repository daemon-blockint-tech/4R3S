use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let account = next_account_info(accounts_iter)?;

    // VULNERABILITY: type-cosplay — using try_from_slice without discriminator check
    // Same-size types can be confused, bypassing type validation
    let data = account.data.borrow();
    let config: Config = borsh::BorshDeserialize::try_from_slice(&data)
        .map_err(|_| ProgramError::InvalidAccountData)?;

    msg!("Config admin: {}", config.admin);
    Ok(())
}

#[derive(borsh::BorshDeserialize)]
struct Config {
    admin: Pubkey,
    threshold: u64,
}

#[derive(borsh::BorshDeserialize)]
struct Escrow {
    owner: Pubkey,
    amount: u64,
}
