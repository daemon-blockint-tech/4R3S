use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    msg,
    program::invoke,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let state = next_account_info(accounts_iter)?;
    let external_program = next_account_info(accounts_iter)?;

    // Read state before CPI
    let initial_value = state.data.borrow()[0];

    // CPI that could modify state
    let ix = Instruction {
        program_id: *external_program.key,
        accounts: vec![AccountMeta::new(*state.key, true)],
        data: vec![],
    };
    invoke(&ix, &[state.clone()])?;

    // VULNERABILITY: account-reloading — state not re-validated after CPI
    // State could have changed during CPI
    let final_value = state.data.borrow()[0];

    msg!("State before: {}, after: {}", initial_value, final_value);
    Ok(())
}
