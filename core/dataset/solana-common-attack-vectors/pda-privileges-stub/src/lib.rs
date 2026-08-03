use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program::invoke_signed,
    pubkey::Pubkey,
    system_instruction,
};

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let pda = next_account_info(accounts_iter)?;
    let authority = next_account_info(accounts_iter)?;

    // VULNERABILITY: pda-privileges — weak PDA seeds (just user pubkey)
    // Attacker can predict PDA and create it before legitimate owner
    let seeds = &[authority.key.as_ref()];
    let (expected_pda, bump) = Pubkey::find_program_address(seeds, program_id);

    if *pda.key != expected_pda {
        msg!("PDA mismatch");
        return Err(solana_program::program_error::ProgramError::InvalidArgument);
    }

    // Use PDA to sign
    invoke_signed(
        &system_instruction::transfer(pda.key, authority.key, 100),
        &[pda.clone(), authority.clone()],
        &[&[authority.key.as_ref(), &[bump]]],
    )?;

    msg!("PDA signed transfer");
    Ok(())
}
