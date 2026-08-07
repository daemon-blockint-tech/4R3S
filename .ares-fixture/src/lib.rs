pub fn spl_token_create_account<'a>(params: TokenCreateAccount<'_, '_>) -> ProgramResult {
    let TokenCreateAccount {
        payer,
        mint,
        account,
        authority,
        authority_seeds,
        token_program,
        system_program,
        rent,
    } = params;
    let acct = &account.key.clone();

    create_or_allocate_account_raw(
        *token_program.key,
        &account,
        &rent,
        &system_program,
        &payer,
        spl_token::state::Account::LEN,
        authority_seeds,
    )?;
    msg!("Created account {}", acct);
    invoke_signed(
        &spl_token::instruction::initialize_account(
            &spl_token::id(),
            acct,
            mint.key,
            authority.key,
        )?,
        &[
            account,
            authority,
            mint,
            token_program,
            system_program,
            rent,
        ],
        &[authority_seeds],
    )?;

    Ok(())
}