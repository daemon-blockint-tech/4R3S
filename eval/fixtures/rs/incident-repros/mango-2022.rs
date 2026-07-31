// Stylized, didactic reproduction inspired by the publicly documented root cause
// of the Mango Markets exploit (Oct 2022, ~$116M). NOT a working program, NOT a
// replay of the real protocol -- see eval/mappings/incident-repros.json for the
// full disclaimer.
//
// Real bug: self-trading inflated the MNGO perp price on Mango's own internal
// oracle with no staleness/confidence/TWAP safeguard, then the inflated price
// was used directly to authorize borrowing against collateral.

pub fn record_trade_price(market: &mut PerpMarket, price: u64) -> ProgramResult {
    // Unconditionally overwrites the internal mark price with the caller-
    // supplied trade price -- no external oracle cross-check, no TWAP, no
    // max-deviation/circuit-breaker versus the previous price.
    market.mark_price = price;
    Ok(())
}

pub fn borrow_against_collateral(
    perp_market: &PerpMarket,
    position_size: u64,
    borrow_amount: u64,
) -> ProgramResult {
    // Values collateral using the self-reported mark_price directly, with no
    // staleness or confidence check -- an attacker who just inflated
    // mark_price via record_trade_price can borrow against phantom value.
    let collateral_value = position_size * perp_market.mark_price;

    if borrow_amount <= collateral_value {
        transfer_borrowed_funds(borrow_amount)?;
    }
    Ok(())
}
