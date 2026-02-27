use anchor_lang::prelude::*;
use anchor_lang::solana_program::sysvar::slot_hashes;
use anchor_lang::solana_program::system_instruction;
use anchor_lang::solana_program::system_program;
use anchor_lang::solana_program::program::invoke;

declare_id!("9DK1L9UF4EmkrMPpv9FZs4B63RvVPwJR34NGWm9NEbVy");

#[cfg(not(feature = "no-entrypoint"))]
use solana_security_txt::security_txt;

#[cfg(not(feature = "no-entrypoint"))]
security_txt! {
    name: "Blitz99 Games",
    project_url: "https://www.blitz99.win",
    contacts: "email:contact@blitz99.win",
    policy: "https://www.blitz99.win/terms",
    preferred_languages: "en,es",
    source_code: "https://github.com/Blitz99Win/blitz-games",
    auditors: "Unaudited — provably fair via on-chain Commit-Reveal + SlotHashes"
}

// ── Constants ─────────────────────────────────────────────────────────────
pub const REVEAL_WINDOW:  u64 = 1000;       // ~7min to reveal (congestion margin)
pub const TIMELOCK_SECS:  i64 = 172_800;    // 48h anti-rug (withdrawals)
pub const AUTH_TIMELOCK:  i64 = 259_200;    // 72h anti-rug (authority transfer)
pub const MIN_POOL:       u64 = 100_000_000; // 0.1 SOL — circuit breaker

// ── Seed-Based Jackpot Constants ─────────────────────────────────────────
// Jackpot triggers when bytes 24..28 of the game seed fall below a threshold
// that scales linearly with bet size. Bigger bets = higher chance.
// Prize = 90% of jackpot pool; 10% seeds the next round.
pub const JACKPOT_MIN_BET:  u64 = 20_000_000;   // 0.02 SOL min to be eligible
pub const JACKPOT_MIN_POOL: u64 = 100_000_000;  // 0.1 SOL min jackpot to trigger
pub const JACKPOT_RATE:     u64 = 43;           // Scaling factor (see probability table)
pub const JACKPOT_BASE:     u64 = 10_000;       // Denominator
// Probability table (approximate):
//   0.02 SOL → 0.002%   |  0.05 SOL → 0.005%  |  0.1 SOL → 0.01%
//   0.5  SOL → 0.05%    |  1.0  SOL → 0.1%    |  5.0 SOL → 0.5% (cap)

// ── Revenue Split Constants (BPS = basis points, /10000) ──────────────────
//
// All games edge = 5.0%
//
// ON LOSS — fees taken from bet, remainder stays in pool:
//   2% house, 2% referrer, 1.0% jackpot  (95.0% stays in pool)
//   No referrer → referrer share absorbed into house
//   Referrer must have ≥0.05 SOL balance + commission ≥0.001 SOL to receive payout
//
// ON WIN — fees taken from bet amount (player receives full gross_payout):
//   Same BPS splits applied to the original bet, not the payout.
//   House fees claimed via claim_house_fees → 100% to authority.

#[program]
pub mod blitz_games {
    use super::*;

    // ── Initialize ────────────────────────────────────────────────
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        pool.authority         = ctx.accounts.authority.key();
        pool.total_balance     = 0;
        pool.jackpot_balance   = 0;
        pool.total_wagered     = 0;
        pool.house_fees_earned = 0;
        pool.paused            = false;
        pool.withdrawal_request = None;
        pool.bump              = ctx.bumps.pool;
        Ok(())
    }

    // ── Fund the pool (owner or anyone can add liquidity) ─────────
    pub fn fund_pool(ctx: Context<FundPool>, amount: u64) -> Result<()> {
        require!(amount > 0, BlitzError::BetTooSmall);
        let ix = system_instruction::transfer(
            &ctx.accounts.funder.key(),
            &ctx.accounts.pool.key(),
            amount,
        );
        invoke(&ix, &[
            ctx.accounts.funder.to_account_info(),
            ctx.accounts.pool.to_account_info(),
        ])?;
        let pool = &mut ctx.accounts.pool;
        let pool_ai = pool.to_account_info();
        sync_pool_balance(pool, &pool_ai)?;
        emit!(PoolFunded { amount, funder: ctx.accounts.funder.key() });
        Ok(())
    }

    // ── Place Bet (Sector99, Dice, Tower) ──────────────────────────────
    pub fn place_bet(
        ctx: Context<PlaceBet>,
        game_type:    u8,         // 0=Flip  1=Sector99  2=Dice  3=Tower
        commitment:   [u8; 32],   // hash(secret_nonce)
        bet_lamports: u64,
        game_config:  [u8; 3],    // [x, y, radius] (Sector99) | [target, is_over, 0] (Dice) | [floors, path_bits, 0] (Tower)
    ) -> Result<()> {
        let clock = Clock::get()?;

        // Cache keys before mutable borrow
        let player_key = ctx.accounts.player.key();
        let pool_key = ctx.accounts.pool.key();
        let referrer_key = ctx.accounts.referrer.key();
        let player_ai = ctx.accounts.player.to_account_info();
        let pool_ai = ctx.accounts.pool.to_account_info();

        let pool  = &mut ctx.accounts.pool;

        // ── Anti-bankruptcy validations ──────────────────────────
        require!(!pool.paused,                      BlitzError::ContractPaused);
        require!(pool.total_balance >= MIN_POOL,    BlitzError::PoolTooLow);
        require!(bet_lamports >= 10_000_000,        BlitzError::BetTooSmall); // 0.01 SOL Minimum to prevent forfeit griefing
        require!(game_type <= 3,                    BlitzError::InvalidGameType);

        if game_type == 0 {
            // Flip: no config needed — enforce clean data
            require!(game_config == [0, 0, 0], BlitzError::InvalidGameConfig);
        }
        if game_type == 1 {
            require!(game_config[0] < 16, BlitzError::InvalidCoordinate);
            require!(game_config[1] < 16, BlitzError::InvalidCoordinate);
            require!(game_config[2] <= 3, BlitzError::InvalidRadius);
        }
        if game_type == 2 {
            // game_config[0] = target (2-95 for Under, 4-97 for Over)
            // game_config[1] = is_over flag (0 = Under, 1 = Over)
            require!(game_config[1] <= 1, BlitzError::InvalidGameConfig);
            
            if game_config[1] == 0 {
                require!(game_config[0] >= 2 && game_config[0] <= 95, BlitzError::InvalidDiceTarget);
            } else {
                require!(game_config[0] >= 4 && game_config[0] <= 97, BlitzError::InvalidDiceTarget);
            }
        }
        if game_type == 3 {
            // Tower: game_config[0] = floors (1-6), game_config[1] = packed path (1 bit per floor)
            let floors = game_config[0];
            require!(floors >= 1 && floors <= 6, BlitzError::InvalidTowerFloors);
            // Ensure unused high bits of path are zero
            let mask = (1u8 << floors).wrapping_sub(1); // e.g., floors=3 → mask=0b111
            require!(game_config[1] & !mask == 0, BlitzError::InvalidGameConfig);
        }

        let max_bet = get_max_bet(pool.total_balance, game_type);
        require!(bet_lamports <= max_bet,           BlitzError::BetExceedsLimit);

        // Validate referrer is a real wallet (system-owned), not a PDA.
        // "No referrer" → pass player's own address (or SystemProgram::ID for legacy).
        let ref_key = ctx.accounts.referrer.key();
        if ref_key != system_program::ID && ref_key != player_key {
            require!(
                *ctx.accounts.referrer.owner == system_program::ID,
                BlitzError::InvalidReferrer
            );
        }

        // Verify pool can pay worst case
        let worst = get_worst_payout(bet_lamports, game_type, &game_config);
        require!(
            pool.total_balance.saturating_add(bet_lamports) >= worst,
            BlitzError::InsufficientLiquidity
        );

        // ── Max Payout Cap — prevents any single bet from draining the pool ──
        let max_payout = get_max_payout_cap(pool.total_balance);
        require!(worst <= max_payout, BlitzError::PayoutExceedsPoolCap);

        // ── Create session ───────────────────────────────────────
        let session              = &mut ctx.accounts.session;
        session.player           = player_key;
        session.referrer         = referrer_key; // SystemProgram::ID if no referrer
        session.bet_lamports     = bet_lamports;
        session.commitment       = commitment;
        session.commit_slot      = clock.slot;
        session.resolve_slot     = get_resolve_slot(clock.slot, bet_lamports);
        session.forfeit_slot     = clock.slot + REVEAL_WINDOW;
        session.game_type        = game_type;
        session.game_state       = 0; // pending
        session.target_x         = game_config[0];
        session.target_y         = game_config[1];
        session.target_radius    = game_config[2];
        session.bump             = ctx.bumps.session;

        // ── Transfer SOL player → pool ───────────────────────────
        let ix = system_instruction::transfer(
            &player_key,
            &pool_key,
            bet_lamports,
        );
        invoke(&ix, &[
            player_ai,
            pool_ai,
        ])?;

        let pool_ai = pool.to_account_info();
        sync_pool_balance(pool, &pool_ai)?;

        pool.total_wagered = pool.total_wagered.wrapping_add(bet_lamports);
        pool.total_bets = pool.total_bets.wrapping_add(1);

        emit!(BetPlaced {
            player: session.player, game_type,
            amount: bet_lamports, resolve_slot: session.resolve_slot,
        });
        Ok(())
    }

    // ── Sector 99: Reveal & Settle ───────────────────────────────────
    pub fn reveal_sector(ctx: Context<RevealGame>, nonce: [u8; 32]) -> Result<()> {
        let clock = Clock::get()?;
        let seed = validate_and_extract_seed(
            &ctx.accounts.session, &ctx.accounts.slot_hashes.to_account_info(), &clock, &nonce, 1
        )?;
        let (won, gross_payout, strike_x, strike_y) = resolve_sector(&seed, &ctx.accounts.session);

        settle_outcome(
            &mut ctx.accounts.pool, &ctx.accounts.player, &ctx.accounts.referrer,
            &ctx.accounts.session, won, gross_payout, &seed,
        )?;
        ctx.accounts.session.game_state = 2;
        emit!(SectorSettled { player: ctx.accounts.session.player, won, strike_x, strike_y, payout: gross_payout });
        Ok(())
    }

    // ── Sector 99: Reveal via delegate (Session Key — ZERO popup!) ──
    pub fn reveal_sector_delegated(ctx: Context<RevealDelegated>, nonce: [u8; 32]) -> Result<()> {
        let clock = Clock::get()?;
        require!(clock.unix_timestamp < ctx.accounts.session_token.expires_at, BlitzError::SessionExpired);
        let seed = validate_and_extract_seed(
            &ctx.accounts.session, &ctx.accounts.slot_hashes.to_account_info(), &clock, &nonce, 1
        )?;
        let (won, gross_payout, strike_x, strike_y) = resolve_sector(&seed, &ctx.accounts.session);

        settle_outcome(
            &mut ctx.accounts.pool, &ctx.accounts.player, &ctx.accounts.referrer,
            &ctx.accounts.session, won, gross_payout, &seed,
        )?;
        ctx.accounts.session.game_state = 2;
        emit!(SectorSettled { player: ctx.accounts.session.player, won, strike_x, strike_y, payout: gross_payout });
        Ok(())
    }

    // ── Forfeit (permissionless cleanup with grace period) ─────────
    // Grace period: player has ~80 extra seconds after forfeit_slot to
    // call emergency_refund before anyone can claim the forfeited bet.
    // No bounty reward — eliminates bot griefing incentive entirely.
    // Forfeited bet goes 100% to pool liquidity (grows the pool).
    pub fn claim_forfeit(ctx: Context<ClaimForfeit>) -> Result<()> {
        let session = &mut ctx.accounts.session;
        let pool    = &mut ctx.accounts.pool;
        let clock   = Clock::get()?;

        let grace_slots: u64 = 200; // ~80 seconds grace period for player
        require!(
            session.game_state < 2 && clock.slot > session.forfeit_slot.saturating_add(grace_slots),
            BlitzError::ForfeitNotAvailable
        );

        // Entire forfeited bet stays in pool — no bounty, no extraction
        // sync_pool_balance will absorb it into total_balance automatically
        let pool_ai = pool.to_account_info();
        sync_pool_balance(pool, &pool_ai)?;

        session.game_state = 2;
        emit!(BetForfeited { player: session.player, amount: session.bet_lamports });
        Ok(())
    }

    // ── Emergency Refund (player gets 90% if slot hash expired) ───
    pub fn emergency_refund(ctx: Context<EmergencyRefund>) -> Result<()> {
        let session = &mut ctx.accounts.session;
        let pool    = &mut ctx.accounts.pool;
        let clock   = Clock::get()?;

        require!(session.game_state == 0,            BlitzError::SessionNotPending);
        require!(clock.slot > session.forfeit_slot,  BlitzError::ForfeitNotAvailable);
        require!(session.player == ctx.accounts.player.key(), BlitzError::NotSessionPlayer);

        let refund  = session.bet_lamports.saturating_mul(90) / 100;
        let penalty = session.bet_lamports.saturating_sub(refund);

        require!(pool.total_balance >= refund, BlitzError::InsufficientLiquidity);

        **pool.to_account_info().try_borrow_mut_lamports()?    -= refund;
        **ctx.accounts.player.try_borrow_mut_lamports()?        += refund;
        
        pool.house_fees_earned = pool.house_fees_earned.saturating_add(penalty);
        
        let pool_ai = pool.to_account_info();
        sync_pool_balance(pool, &pool_ai)?;
        
        session.game_state = 2;

        emit!(BetForfeited { player: session.player, amount: penalty });
        Ok(())
    }

    // ── Emergency Player Refund (anyone can call if pool goes insolvent) ──
    pub fn emergency_player_refund(ctx: Context<BotRefund>) -> Result<()> {
        let session = &mut ctx.accounts.session;
        let pool    = &mut ctx.accounts.pool;

        require!(session.game_state == 0,            BlitzError::SessionNotPending);
        require!(session.player == ctx.accounts.player.key(), BlitzError::NotSessionPlayer);

        // Allow ONLY if pool physically cannot pay worst case win anymore
        let config = [session.target_x, session.target_y, session.target_radius];
        let worst = get_worst_payout(session.bet_lamports, session.game_type, &config);
        require!(pool.total_balance < worst,         BlitzError::InsufficientLiquidity);

        let refund  = session.bet_lamports.saturating_mul(96) / 100; // 96% return
        let penalty = session.bet_lamports.saturating_sub(refund);   // 4% anti-abuse penalty

        **pool.to_account_info().try_borrow_mut_lamports()?    -= refund;
        **ctx.accounts.player.try_borrow_mut_lamports()?        += refund;
        
        pool.house_fees_earned = pool.house_fees_earned.saturating_add(penalty);
        
        let pool_ai = pool.to_account_info();
        sync_pool_balance(pool, &pool_ai)?;
        
        session.game_state = 2;

        emit!(BetForfeited { player: session.player, amount: penalty });
        Ok(())
    }

    // ── Session Keys: Authorize ephemeral key for auto-reveals ────
    pub fn create_session(
        ctx: Context<CreateSession>,
        validity_secs: i64,
        gas_lamports:  u64,
    ) -> Result<()> {
        let clock = Clock::get()?;
        require!(validity_secs > 0 && validity_secs <= 86400, BlitzError::InvalidSessionDuration);
        require!(gas_lamports <= 10_000_000, BlitzError::GasTooHigh);

        let token = &mut ctx.accounts.session_token;
        token.player     = ctx.accounts.player.key();
        token.delegate   = ctx.accounts.delegate.key();
        token.expires_at = clock.unix_timestamp + validity_secs;
        token.bump       = ctx.bumps.session_token;

        if gas_lamports > 0 {
            let ix = system_instruction::transfer(
                &ctx.accounts.player.key(),
                &ctx.accounts.delegate.key(),
                gas_lamports,
            );
            invoke(&ix, &[
                ctx.accounts.player.to_account_info(),
                ctx.accounts.delegate.to_account_info(),
            ])?;
        }

        emit!(SessionCreated {
            player: token.player, delegate: token.delegate,
            expires_at: token.expires_at
        });
        Ok(())
    }

    pub fn close_session(_ctx: Context<CloseSession>) -> Result<()> {
        // The rent from session_token (0.0019 SOL) is automatically reclaimed by the `close = player` constraint.
        // We cannot reclaim gas from the `delegate` Keypair directly because it is owned by the System Program,
        // and its private key was lost by the user (hence it being stale). Any attempt to mutate its lamports
        // here would result in an ExternalAccountLamportSpend runtime error.
        Ok(())
    }

    // ── Dice: Reveal & Settle ─────────────────────────────────────
    pub fn reveal_dice(ctx: Context<RevealGame>, nonce: [u8; 32]) -> Result<()> {
        let clock = Clock::get()?;
        let seed = validate_and_extract_seed(
            &ctx.accounts.session, &ctx.accounts.slot_hashes.to_account_info(), &clock, &nonce, 2
        )?;
        let (won, gross_payout, roll, target, is_over) = resolve_dice(&seed, &ctx.accounts.session);

        settle_outcome(
            &mut ctx.accounts.pool, &ctx.accounts.player, &ctx.accounts.referrer,
            &ctx.accounts.session, won, gross_payout, &seed,
        )?;
        ctx.accounts.session.game_state = 2;
        emit!(DiceSettled { player: ctx.accounts.session.player, won, roll, target, payout: gross_payout, is_over });
        Ok(())
    }

    // ── Dice: Reveal via delegate (Session Key — ZERO popup!) ─────
    pub fn reveal_dice_delegated(ctx: Context<RevealDelegated>, nonce: [u8; 32]) -> Result<()> {
        let clock = Clock::get()?;
        require!(clock.unix_timestamp < ctx.accounts.session_token.expires_at, BlitzError::SessionExpired);
        let seed = validate_and_extract_seed(
            &ctx.accounts.session, &ctx.accounts.slot_hashes.to_account_info(), &clock, &nonce, 2
        )?;
        let (won, gross_payout, roll, target, is_over) = resolve_dice(&seed, &ctx.accounts.session);

        settle_outcome(
            &mut ctx.accounts.pool, &ctx.accounts.player, &ctx.accounts.referrer,
            &ctx.accounts.session, won, gross_payout, &seed,
        )?;
        ctx.accounts.session.game_state = 2;
        emit!(DiceSettled { player: ctx.accounts.session.player, won, roll, target, payout: gross_payout, is_over });
        Ok(())
    }

    // ── Tower: Reveal & Settle ────────────────────────────────────
    pub fn reveal_tower(ctx: Context<RevealGame>, nonce: [u8; 32]) -> Result<()> {
        let clock = Clock::get()?;
        let seed = validate_and_extract_seed(
            &ctx.accounts.session, &ctx.accounts.slot_hashes.to_account_info(), &clock, &nonce, 3
        )?;
        let (won, gross_payout, death_floor, path, traps) = resolve_tower(&seed, &ctx.accounts.session);
        let floors = ctx.accounts.session.target_x;

        settle_outcome(
            &mut ctx.accounts.pool, &ctx.accounts.player, &ctx.accounts.referrer,
            &ctx.accounts.session, won, gross_payout, &seed,
        )?;
        ctx.accounts.session.game_state = 2;
        emit!(TowerSettled { player: ctx.accounts.session.player, won, floors, death_floor, payout: gross_payout, path, traps });
        Ok(())
    }

    // ── Tower: Reveal via delegate (Session Key — ZERO popup!) ────
    pub fn reveal_tower_delegated(ctx: Context<RevealDelegated>, nonce: [u8; 32]) -> Result<()> {
        let clock = Clock::get()?;
        require!(clock.unix_timestamp < ctx.accounts.session_token.expires_at, BlitzError::SessionExpired);
        let seed = validate_and_extract_seed(
            &ctx.accounts.session, &ctx.accounts.slot_hashes.to_account_info(), &clock, &nonce, 3
        )?;
        let (won, gross_payout, death_floor, path, traps) = resolve_tower(&seed, &ctx.accounts.session);
        let floors = ctx.accounts.session.target_x;

        settle_outcome(
            &mut ctx.accounts.pool, &ctx.accounts.player, &ctx.accounts.referrer,
            &ctx.accounts.session, won, gross_payout, &seed,
        )?;
        ctx.accounts.session.game_state = 2;
        emit!(TowerSettled { player: ctx.accounts.session.player, won, floors, death_floor, payout: gross_payout, path, traps });
        Ok(())
    }

    // ── Flip: Reveal & Settle (50/50 coin flip, 1.90x payout) ────
    pub fn reveal_flip(ctx: Context<RevealGame>, nonce: [u8; 32]) -> Result<()> {
        let clock = Clock::get()?;
        let seed = validate_and_extract_seed(
            &ctx.accounts.session, &ctx.accounts.slot_hashes.to_account_info(), &clock, &nonce, 0
        )?;
        let (won, gross_payout, roll) = resolve_flip(&seed, &ctx.accounts.session);

        settle_outcome(
            &mut ctx.accounts.pool, &ctx.accounts.player, &ctx.accounts.referrer,
            &ctx.accounts.session, won, gross_payout, &seed,
        )?;
        ctx.accounts.session.game_state = 2;
        emit!(FlipSettled { player: ctx.accounts.session.player, won, roll, payout: gross_payout });
        Ok(())
    }

    // ── Flip: Reveal via delegate (Session Key — ZERO popup!) ───
    pub fn reveal_flip_delegated(ctx: Context<RevealDelegated>, nonce: [u8; 32]) -> Result<()> {
        let clock = Clock::get()?;
        require!(clock.unix_timestamp < ctx.accounts.session_token.expires_at, BlitzError::SessionExpired);
        let seed = validate_and_extract_seed(
            &ctx.accounts.session, &ctx.accounts.slot_hashes.to_account_info(), &clock, &nonce, 0
        )?;
        let (won, gross_payout, roll) = resolve_flip(&seed, &ctx.accounts.session);

        settle_outcome(
            &mut ctx.accounts.pool, &ctx.accounts.player, &ctx.accounts.referrer,
            &ctx.accounts.session, won, gross_payout, &seed,
        )?;
        ctx.accounts.session.game_state = 2;
        emit!(FlipSettled { player: ctx.accounts.session.player, won, roll, payout: gross_payout });
        Ok(())
    }

    // ── Admin: Pause ──────────────────────────────────────────────
    pub fn set_paused(ctx: Context<AdminOnly>, paused: bool) -> Result<()> {
        ctx.accounts.pool.paused = paused;
        Ok(())
    }

    // ── Admin: Request withdrawal (48h timelock anti-rug) ─────────
    pub fn request_withdrawal(ctx: Context<AdminOnly>, amount: u64) -> Result<()> {
        let pool  = &mut ctx.accounts.pool;
        let clock = Clock::get()?;
        require!(pool.withdrawal_request.is_none(), BlitzError::PendingWithdrawal);
        let max = pool.total_balance / 5; // max 20% per withdrawal
        require!(amount <= max, BlitzError::WithdrawalTooLarge);

        pool.withdrawal_request = Some(WithdrawalRequest {
            amount,
            requested_at: clock.unix_timestamp,
            unlocks_at:   clock.unix_timestamp + TIMELOCK_SECS,
        });
        emit!(WithdrawalRequested { amount, unlocks_at: clock.unix_timestamp + TIMELOCK_SECS });
        Ok(())
    }

    pub fn execute_withdrawal(ctx: Context<AdminOnly>) -> Result<()> {
        let pool  = &mut ctx.accounts.pool;
        let clock = Clock::get()?;
        let req   = pool.withdrawal_request.clone().ok_or(BlitzError::NoWithdrawalRequest)?;

        require!(clock.unix_timestamp >= req.unlocks_at, BlitzError::TimelockActive);
        require!(pool.total_balance >= req.amount,        BlitzError::InsufficientLiquidity);

        **pool.to_account_info().try_borrow_mut_lamports()?    -= req.amount;
        **ctx.accounts.authority.try_borrow_mut_lamports()?     += req.amount;
        pool.withdrawal_request = None;
        let pool_ai = pool.to_account_info();
        sync_pool_balance(pool, &pool_ai)?;
        emit!(WithdrawalExecuted { amount: req.amount });
        Ok(())
    }

    pub fn cancel_withdrawal(ctx: Context<AdminOnly>) -> Result<()> {
        ctx.accounts.pool.withdrawal_request = None;
        Ok(())
    }

    // ── Admin: Claim House Fees ───────────────────────────────────
    pub fn claim_house_fees(ctx: Context<ClaimHouseFeesCtx>, amount: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        
        require!(amount > 0, BlitzError::BetTooSmall);
        require!(amount <= pool.house_fees_earned, BlitzError::InsufficientLiquidity);
        let rent = Rent::get()?.minimum_balance(pool.to_account_info().data_len());
        require!(
            pool.to_account_info().lamports().saturating_sub(rent) >= amount,
            BlitzError::InsufficientLiquidity
        );

        // 100% of house fees go to authority (single owner model)
        **pool.to_account_info().try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.authority.try_borrow_mut_lamports()? += amount;

        pool.house_fees_earned = pool.house_fees_earned.saturating_sub(amount);
        let pool_ai = pool.to_account_info();
        sync_pool_balance(pool, &pool_ai)?;

        emit!(HouseFeesClaimed { amount, authority: ctx.accounts.authority.key() });
        Ok(())
    }

    // ── Admin: Reinvest House Fees ────────────────────────────────
    pub fn reinvest_house_fees(ctx: Context<AdminOnly>, amount: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        
        require!(amount > 0, BlitzError::BetTooSmall);
        require!(amount <= pool.house_fees_earned, BlitzError::InsufficientLiquidity);

        // Move funds internally from reserved fees to liquid pool
        pool.house_fees_earned = pool.house_fees_earned.saturating_sub(amount);
        let pool_ai = pool.to_account_info();
        sync_pool_balance(pool, &pool_ai)?;

        emit!(HouseFeesReinvested { amount, authority: ctx.accounts.authority.key() });
        Ok(())
    }

    // ── Authority Transfer (with 72h timelock) ─────────────────

    pub fn propose_authority_transfer(ctx: Context<AdminOnly>, new_authority: Pubkey) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        require!(new_authority != pool.authority, BlitzError::InvalidReferrer);
        require!(new_authority != Pubkey::default(), BlitzError::InvalidReferrer);

        let now = Clock::get()?.unix_timestamp;
        pool.pending_authority = Some(new_authority);
        pool.authority_transfer_at = now + AUTH_TIMELOCK;

        emit!(AuthorityTransferProposed {
            current: pool.authority,
            proposed: new_authority,
            unlocks_at: pool.authority_transfer_at,
        });
        Ok(())
    }

    pub fn cancel_authority_transfer(ctx: Context<AdminOnly>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        require!(pool.pending_authority.is_some(), BlitzError::NoWithdrawalRequest);

        pool.pending_authority = None;
        pool.authority_transfer_at = 0;

        emit!(AuthorityTransferCancelled { authority: pool.authority });
        Ok(())
    }

    pub fn execute_authority_transfer(ctx: Context<ExecuteAuthorityTransfer>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        let new_auth = pool.pending_authority.ok_or(BlitzError::NoWithdrawalRequest)?;

        // Verify the new authority is the signer
        require!(ctx.accounts.new_authority.key() == new_auth, BlitzError::InvalidReferrer);

        // Verify timelock has passed
        let now = Clock::get()?.unix_timestamp;
        require!(now >= pool.authority_transfer_at, BlitzError::TimelockActive);

        let old = pool.authority;
        pool.authority = new_auth;
        pool.pending_authority = None;
        pool.authority_transfer_at = 0;

        emit!(AuthorityTransferred { old_authority: old, new_authority: new_auth });
        Ok(())
    }

    // ── Admin: Migrate pool account to new size (one-time) ─────
    pub fn migrate_pool(ctx: Context<MigratePool>) -> Result<()> {
        let pool_ai = &ctx.accounts.pool;
        let authority_key = ctx.accounts.authority.key();
        let new_size = 8 + GlobalPool::LEN;
        let old_size = pool_ai.data_len();

        // Verify PDA seeds
        let (expected_pda, _bump) = Pubkey::find_program_address(&[b"global_pool"], ctx.program_id);
        require!(pool_ai.key() == expected_pda, BlitzError::InvalidGameConfig);

        // Verify owner is this program
        require!(pool_ai.owner == ctx.program_id, BlitzError::InvalidGameConfig);

        // Verify authority matches (first 32 bytes after 8-byte discriminator)
        let data = pool_ai.try_borrow_data()?;
        let stored_authority = Pubkey::try_from(&data[8..40]).unwrap();
        require!(stored_authority == authority_key, BlitzError::ContractPaused);
        drop(data);

        if old_size < new_size {
            // Calculate additional rent needed
            let rent = Rent::get()?;
            let old_rent = rent.minimum_balance(old_size);
            let new_rent = rent.minimum_balance(new_size);
            let diff = new_rent.saturating_sub(old_rent);

            // Transfer extra rent from authority to pool
            if diff > 0 {
                let ix = system_instruction::transfer(&authority_key, pool_ai.key, diff);
                invoke(&ix, &[
                    ctx.accounts.authority.to_account_info(),
                    pool_ai.clone(),
                ])?;
            }

            // Realloc the account
            pool_ai.realloc(new_size, false)?;

            // Zero-fill ONLY the new bytes (preserve existing data)
            let mut data = pool_ai.try_borrow_mut_data()?;
            for byte in data[old_size..new_size].iter_mut() {
                *byte = 0;
            }
            drop(data);

            msg!("Pool migrated: {} → {} bytes", old_size, new_size);
        } else {
            msg!("Pool already correct size: {} bytes", old_size);
        }
        Ok(())
    }
}

// ══════════════════════════════════════════════════════════════════════════
//  HELPERS
// ══════════════════════════════════════════════════════════════════════════

/// Check if the referrer is a valid external wallet (not SystemProgram, not the player)
fn is_valid_referrer(referrer: Pubkey, player: Pubkey) -> bool {
    referrer != system_program::ID && referrer != player
}

/// Dynamically compute correct total_balance from physical lamports.
/// This is the SOLE source of truth — eliminates all accounting desync.
fn sync_pool_balance(pool: &mut Account<GlobalPool>, pool_ai: &AccountInfo) -> Result<()> {
    let rent = Rent::get()?.minimum_balance(pool_ai.data_len());
    let physical = pool_ai.lamports().saturating_sub(rent);
    let reserved = pool.house_fees_earned.saturating_add(pool.jackpot_balance);
    pool.total_balance = physical.saturating_sub(reserved);
    // Invariant: physical lamports must cover all reserved compartments
    require!(physical >= reserved, BlitzError::AccountingBroken);
    Ok(())
}

/// Get fee BPS for a game type. Returns (house_bps, ref_bps, jackpot_bps, treasury_bps).
/// All games: 5% total edge (2% house, 2% referrer, 1% jackpot)
/// "Viral Strategy" — 2% instant referral makes influencers fight to promote.
/// Without referrer: house absorbs the 2% → total house = 4%.
fn get_fee_bps(_game_type: u8) -> (u64, u64, u64, u64) {
    (200, 200, 100, 0)  // 5% total edge — no treasury split
}

/// SINGLE settlement function for ALL games. Handles win/loss splits,
/// physical lamport transfers, internal accounting, pool sync, AND
/// seed-based jackpot trigger check.
///
/// ATOMIC DESIGN:
///   1. Compute ALL values as pure math (no state mutation)
///   1.5. Check seed-based jackpot trigger
///   2. Validate solvency
///   3. Execute ALL physical lamport transfers
///   4. Update ALL internal compartments
///   5. Sync total_balance from physical reality (SOLE source of truth)
///
/// If ANY step fails, the entire Solana tx reverts — no partial state.
fn settle_outcome(
    pool: &mut Account<GlobalPool>,
    player_ai: &AccountInfo,
    referrer_ai: &AccountInfo,
    session: &Account<GameSession>,
    won: bool,
    gross_payout: u64,
    seed: &[u8; 32],
) -> Result<()> {
    let has_ref = is_valid_referrer(session.referrer, session.player);
    let (house_bps, ref_bps, jackpot_bps, treasury_bps) = get_fee_bps(session.game_type);
    let bet = session.bet_lamports;

    // ── STEP 1: Pure math — compute all splits ──────────────────
    let jackpot_cut = bet.saturating_mul(jackpot_bps) / 10_000;
    // house_cut accumulates house fees (100% to authority at claim time)
    let mut house_cut = bet.saturating_mul(house_bps + treasury_bps) / 10_000;
    let mut ref_cut = 0u64;

    if has_ref {
        let potential_ref = bet.saturating_mul(ref_bps) / 10_000;
        // Anti-abuse: referrer must have ≥0.05 SOL and commission must be ≥0.001 SOL
        let ref_balance = referrer_ai.lamports();
        if ref_balance >= 50_000_000 && potential_ref >= 1_000_000 {
            ref_cut = potential_ref;
        } else {
            // Ineligible referrer → commission goes to house
            house_cut = house_cut.saturating_add(potential_ref);
        }
    } else {
        // No referrer → absorb referrer share into house
        house_cut = house_cut.saturating_add(bet.saturating_mul(ref_bps) / 10_000);
    }

    // ── STEP 1.5: Seed-based jackpot check ──────────────────────
    // Uses bytes 24..28 of the game seed — independent of game outcome bytes (0..8).
    // Probability scales linearly with bet size; capped at ~0.5% per bet.
    // Prize = 90% of jackpot pool; 10% seeds the next jackpot round.
    let mut jackpot_prize = 0u64;
    if bet >= JACKPOT_MIN_BET && pool.jackpot_balance >= JACKPOT_MIN_POOL {
        let jackpot_roll = u32::from_le_bytes(seed[24..28].try_into().unwrap()) as u64;
        let mut threshold = bet.saturating_mul(JACKPOT_RATE) / JACKPOT_BASE;
        threshold = threshold.min((u32::MAX as u64) / 200); // cap ~0.5%
        if jackpot_roll < threshold {
            jackpot_prize = pool.jackpot_balance.saturating_mul(90) / 100;
        }
    }

    // Total lamports leaving the pool account
    let game_out = if won { gross_payout + ref_cut } else { ref_cut };
    let total_physical_out = game_out + jackpot_prize;

    // ── STEP 2: Solvency check ──────────────────────────────────
    let rent = Rent::get()?.minimum_balance(pool.to_account_info().data_len());
    let available = pool.to_account_info().lamports()
        .saturating_sub(rent)
        .saturating_sub(pool.house_fees_earned)
        .saturating_sub(pool.jackpot_balance);
    // Game pool must cover game transfers + fee increments
    require!(available >= game_out + jackpot_cut + house_cut, BlitzError::InsufficientLiquidity);

    // ── STEP 3: Physical lamport transfers ───────────────────────
    if total_physical_out > 0 {
        **pool.to_account_info().try_borrow_mut_lamports()? -= total_physical_out;
        let player_receives = if won { gross_payout } else { 0 } + jackpot_prize;
        if player_receives > 0 {
            **player_ai.try_borrow_mut_lamports()? += player_receives;
        }
        if ref_cut > 0 {
            // Fallback: if referrer account is closed/invalid, redirect to player
            match referrer_ai.try_borrow_mut_lamports() {
                Ok(mut ref_lam) => { **ref_lam += ref_cut; }
                Err(_) => { **player_ai.try_borrow_mut_lamports()? += ref_cut; }
            }
        }
    }

    // ── STEP 4: Internal compartment updates ─────────────────────
    pool.jackpot_balance = pool.jackpot_balance
        .saturating_sub(jackpot_prize)
        .saturating_add(jackpot_cut);
    pool.house_fees_earned = pool.house_fees_earned.saturating_add(house_cut);

    // ── STEP 4.5: Transparency counters ───────────────────────────
    if won {
        pool.total_wins = pool.total_wins.wrapping_add(1);
        if gross_payout > pool.biggest_win {
            pool.biggest_win = gross_payout;
        }
    }
    if jackpot_prize > 0 {
        pool.total_jackpot_won = pool.total_jackpot_won.wrapping_add(jackpot_prize);
    }

    // ── STEP 5: Sync total_balance from physical lamports ────────
    let pool_ai = pool.to_account_info();
    sync_pool_balance(pool, &pool_ai)?;

    // ── Emit jackpot event if triggered ──────────────────────────
    if jackpot_prize > 0 {
        emit!(JackpotWon { player: session.player, amount: jackpot_prize });
    }

    Ok(())
}

// ── Game-specific outcome resolvers ──────────────────────────────────────
// Each returns (won: bool, gross_payout: u64) from the seed + session data.

fn resolve_dice(seed: &[u8; 32], session: &Account<GameSession>) -> (bool, u64, u8, u8, bool) {
    let roll = u64::from_le_bytes(seed[0..8].try_into().unwrap()) % 100;
    let target = session.target_x as u64;
    let is_over = session.target_y == 1;
    let won = if is_over { roll > target } else { roll < target };
    let win_chance = if is_over { 99u64.saturating_sub(target) } else { target };
    let gross_payout = session.bet_lamports
        .saturating_mul(9_500)
        .saturating_div(win_chance.max(1))
        / 100;
    (won, if won { gross_payout } else { 0 }, roll as u8, target as u8, is_over)
}

fn resolve_sector(seed: &[u8; 32], session: &Account<GameSession>) -> (bool, u64, u8, u8) {
    let strike_x = seed[0] % 16;
    let strike_y = seed[1] % 16;
    let dist_x = session.target_x.abs_diff(strike_x);
    let dist_y = session.target_y.abs_diff(strike_y);
    let max_dist = dist_x.max(dist_y);
    let won = max_dist <= session.target_radius;
    let gross_payout = if won {
        let width = session.target_radius as u64 * 2 + 1;
        let area = width * width;
        let multiplier_bps = (256 * 10_000 / area) * 95 / 100;
        session.bet_lamports.saturating_mul(multiplier_bps) / 10_000
    } else { 0 };
    (won, gross_payout, strike_x, strike_y)
}

fn resolve_tower(seed: &[u8; 32], session: &Account<GameSession>) -> (bool, u64, u8, u8, u8) {
    let floors    = session.target_x as usize;
    let path_bits = session.target_y;
    let mut death_floor: u8 = 0;
    let mut trap_bits: u8 = 0;
    for i in 0..floors {
        let trap_lane = seed[i] % 2;
        trap_bits |= trap_lane << i;
        let player_choice = (path_bits >> i) & 1;
        if death_floor == 0 && player_choice == trap_lane {
            death_floor = (i + 1) as u8;
        }
    }
    let won = death_floor == 0;
    let gross_payout = if won {
        let power = 1u64 << (floors as u64);
        session.bet_lamports.saturating_mul(95).saturating_mul(power) / 100
    } else { 0 };
    (won, gross_payout, death_floor, path_bits, trap_bits)
}

/// Coin Flip: 50/50 chance, fixed 1.90x payout (5% house edge).
/// No game_config needed — probability and multiplier are hardcoded.
/// This eliminates any possibility of config manipulation.
fn resolve_flip(seed: &[u8; 32], session: &Account<GameSession>) -> (bool, u64, u8) {
    let roll = u64::from_le_bytes(seed[0..8].try_into().unwrap()) % 100;
    let won = roll < 50; // exact 50% probability
    let gross_payout = session.bet_lamports.saturating_mul(190) / 100; // 1.90x
    (won, if won { gross_payout } else { 0 }, roll as u8)
}

// ── Shared reveal validation ─────────────────────────────────────────────
// Common checks for all reveal endpoints. Returns the extracted seed.

fn validate_and_extract_seed<'info>(
    session: &Account<'info, GameSession>,
    slot_hashes_ai: &AccountInfo<'info>,
    clock: &Clock,
    nonce: &[u8; 32],
    expected_game_type: u8,
) -> Result<[u8; 32]> {
    require!(session.game_state == 0,                            BlitzError::SessionNotPending);
    require!(session.game_type  == expected_game_type,           BlitzError::WrongGameType);
    require!(clock.slot >= session.resolve_slot,                 BlitzError::TooEarlyToReveal);
    require!(clock.slot <= session.forfeit_slot,                 BlitzError::RevealWindowExpired);
    require!(clock.slot.saturating_sub(session.resolve_slot) < 512, BlitzError::SlotTooOld);

    let computed = anchor_lang::solana_program::hash::hash(nonce);
    require!(computed.to_bytes() == session.commitment,          BlitzError::InvalidNonce);

    extract_seed(slot_hashes_ai, session.resolve_slot, nonce, session.bet_lamports)
}

/// Protective max bet: scales down when pool is small to prevent bankruptcy.
/// Under 5 SOL: very conservative. Above 5 SOL: standard limits.
pub fn get_max_bet(pool: u64, game: u8) -> u64 {
    let five_sol = 5_000_000_000u64;

    if pool < five_sol {
        // Survival mode: 1% for all games when pool < 5 SOL
        match game {
            0 => pool.saturating_mul(1) / 100,  // Flip: 1%
            1 => pool.saturating_mul(1) / 100,  // Sector: 1%
            2 => pool.saturating_mul(1) / 100,  // Dice: 1%
            3 => pool.saturating_mul(1) / 100,  // Tower: 1%
            _ => 0,
        }
    } else {
        // Normal mode
        match game {
            0 => pool.saturating_mul(3)  / 100,  // Flip: 3% (1.90x — safe)
            1 => pool.saturating_mul(2)  / 100,  // Sector: 2%
            2 => pool.saturating_mul(3)  / 100,  // Dice: 3%
            3 => pool.saturating_mul(2)  / 100,  // Tower: 2% (high multipliers)
            _ => 0,
        }
    }
}

/// Max Payout Cap — tiered by pool health (TIGHTENED).
/// Limits the maximum possible payout to a percentage of pool.
/// This ensures no single bet can catastrophically drain the pool.
///
/// Pool < 5 SOL  (survival):  max payout = 3% of pool
/// Pool < 20 SOL (growing):   max payout = 5% of pool
/// Pool < 50 SOL (healthy):   max payout = 8% of pool
/// Pool ≥ 50 SOL (strong):    max payout = 10% of pool
///
/// + Hard absolute cap of 25 SOL — prevents whale extraction even on large pools.
///
/// Mathematical guarantee: even after worst-case Tower 6F (60.8x) win,
/// the pool drops by at most 10%. Recovery in days via normal bet flow.
pub fn get_max_payout_cap(pool: u64) -> u64 {
    let five_sol   =  5_000_000_000u64;
    let twenty_sol = 20_000_000_000u64;
    let fifty_sol  = 50_000_000_000u64;
    let hard_cap   = 25_000_000_000u64; // 25 SOL absolute maximum

    let cap = if pool < five_sol {
        pool.saturating_mul(3) / 100      // 3% — protect seed capital
    } else if pool < twenty_sol {
        pool.saturating_mul(5) / 100      // 5% — growing phase
    } else if pool < fifty_sol {
        pool.saturating_mul(8) / 100      // 8% — healthy
    } else {
        pool.saturating_mul(10) / 100     // 10% — strong pool
    };

    cap.min(hard_cap)
}

pub fn get_resolve_slot(slot: u64, bet: u64) -> u64 {
    let base_delay: u64 = 5; // min ~2s for basic fairness
    slot + base_delay + match bet {
        0..=50_000_000            => 5,                          // ~4s total (micro-bets)
        50_000_001..=500_000_000  => 15 + (bet / 50_000_000),    // ~8-18s (scales with bet)
        _                         => 50,                         // ~22s (whales, 12+ leaders)
    }
}

pub fn get_worst_payout(bet: u64, game: u8, config: &[u8; 3]) -> u64 {
    match game {
        0 => {
            // Flip: fixed 1.90x payout — no config dependency
            bet.saturating_mul(190) / 100
        },
        1 => {
            // Sector 99: Dynamic Multiplier per radius
            let radius = if config[2] <= 3 { config[2] as u64 } else { 0 };
            let width = radius * 2 + 1;
            let area = width * width;
            let multiplier_bps = (256 * 10_000 / area) * 95 / 100;
            bet.saturating_mul(multiplier_bps) / 10_000
        },
        2 => {
            // Dice: Dynamic Multiplier per target
            let target = if config[0] >= 2 && config[0] <= 97 { config[0] as u64 } else { 2 };
            let is_over = config[1] == 1;
            let win_chance = if is_over { 99u64.saturating_sub(target) } else { target };
            let chance = win_chance.max(1);
            bet.saturating_mul(9_500).saturating_div(chance) / 100
        },
        3 => {
            // Tower: Multiplier = 0.95 * 2^floors (max 6 floors = 60.8x)
            let floors = if config[0] >= 1 && config[0] <= 6 { config[0] as u64 } else { 1 };
            let power = 1u64 << floors; // 2^floors
            bet.saturating_mul(95).saturating_mul(power) / 100
        },
        _ => 0,
    }
}

/// Blake3 multi-slot seed extraction — fastest crypto hash available.
/// Concatenates nonce + 3 consecutive slot hashes + target_slot + bet_lamports,
/// then runs Blake3 — cryptographically irreversible, 2x faster than Keccak256.
/// Grinding 3 consecutive leaders through a one-way hash = not rentable.
fn extract_seed(
    slot_hashes_ai: &AccountInfo,
    target_slot: u64,
    nonce: &[u8; 32],
    bet_lamports: u64,
) -> Result<[u8; 32]> {
    let data = slot_hashes_ai.data.borrow();
    let n = u64::from_le_bytes(data[0..8].try_into().unwrap()) as usize;
    let mix_count: u64 = 3;

    // Collect 3 consecutive slot hashes
    let mut slot_hash_data = [[0u8; 32]; 3];
    for offset in 0..mix_count {
        let slot = target_slot + offset;
        let mut found = false;
        for i in 0..n.min(512) {
            let off = 8 + i * 40;
            let s = u64::from_le_bytes(data[off..off+8].try_into().unwrap());
            if s == slot {
                slot_hash_data[offset as usize] = data[off+8..off+40].try_into().unwrap();
                found = true;
                break;
            }
        }
        if !found { return Err(BlitzError::SlotHashNotFound.into()); }
    }

    // Blake3( nonce || hash0 || hash1 || hash2 || slot_bytes || bet_bytes )
    let mut hasher = blake3::Hasher::new();
    hasher.update(nonce);
    hasher.update(&slot_hash_data[0]);
    hasher.update(&slot_hash_data[1]);
    hasher.update(&slot_hash_data[2]);
    hasher.update(&target_slot.to_le_bytes());
    hasher.update(&bet_lamports.to_le_bytes());
    let digest = hasher.finalize();

    Ok(*digest.as_bytes())
}

// ══════════════════════════════════════════════════════════════════════════
//  ACCOUNTS
// ══════════════════════════════════════════════════════════════════════════

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = authority, space = 8 + GlobalPool::LEN,
              seeds = [b"global_pool"], bump)]
    pub pool: Account<'info, GlobalPool>,
    #[account(mut)] pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct FundPool<'info> {
    #[account(mut, seeds = [b"global_pool"], bump = pool.bump)]
    pub pool: Account<'info, GlobalPool>,
    #[account(mut)] pub funder: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(game_type: u8, commitment: [u8; 32], bet_lamports: u64)]
pub struct PlaceBet<'info> {
    #[account(mut)] pub player: Signer<'info>,
    /// CHECK: Optional referrer wallet. Pass player's own address if no referrer.
    pub referrer: AccountInfo<'info>,
    #[account(mut, seeds = [b"global_pool"], bump = pool.bump)]
    pub pool: Account<'info, GlobalPool>,
    #[account(init, payer = player, space = 8 + GameSession::LEN,
              seeds = [b"session", player.key().as_ref(), commitment.as_ref()], bump)]
    pub session: Account<'info, GameSession>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RevealGame<'info> {
    #[account(mut)] pub player: Signer<'info>,
    /// CHECK: Must match session.referrer. Writable so referrer can receive fee share.
    #[account(mut, address = session.referrer)]
    pub referrer: AccountInfo<'info>,
    #[account(mut, seeds = [b"global_pool"], bump = pool.bump)]
    pub pool: Account<'info, GlobalPool>,
    #[account(mut, has_one = player, close = player)]
    pub session: Account<'info, GameSession>,
    /// CHECK: address validated below — not injectable
    #[account(address = slot_hashes::ID)]
    pub slot_hashes: UncheckedAccount<'info>,
}

/// Session Key reveal: delegate signs, player receives payout
#[derive(Accounts)]
pub struct RevealDelegated<'info> {
    /// The ephemeral key that auto-signs (no Phantom popup)
    #[account(mut)] pub delegate: Signer<'info>,
    /// The original player — receives payout + session rent refund
    /// CHECK: validated via has_one on session + session_token
    #[account(mut)] pub player: AccountInfo<'info>,
    /// CHECK: Must match session.referrer. Writable so referrer can receive fee share.
    #[account(mut, address = session.referrer)]
    pub referrer: AccountInfo<'info>,
    #[account(mut, seeds = [b"global_pool"], bump = pool.bump)]
    pub pool: Account<'info, GlobalPool>,
    #[account(mut, has_one = player, close = player)]
    pub session: Account<'info, GameSession>,
    /// Session token proving delegate is authorized by player
    #[account(
        seeds = [b"session_key", player.key().as_ref()],
        bump = session_token.bump,
        has_one = delegate,
        has_one = player,
    )]
    pub session_token: Account<'info, SessionToken>,
    /// CHECK: address validated below — not injectable
    #[account(address = slot_hashes::ID)]
    pub slot_hashes: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct CreateSession<'info> {
    #[account(mut)] pub player: Signer<'info>,
    /// CHECK: the ephemeral key generated in the browser
    #[account(mut)] pub delegate: AccountInfo<'info>,
    #[account(
        init, payer = player,
        space = 8 + SessionToken::LEN,
        seeds = [b"session_key", player.key().as_ref()],
        bump
    )]
    pub session_token: Account<'info, SessionToken>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CloseSession<'info> {
    #[account(mut)] pub player: Signer<'info>,
    /// CHECK: delegate to reclaim gas from
    #[account(mut, address = session_token.delegate)]
    pub delegate: AccountInfo<'info>,
    #[account(
        mut, close = player,
        seeds = [b"session_key", player.key().as_ref()],
        bump = session_token.bump,
        has_one = player,
    )]
    pub session_token: Account<'info, SessionToken>,
}



#[derive(Accounts)]
pub struct ClaimForfeit<'info> {
    #[account(mut, seeds = [b"global_pool"], bump = pool.bump)]
    pub pool: Account<'info, GlobalPool>,
    #[account(mut, close = pool)] pub session: Account<'info, GameSession>,
    /// Permissionless: anyone can clean up forfeited sessions. Rent goes to pool.
    #[account(mut)] pub caller: Signer<'info>,
}

#[derive(Accounts)]
pub struct EmergencyRefund<'info> {
    #[account(mut, seeds = [b"global_pool"], bump = pool.bump)]
    pub pool: Account<'info, GlobalPool>,
    #[account(mut, close = player, has_one = player)] pub session: Account<'info, GameSession>,
    #[account(mut)] pub player: Signer<'info>,
}

#[derive(Accounts)]
pub struct BotRefund<'info> {
    #[account(mut, seeds = [b"global_pool"], bump = pool.bump)]
    pub pool: Account<'info, GlobalPool>,
    #[account(mut, close = player)] pub session: Account<'info, GameSession>,
    /// CHECK: We don't read data, just send lamports back to the original player.
    #[account(mut, address = session.player)] pub player: AccountInfo<'info>,
    #[account(mut)] pub caller: Signer<'info>,
}

#[derive(Accounts)]
pub struct AdminOnly<'info> {
    #[account(mut, seeds = [b"global_pool"], bump = pool.bump, has_one = authority)]
    pub pool: Account<'info, GlobalPool>,
    #[account(mut)] pub authority: Signer<'info>,
}

/// Migration context — uses UncheckedAccount because the old pool
/// may be smaller than the new GlobalPool struct (can't deserialize yet).
#[derive(Accounts)]
pub struct MigratePool<'info> {
    /// CHECK: Manually validated via PDA seeds + authority check in instruction.
    #[account(mut)]
    pub pool: AccountInfo<'info>,
    #[account(mut)] pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ClaimHouseFeesCtx<'info> {
    #[account(mut, seeds = [b"global_pool"], bump = pool.bump, has_one = authority)]
    pub pool: Account<'info, GlobalPool>,
    #[account(mut)] pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct ExecuteAuthorityTransfer<'info> {
    #[account(mut, seeds = [b"global_pool"], bump = pool.bump)]
    pub pool: Account<'info, GlobalPool>,
    /// The new authority must sign to accept the transfer
    #[account(mut)] pub new_authority: Signer<'info>,
}


// ══════════════════════════════════════════════════════════════════════════
//  STATE
// ══════════════════════════════════════════════════════════════════════════

#[account]
pub struct GlobalPool {
    pub authority:              Pubkey,                    // 32
    pub total_balance:          u64,                       // 8
    pub jackpot_balance:        u64,                       // 8
    pub total_wagered:          u64,                       // 8
    pub house_fees_earned:      u64,                       // 8
    pub paused:                 bool,                      // 1
    pub withdrawal_request:     Option<WithdrawalRequest>, // 1 + 24 = 25
    pub bump:                   u8,                        // 1
    // ── Transparency counters (anyone can verify on-chain) ──
    pub total_bets:             u64,                       // 8
    pub total_wins:             u64,                       // 8
    pub total_jackpot_won:      u64,                       // 8
    pub biggest_win:            u64,                       // 8
    // ── Authority transfer (72h timelock) ──
    pub pending_authority:      Option<Pubkey>,            // 1 + 32 = 33
    pub authority_transfer_at:  i64,                       // 8
}
impl GlobalPool { pub const LEN: usize = 32 + 8 + 8 + 8 + 8 + 1 + 25 + 1 + 8 + 8 + 8 + 8 + 33 + 8; }

#[account]
pub struct GameSession {
    pub player:        Pubkey,    // 32
    pub referrer:      Pubkey,    // 32 — NEW: who referred this player
    pub bet_lamports:  u64,       // 8
    pub commitment:    [u8; 32],  // 32
    pub commit_slot:   u64,       // 8
    pub resolve_slot:  u64,       // 8
    pub forfeit_slot:  u64,       // 8
    pub game_type:     u8,        // 1
    pub game_state:    u8,        // 1
    pub target_x:      u8,        // 1
    pub target_y:      u8,        // 1
    pub target_radius: u8,        // 1
    pub bump:          u8,        // 1
}
impl GameSession { pub const LEN: usize = 32 + 32 + 8 + 32 + 8 + 8 + 8 + 1 + 1 + 1 + 1 + 1 + 1; }

#[account]
pub struct SessionToken {
    pub player:     Pubkey,    // 32
    pub delegate:   Pubkey,    // 32
    pub expires_at: i64,       // 8
    pub bump:       u8,        // 1
}
impl SessionToken { pub const LEN: usize = 32 + 32 + 8 + 1; }

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct WithdrawalRequest {
    pub amount:       u64,  // 8
    pub requested_at: i64,  // 8
    pub unlocks_at:   i64,  // 8
}

// ══════════════════════════════════════════════════════════════════════════
//  ERRORS & EVENTS
// ══════════════════════════════════════════════════════════════════════════

#[error_code]
pub enum BlitzError {
    #[msg("Contract is paused")]
    ContractPaused,
    #[msg("Pool balance too low")]
    PoolTooLow,
    #[msg("Bet too small (min 0.01 SOL)")]
    BetTooSmall,
    #[msg("Bet exceeds limit")]
    BetExceedsLimit,
    #[msg("Invalid game type")]
    InvalidGameType,
    #[msg("Invalid game config array")]
    InvalidGameConfig,
    #[msg("Invalid coordinate (must be 0-15)")]
    InvalidCoordinate,
    #[msg("Invalid radius (must be 0-3)")]
    InvalidRadius,
    #[msg("Session not pending")]
    SessionNotPending,
    #[msg("Session not active")]
    SessionNotActive,
    #[msg("Reveal window expired")]
    RevealWindowExpired,
    #[msg("Too early to reveal")]
    TooEarlyToReveal,
    #[msg("Wrong game type")]
    WrongGameType,
    #[msg("Invalid nonce")]
    InvalidNonce,
    #[msg("Insufficient liquidity")]
    InsufficientLiquidity,
    #[msg("Slot hash not found")]
    SlotHashNotFound,
    #[msg("Forfeit not available")]
    ForfeitNotAvailable,
    #[msg("Withdrawal too large (max 20%)")]
    WithdrawalTooLarge,
    #[msg("Pending withdrawal exists")]
    PendingWithdrawal,
    #[msg("No withdrawal request")]
    NoWithdrawalRequest,
    #[msg("Timelock active")]
    TimelockActive,
    #[msg("Session key expired")]
    SessionExpired,
    #[msg("Invalid session duration (1s - 24h)")]
    InvalidSessionDuration,
    #[msg("Gas funding too high (max 0.01 SOL)")]
    GasTooHigh,
    #[msg("Invalid dice target (2-95)")]
    InvalidDiceTarget,
    #[msg("Invalid referrer: must be a regular wallet")]
    InvalidReferrer,
    #[msg("Slot hash too old (>512 slots), use emergency_refund")]
    SlotTooOld,
    #[msg("Caller is not the session player")]
    NotSessionPlayer,
    #[msg("Payout exceeds pool safety cap")]
    PayoutExceedsPoolCap,
    #[msg("Invalid tower floors (must be 1-6)")]
    InvalidTowerFloors,
    #[msg("Accounting invariant violated")]
    AccountingBroken,
}

#[event] pub struct PoolFunded          { pub amount: u64, pub funder: Pubkey }
#[event] pub struct BetPlaced           { pub player: Pubkey, pub game_type: u8, pub amount: u64, pub resolve_slot: u64 }
#[event] pub struct FlipSettled         { pub player: Pubkey, pub won: bool, pub roll: u8, pub payout: u64 }
#[event] pub struct DiceSettled         { pub player: Pubkey, pub won: bool, pub roll: u8, pub target: u8, pub payout: u64, pub is_over: bool }
#[event] pub struct SectorSettled       { pub player: Pubkey, pub won: bool, pub strike_x: u8, pub strike_y: u8, pub payout: u64 }
#[event] pub struct TowerSettled        { pub player: Pubkey, pub won: bool, pub floors: u8, pub death_floor: u8, pub payout: u64, pub path: u8, pub traps: u8 }
#[event] pub struct BetForfeited        { pub player: Pubkey, pub amount: u64 }
#[event] pub struct WithdrawalRequested { pub amount: u64, pub unlocks_at: i64 }
#[event] pub struct WithdrawalExecuted  { pub amount: u64 }
#[event] pub struct HouseFeesClaimed    { pub amount: u64, pub authority: Pubkey }
#[event] pub struct HouseFeesReinvested { pub amount: u64, pub authority: Pubkey }
#[event] pub struct SessionCreated      { pub player: Pubkey, pub delegate: Pubkey, pub expires_at: i64 }
#[event] pub struct JackpotWon          { pub player: Pubkey, pub amount: u64 }
#[event] pub struct AuthorityTransferProposed { pub current: Pubkey, pub proposed: Pubkey, pub unlocks_at: i64 }
#[event] pub struct AuthorityTransferCancelled { pub authority: Pubkey }
#[event] pub struct AuthorityTransferred { pub old_authority: Pubkey, pub new_authority: Pubkey }
