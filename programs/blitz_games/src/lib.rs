//! # Blitz99 Games — On-Chain Casino Protocol
//!
//! Provably fair via Commit-Reveal + multi-slot BLAKE3 seed.
//! Four game types: Flip | Sector99 | Dice | Tower.
//! Phase-adaptive edge (2.5% → 2.0% → 1.5%) and auto-reinvest.
//!
//! Program ID: 9DK1L9UF4EmkrMPpv9FZs4B63RvVPwJR34NGWm9NEbVy

use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    hash,
    program::invoke,
    system_instruction,
    system_program,
    sysvar::slot_hashes,
};

declare_id!("9DK1L9UF4EmkrMPpv9FZs4B63RvVPwJR34NGWm9NEbVy");

#[cfg(not(feature = "no-entrypoint"))]
use solana_security_txt::security_txt;

#[cfg(not(feature = "no-entrypoint"))]
security_txt! {
    name:                "Blitz99 Games",
    project_url:         "https://www.blitz99.win",
    contacts:            "email:contact@blitz99.win",
    policy:              "https://www.blitz99.win/terms",
    preferred_languages: "en,es",
    auditors:            "Unaudited — provably fair via on-chain Commit-Reveal + SlotHashes"
}

// ══════════════════════════════════════════════════════════════════════════
//  CONSTANTS
// ══════════════════════════════════════════════════════════════════════════

// ── Core timing ───────────────────────────────────────────────────────────
/// Slots the player has to reveal before the bet is forfeit-eligible (~3.3 min).
/// Must stay below 512 (SlotHashes sysvar limit).
pub const REVEAL_WINDOW:      u64 = 500;
/// Slot spacing between the three seed hashes — guarantees different validator leaders.
pub const SLOT_SPREAD:        u64 = 10;

// ── Anti-rug timelocks ────────────────────────────────────────────────────
/// 48 h delay before a requested withdrawal can be executed.
pub const TIMELOCK_SECS:      i64 = 172_800;
/// 72 h delay before an authority transfer can be executed.
pub const AUTH_TIMELOCK:      i64 = 259_200;
/// Maximum continuous pause duration. Contract auto-unpauses on next bet attempt.
pub const MAX_PAUSE_DURATION: i64 = 86_400;

// ── Pool safety ───────────────────────────────────────────────────────────
/// Minimum pool balance for bets to be accepted (0.1 SOL).
pub const MIN_POOL: u64 = 100_000_000;

// ── Jackpot ───────────────────────────────────────────────────────────────
/// Minimum bet to be eligible for a jackpot trigger (0.02 SOL).
pub const JACKPOT_MIN_BET:  u64 = 20_000_000;
/// Minimum jackpot pool required to pay out (0.1 SOL).
pub const JACKPOT_MIN_POOL: u64 = 100_000_000;
/// Linear scaling factor: threshold = bet × JACKPOT_RATE / JACKPOT_BASE.
/// Probability table:
///   0.02 SOL → ~0.002% | 0.1 SOL → ~0.01% | 1.0 SOL → ~0.1% | 5.0 SOL → ~0.5% (cap)
pub const JACKPOT_RATE:     u64 = 43;
pub const JACKPOT_BASE:     u64 = 10_000;

// ── Phase thresholds ──────────────────────────────────────────────────────
/// Phase 0→1 transition: 50 SOL. Below = bootstrap mode (E=2.5%).
pub const PHASE1_THRESHOLD: u64 = 50_000_000_000;
/// Phase 1→2 transition: 500 SOL. Above = competitive mode (E=1.5%).
pub const PHASE2_THRESHOLD: u64 = 500_000_000_000;

// ── Fee schedule (basis points, denominator = 10_000) ────────────────────
//
//  Phase 0 (<50 SOL)   │ with ref: H=0.5% R=1.5% J=0.5% → E=2.5%
//                      │  no ref:  H=2.0% R=0%   J=0.5% → E=2.5%
//  Phase 1 (<500 SOL)  │ with ref: H=0.5% R=1.0% J=0.5% → E=2.0%
//                      │  no ref:  H=1.5% R=0%   J=0.5% → E=2.0%
//  Phase 2 (500+ SOL)  │ with ref: H=0.5% R=0.75% J=0.25% → E=1.5%
//                      │  no ref:  H=1.25% R=0%  J=0.25% → E=1.5%
//
//  Referrer eligibility: balance ≥ 0.05 SOL AND commission ≥ 0.001 SOL.
//  Ineligible referrer → their share absorbed by house.
//
//  Auto-reinvest split by phase:
//    Phase 0: 0.1% operational claimable; rest locked in pool.
//    Phase 1: 0.1% + 50% of remainder claimable; 50% reinvested.
//    Phase 2: 100% claimable — pool self-sustains by volume.

/// Always-claimable operational portion (0.1% of every bet).
pub const OPERATIONAL_BPS: u64 = 10;

// ══════════════════════════════════════════════════════════════════════════
//  UNIFIED PAYOUT FORMULA
// ══════════════════════════════════════════════════════════════════════════
//
//  All four games share one formula — payouts expressed as win-probability fractions:
//
//    gross = bet × num × win_chance_den
//            ───────────────────────────
//            win_chance_num × 10_000
//
//  Game mapping:
//    Flip    → (50, 100)          — exact 50% probability
//    Dice    → (win_range, 100)   — e.g. under-50 → (50, 100)
//    Sector  → (area, 256)        — area = (2r+1)²; r=0 → 256× max
//    Tower   → (1, 2^floors)      — e.g. 3 floors → (1, 8) = 8×
//
//  `num` = phase-adjusted retention numerator:
//    Phase 0 → 9_750 (E=2.5%) | Phase 1 → 9_800 (E=2.0%) | Phase 2 → 9_850 (E=1.5%)

// ══════════════════════════════════════════════════════════════════════════
//  GAME OUTCOME — internal enum for unified settlement dispatch
// ══════════════════════════════════════════════════════════════════════════

/// Carries game-specific resolution data from the resolver to the event emitter.
/// Keeps each of the 8 reveal instructions down to ~5 lines.
enum GameOutcome {
    Flip   { roll: u8 },
    Sector { strike_x: u8, strike_y: u8 },
    Dice   { roll: u8, target: u8, is_over: bool },
    Tower  { floors: u8, death_floor: u8, path: u8, traps: u8 },
}

// ══════════════════════════════════════════════════════════════════════════
//  PROGRAM
// ══════════════════════════════════════════════════════════════════════════

#[program]
pub mod blitz_games {
    use super::*;

    // ── Initialize ─────────────────────────────────────────────────────────

    /// @notice Bootstraps the global pool PDA. Called once at deploy.
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let p = &mut ctx.accounts.pool;
        p.authority              = ctx.accounts.authority.key();
        p.total_balance          = 0;
        p.jackpot_balance        = 0;
        p.total_wagered          = 0;
        p.house_fees_earned      = 0;
        p.paused                 = false;
        p.pause_expires_at       = 0;
        p.withdrawal_request     = None;
        p.bump                   = ctx.bumps.pool;
        p.total_bets             = 0;
        p.total_wins             = 0;
        p.total_jackpot_won      = 0;
        p.biggest_win            = 0;
        p.total_paid_out         = 0;
        p.pending_authority      = None;
        p.authority_transfer_at  = 0;
        p.total_reinvested       = 0;
        p.operational_extracted  = 0;
        p.reinvest_request       = None;
        Ok(())
    }

    // ── Fund Pool ──────────────────────────────────────────────────────────

    /// @notice Deposits SOL into the pool. Permissionless — anyone can add liquidity.
    pub fn fund_pool(ctx: Context<FundPool>, amount: u64) -> Result<()> {
        require!(amount > 0, BlitzError::BetTooSmall);
        invoke(
            &system_instruction::transfer(&ctx.accounts.funder.key(), &ctx.accounts.pool.key(), amount),
            &[ctx.accounts.funder.to_account_info(), ctx.accounts.pool.to_account_info()],
        )?;
        let pool_ai = ctx.accounts.pool.to_account_info();
        sync_balance(&mut ctx.accounts.pool, &pool_ai)?;
        emit!(PoolFunded { amount, funder: ctx.accounts.funder.key() });
        Ok(())
    }

    // ── Place Bet ──────────────────────────────────────────────────────────

    /// @notice Commits a bet via Commit-Reveal. Transfers `bet_lamports` into the pool.
    /// @dev    `commitment` = SHA-256(nonce); nonce supplied at reveal time.
    ///         Auto-expires a stale pause if MAX_PAUSE_DURATION has elapsed.
    /// @param game_type   0=Flip | 1=Sector99 | 2=Dice | 3=Tower
    /// @param commitment  SHA-256 of the player's secret nonce
    /// @param bet_lamports Wager in lamports (min 0.01 SOL)
    /// @param game_config  [x,y,r] for Sector | [target,is_over,0] for Dice | [floors,path,0] for Tower
    pub fn place_bet(
        ctx:          Context<PlaceBet>,
        game_type:    u8,
        commitment:   [u8; 32],
        bet_lamports: u64,
        game_config:  [u8; 3],
    ) -> Result<()> {
        let clock      = Clock::get()?;
        let pool       = &mut ctx.accounts.pool;
        let player_key = ctx.accounts.player.key();

        // Auto-expire a forgotten pause (player-protective, no owner action needed)
        if pool.paused && clock.unix_timestamp >= pool.pause_expires_at {
            pool.paused           = false;
            pool.pause_expires_at = 0;
        }

        require!(!pool.paused,                   BlitzError::ContractPaused);
        require!(pool.total_balance >= MIN_POOL, BlitzError::PoolTooLow);
        require!(bet_lamports >= 10_000_000,     BlitzError::BetTooSmall);
        require!(game_type <= 3,                 BlitzError::InvalidGameType);

        validate_game_config(game_type, &game_config)?;

        let max_bet = get_max_bet(pool.total_balance, game_type, &game_config);
        require!(bet_lamports <= max_bet, BlitzError::BetExceedsLimit);

        let worst = get_worst_payout(bet_lamports, game_type, &game_config);
        require!(worst <= get_max_payout_cap(pool.total_balance), BlitzError::PayoutExceedsPoolCap);
        require!(
            pool.total_balance.saturating_add(bet_lamports) >= worst,
            BlitzError::InsufficientLiquidity
        );

        let ref_key = ctx.accounts.referrer.key();
        if ref_key != system_program::ID && ref_key != player_key {
            require!(*ctx.accounts.referrer.owner == system_program::ID, BlitzError::InvalidReferrer);
        }

        let s           = &mut ctx.accounts.session;
        s.player        = player_key;
        s.referrer      = ref_key;
        s.bet_lamports  = bet_lamports;
        s.commitment    = commitment;
        s.commit_slot   = clock.slot;
        s.resolve_slot  = get_resolve_slot(clock.slot, bet_lamports);
        s.forfeit_slot  = clock.slot + REVEAL_WINDOW;
        s.game_type     = game_type;
        s.game_state    = 0;
        s.target_x      = game_config[0];
        s.target_y      = game_config[1];
        s.target_radius = game_config[2];
        s.bump          = ctx.bumps.session;

         let pool_ai = pool.to_account_info();
        invoke(
            &system_instruction::transfer(&player_key, pool_ai.key, bet_lamports),
            &[ctx.accounts.player.to_account_info(), pool_ai.clone()],
        )?;
        sync_balance(pool, &pool_ai)?;
        pool.total_wagered = pool.total_wagered.saturating_add(bet_lamports);
        pool.total_bets    = pool.total_bets.saturating_add(1);

        emit!(BetPlaced { player: s.player, game_type, amount: bet_lamports, resolve_slot: s.resolve_slot });
        Ok(())
    }

    // ── Reveal: direct (player signs) ─────────────────────────────────────

    /// @notice Reveals nonce and settles a Flip bet. Player must sign.
     pub fn reveal_flip(ctx: Context<RevealGame>, nonce: [u8; 32]) -> Result<()> {
        let (won, payout, outcome, seed) = resolve(0, &ctx.accounts.session, &ctx.accounts.slot_hashes.to_account_info(), &nonce, ctx.accounts.pool.total_balance)?;
        settle(&mut ctx.accounts.pool, &ctx.accounts.player, &ctx.accounts.referrer, &ctx.accounts.session, won, payout, seed)?;
        ctx.accounts.session.game_state = 2;
        emit_outcome(ctx.accounts.session.player, won, payout, &outcome);
        Ok(())
    }

    /// @notice Reveals nonce and settles a Sector99 bet. Player must sign.
     pub fn reveal_sector(ctx: Context<RevealGame>, nonce: [u8; 32]) -> Result<()> {
        let (won, payout, outcome, seed) = resolve(1, &ctx.accounts.session, &ctx.accounts.slot_hashes.to_account_info(), &nonce, ctx.accounts.pool.total_balance)?;
        settle(&mut ctx.accounts.pool, &ctx.accounts.player, &ctx.accounts.referrer, &ctx.accounts.session, won, payout, seed)?;
        ctx.accounts.session.game_state = 2;
        emit_outcome(ctx.accounts.session.player, won, payout, &outcome);
        Ok(())
    }

    /// @notice Reveals nonce and settles a Dice bet. Player must sign.
     pub fn reveal_dice(ctx: Context<RevealGame>, nonce: [u8; 32]) -> Result<()> {
        let (won, payout, outcome, seed) = resolve(2, &ctx.accounts.session, &ctx.accounts.slot_hashes.to_account_info(), &nonce, ctx.accounts.pool.total_balance)?;
        settle(&mut ctx.accounts.pool, &ctx.accounts.player, &ctx.accounts.referrer, &ctx.accounts.session, won, payout, seed)?;
        ctx.accounts.session.game_state = 2;
        emit_outcome(ctx.accounts.session.player, won, payout, &outcome);
        Ok(())
    }

    /// @notice Reveals nonce and settles a Tower bet. Player must sign.
     pub fn reveal_tower(ctx: Context<RevealGame>, nonce: [u8; 32]) -> Result<()> {
        let (won, payout, outcome, seed) = resolve(3, &ctx.accounts.session, &ctx.accounts.slot_hashes.to_account_info(), &nonce, ctx.accounts.pool.total_balance)?;
        settle(&mut ctx.accounts.pool, &ctx.accounts.player, &ctx.accounts.referrer, &ctx.accounts.session, won, payout, seed)?;
        ctx.accounts.session.game_state = 2;
        emit_outcome(ctx.accounts.session.player, won, payout, &outcome);
        Ok(())
    }

    // ── Reveal: delegated (session key — zero wallet popup) ───────────────

    /// @notice Delegated Flip reveal. Ephemeral session key signs — no wallet popup.
     pub fn reveal_flip_delegated(ctx: Context<RevealDelegated>, nonce: [u8; 32]) -> Result<()> {
        check_session_token(&ctx.accounts.session_token)?;
        let (won, payout, outcome, seed) = resolve(0, &ctx.accounts.session, &ctx.accounts.slot_hashes.to_account_info(), &nonce, ctx.accounts.pool.total_balance)?;
        settle(&mut ctx.accounts.pool, &ctx.accounts.player, &ctx.accounts.referrer, &ctx.accounts.session, won, payout, seed)?;
        ctx.accounts.session.game_state = 2;
        emit_outcome(ctx.accounts.session.player, won, payout, &outcome);
        Ok(())
    }

    /// @notice Delegated Sector99 reveal.
     pub fn reveal_sector_delegated(ctx: Context<RevealDelegated>, nonce: [u8; 32]) -> Result<()> {
        check_session_token(&ctx.accounts.session_token)?;
        let (won, payout, outcome, seed) = resolve(1, &ctx.accounts.session, &ctx.accounts.slot_hashes.to_account_info(), &nonce, ctx.accounts.pool.total_balance)?;
        settle(&mut ctx.accounts.pool, &ctx.accounts.player, &ctx.accounts.referrer, &ctx.accounts.session, won, payout, seed)?;
        ctx.accounts.session.game_state = 2;
        emit_outcome(ctx.accounts.session.player, won, payout, &outcome);
        Ok(())
    }

    /// @notice Delegated Dice reveal.
     pub fn reveal_dice_delegated(ctx: Context<RevealDelegated>, nonce: [u8; 32]) -> Result<()> {
        check_session_token(&ctx.accounts.session_token)?;
        let (won, payout, outcome, seed) = resolve(2, &ctx.accounts.session, &ctx.accounts.slot_hashes.to_account_info(), &nonce, ctx.accounts.pool.total_balance)?;
        settle(&mut ctx.accounts.pool, &ctx.accounts.player, &ctx.accounts.referrer, &ctx.accounts.session, won, payout, seed)?;
        ctx.accounts.session.game_state = 2;
        emit_outcome(ctx.accounts.session.player, won, payout, &outcome);
        Ok(())
    }

    /// @notice Delegated Tower reveal.
     pub fn reveal_tower_delegated(ctx: Context<RevealDelegated>, nonce: [u8; 32]) -> Result<()> {
        check_session_token(&ctx.accounts.session_token)?;
        let (won, payout, outcome, seed) = resolve(3, &ctx.accounts.session, &ctx.accounts.slot_hashes.to_account_info(), &nonce, ctx.accounts.pool.total_balance)?;
        settle(&mut ctx.accounts.pool, &ctx.accounts.player, &ctx.accounts.referrer, &ctx.accounts.session, won, payout, seed)?;
        ctx.accounts.session.game_state = 2;
        emit_outcome(ctx.accounts.session.player, won, payout, &outcome);
        Ok(())
    }

    // ── Forfeit / Refund paths ─────────────────────────────────────────────

    /// @notice Permissionless cleanup after forfeit window + 200 slot grace period.
    /// @dev    Entire bet stays in pool. No bounty = no bot-griefing incentive.
    pub fn claim_forfeit(ctx: Context<ClaimForfeit>) -> Result<()> {
        let clock = Clock::get()?;
        require!(
            ctx.accounts.session.game_state < 2
                && clock.slot > ctx.accounts.session.forfeit_slot.saturating_add(200),
            BlitzError::ForfeitNotAvailable
        );
        let pool_ai = ctx.accounts.pool.to_account_info();
        sync_balance(&mut ctx.accounts.pool, &pool_ai)?;
        ctx.accounts.session.game_state = 2;
        emit!(BetForfeited { player: ctx.accounts.session.player, amount: ctx.accounts.session.bet_lamports });
        Ok(())
    }

    /// @notice Player voluntarily forfeits while slot hash is still accessible.
    /// @dev    4% refund makes selective-reveal EV-negative:
    ///         EV(flip) = 0.5×0.95 + 0.5×(0.04−1) = −0.005 SOL. Attack unprofitable.
    pub fn voluntary_forfeit(ctx: Context<VoluntaryForfeit>) -> Result<()> {
        let clock = Clock::get()?;
        require!(ctx.accounts.session.game_state == 0,                             BlitzError::SessionNotPending);
        require!(ctx.accounts.session.player == ctx.accounts.player.key(),         BlitzError::NotSessionPlayer);
        require!(clock.slot > ctx.accounts.session.forfeit_slot,                   BlitzError::ForfeitNotAvailable);
        require!(clock.slot.saturating_sub(ctx.accounts.session.resolve_slot) < 490, BlitzError::UseEmergencyRefund);
        send_refund(&mut ctx.accounts.pool, &ctx.accounts.player, ctx.accounts.session.bet_lamports, 4)?;
        ctx.accounts.session.game_state = 2;
        emit!(BetForfeited { player: ctx.accounts.session.player, amount: ctx.accounts.session.bet_lamports.saturating_mul(96) / 100 });
        Ok(())
    }

    /// @notice Refunds 4% when the slot hash has expired (>490 slots). Genuine failure path.
    /// @dev    96% stays in pool — deters deliberate non-reveal abuse.
    pub fn emergency_refund(ctx: Context<EmergencyRefund>) -> Result<()> {
        let clock = Clock::get()?;
        require!(ctx.accounts.session.game_state == 0,                              BlitzError::SessionNotPending);
        require!(ctx.accounts.session.player == ctx.accounts.player.key(),          BlitzError::NotSessionPlayer);
        require!(clock.slot > ctx.accounts.session.forfeit_slot,                    BlitzError::ForfeitNotAvailable);
        require!(clock.slot.saturating_sub(ctx.accounts.session.resolve_slot) >= 490, BlitzError::SlotHashStillAvailable);
        send_refund(&mut ctx.accounts.pool, &ctx.accounts.player, ctx.accounts.session.bet_lamports, 4)?;
        ctx.accounts.session.game_state = 2;
        emit!(BetForfeited { player: ctx.accounts.session.player, amount: ctx.accounts.session.bet_lamports.saturating_mul(96) / 100 });
        Ok(())
    }

    /// @notice Permissionless circuit breaker when pool cannot cover worst-case payout.
    /// @dev    50% refund is fair — insolvency is not the player's fault.
    pub fn emergency_player_refund(ctx: Context<BotRefund>) -> Result<()> {
        require!(ctx.accounts.session.game_state == 0,                     BlitzError::SessionNotPending);
        require!(ctx.accounts.session.player == ctx.accounts.player.key(), BlitzError::NotSessionPlayer);
        let cfg   = [ctx.accounts.session.target_x, ctx.accounts.session.target_y, ctx.accounts.session.target_radius];
        let worst = get_worst_payout(ctx.accounts.session.bet_lamports, ctx.accounts.session.game_type, &cfg);
        require!(ctx.accounts.pool.total_balance < worst, BlitzError::InsufficientLiquidity);
        send_refund(&mut ctx.accounts.pool, &ctx.accounts.player, ctx.accounts.session.bet_lamports, 50)?;
        ctx.accounts.session.game_state = 2;
        emit!(BetForfeited { player: ctx.accounts.session.player, amount: ctx.accounts.session.bet_lamports.saturating_mul(50) / 100 });
        Ok(())
    }

    // ── Session Keys ───────────────────────────────────────────────────────

    /// @notice Creates a time-bounded delegate key for wallet-popup-free auto-reveals.
    /// @dev    validity_secs capped at 24h. Gas forwarded to delegate up to 0.01 SOL.
    pub fn create_session(ctx: Context<CreateSession>, validity_secs: i64, gas_lamports: u64) -> Result<()> {
        require!(validity_secs > 0 && validity_secs <= 86400, BlitzError::InvalidSessionDuration);
        require!(gas_lamports <= 10_000_000,                  BlitzError::GasTooHigh);
        let clock   = Clock::get()?;
        let t       = &mut ctx.accounts.session_token;
        t.player    = ctx.accounts.player.key();
        t.delegate  = ctx.accounts.delegate.key();
        t.expires_at = clock.unix_timestamp + validity_secs;
        t.bump      = ctx.bumps.session_token;
        if gas_lamports > 0 {
            invoke(
                &system_instruction::transfer(&t.player, &t.delegate, gas_lamports),
                &[ctx.accounts.player.to_account_info(), ctx.accounts.delegate.to_account_info()],
            )?;
        }
        emit!(SessionCreated { player: t.player, delegate: t.delegate, expires_at: t.expires_at });
        Ok(())
    }

    /// @notice Closes the session token PDA, reclaiming rent to the player.
    pub fn close_session(_ctx: Context<CloseSession>) -> Result<()> { Ok(()) }

    // ── Admin ──────────────────────────────────────────────────────────────

    /// @notice Pauses or unpauses the contract.
    /// @dev    Pause is hard-capped at MAX_PAUSE_DURATION (24h).
    ///         place_bet auto-expires a forgotten pause — funds can never be frozen permanently.
    pub fn set_paused(ctx: Context<AdminOnly>, paused: bool) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        pool.paused = paused;
        if paused {
            pool.pause_expires_at = Clock::get()?.unix_timestamp + MAX_PAUSE_DURATION;
            emit!(ContractPaused { authority: pool.authority, expires_at: pool.pause_expires_at });
        } else {
            pool.pause_expires_at = 0;
            emit!(ContractUnpaused { authority: pool.authority });
        }
        Ok(())
    }

    /// @notice Initiates a withdrawal (48h timelock, max 20% of pool per request).
    pub fn request_withdrawal(ctx: Context<AdminOnly>, amount: u64) -> Result<()> {
        let pool  = &mut ctx.accounts.pool;
        let clock = Clock::get()?;
        require!(pool.withdrawal_request.is_none(),  BlitzError::PendingWithdrawal);
        require!(amount <= pool.total_balance / 5,   BlitzError::WithdrawalTooLarge);
        pool.withdrawal_request = Some(WithdrawalRequest {
            amount,
            requested_at: clock.unix_timestamp,
            unlocks_at:   clock.unix_timestamp + TIMELOCK_SECS,
        });
        emit!(WithdrawalRequested { amount, unlocks_at: clock.unix_timestamp + TIMELOCK_SECS });
        Ok(())
    }

    /// @notice Executes a pending withdrawal after the 48h timelock.
    pub fn execute_withdrawal(ctx: Context<AdminOnly>) -> Result<()> {
        let pool  = &mut ctx.accounts.pool;
        let clock = Clock::get()?;
        let req   = pool.withdrawal_request.clone().ok_or(BlitzError::NoWithdrawalRequest)?;
        require!(clock.unix_timestamp >= req.unlocks_at, BlitzError::TimelockActive);
        require!(pool.total_balance >= req.amount,        BlitzError::InsufficientLiquidity);
        **pool.to_account_info().try_borrow_mut_lamports()? -= req.amount;
        **ctx.accounts.authority.try_borrow_mut_lamports()? += req.amount;
        pool.withdrawal_request = None;
        let pool_ai = pool.to_account_info();
        sync_balance(pool, &pool_ai)?;
        emit!(WithdrawalExecuted { amount: req.amount });
        Ok(())
    }

    /// @notice Cancels a pending withdrawal request.
    pub fn cancel_withdrawal(ctx: Context<AdminOnly>) -> Result<()> {
        ctx.accounts.pool.withdrawal_request = None;
        Ok(())
    }

    /// @notice Withdraws the claimable portion of house fees.
    /// @dev    Only `house_fees_earned` is withdrawable. Liquid pool balance is protected.
    pub fn claim_house_fees(ctx: Context<ClaimHouseFeesCtx>, amount: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        require!(amount > 0 && amount <= pool.house_fees_earned, BlitzError::InsufficientLiquidity);
        let rent = Rent::get()?.minimum_balance(pool.to_account_info().data_len());
        require!(pool.to_account_info().lamports().saturating_sub(rent) >= amount, BlitzError::InsufficientLiquidity);
        **pool.to_account_info().try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.authority.try_borrow_mut_lamports()? += amount;
        pool.house_fees_earned     = pool.house_fees_earned.saturating_sub(amount);
        pool.operational_extracted = pool.operational_extracted.saturating_add(amount);
        let pool_ai = pool.to_account_info();
        sync_balance(pool, &pool_ai)?;
        emit!(HouseFeesClaimed { amount, authority: ctx.accounts.authority.key() });
        Ok(())
    }

    /// @notice Initiates a request to reinvest house fees back to the liquid pool (24h timelock).
    pub fn request_reinvest(ctx: Context<AdminOnly>, amount: u64) -> Result<()> {
        let pool  = &mut ctx.accounts.pool;
        let clock = Clock::get()?;
        require!(amount > 0 && amount <= pool.house_fees_earned, BlitzError::InsufficientLiquidity);
        require!(pool.reinvest_request.is_none(),  BlitzError::PendingWithdrawal);
        pool.reinvest_request = Some(WithdrawalRequest {
            amount,
            requested_at: clock.unix_timestamp,
            unlocks_at:   clock.unix_timestamp + MAX_PAUSE_DURATION, // 24h delay
        });
        emit!(ReinvestRequested { amount, unlocks_at: clock.unix_timestamp + MAX_PAUSE_DURATION });
        Ok(())
    }

    /// @notice Executes a pending house fee reinvestment after the 24h timelock.
    /// @dev    Purely internal accounting — no lamports leave the account.
    pub fn execute_reinvest(ctx: Context<AdminOnly>) -> Result<()> {
        let pool  = &mut ctx.accounts.pool;
        let clock = Clock::get()?;
        let req   = pool.reinvest_request.clone().ok_or(BlitzError::NoWithdrawalRequest)?;
        require!(clock.unix_timestamp >= req.unlocks_at, BlitzError::TimelockActive);
        require!(req.amount <= pool.house_fees_earned, BlitzError::InsufficientLiquidity);
        pool.house_fees_earned = pool.house_fees_earned.saturating_sub(req.amount);
        pool.total_reinvested  = pool.total_reinvested.saturating_add(req.amount);
        pool.reinvest_request  = None;
        let pool_ai = pool.to_account_info();
        sync_balance(pool, &pool_ai)?;
        emit!(ReinvestExecuted { amount: req.amount });
        Ok(())
    }

    // ── Authority Transfer (72h timelock, new key must co-sign) ──────────

    /// @notice Proposes a new authority (72h timelock + new key must confirm).
    pub fn propose_authority_transfer(ctx: Context<AdminOnly>, new_authority: Pubkey) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        require!(new_authority != pool.authority && new_authority != Pubkey::default(), BlitzError::InvalidAuthority);
        let now = Clock::get()?.unix_timestamp;
        pool.pending_authority     = Some(new_authority);
        pool.authority_transfer_at = now + AUTH_TIMELOCK;
        emit!(AuthorityTransferProposed { current: pool.authority, proposed: new_authority, unlocks_at: pool.authority_transfer_at });
        Ok(())
    }

    /// @notice Cancels a pending authority transfer.
    pub fn cancel_authority_transfer(ctx: Context<AdminOnly>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        require!(pool.pending_authority.is_some(), BlitzError::NoWithdrawalRequest);
        pool.pending_authority     = None;
        pool.authority_transfer_at = 0;
        emit!(AuthorityTransferCancelled { authority: pool.authority });
        Ok(())
    }

    /// @notice Finalises authority transfer. New authority must sign to confirm.
    pub fn execute_authority_transfer(ctx: Context<ExecuteAuthorityTransfer>) -> Result<()> {
        let pool     = &mut ctx.accounts.pool;
        let new_auth = pool.pending_authority.ok_or(BlitzError::NoWithdrawalRequest)?;
        require!(ctx.accounts.new_authority.key() == new_auth,          BlitzError::InvalidAuthority);
        require!(Clock::get()?.unix_timestamp >= pool.authority_transfer_at, BlitzError::TimelockActive);
        let old        = pool.authority;
        pool.authority = new_auth;
        pool.pending_authority     = None;
        pool.authority_transfer_at = 0;
        emit!(AuthorityTransferred { old_authority: old, new_authority: new_auth });
        Ok(())
    }

    // ── One-time migration (remove after upgrade) ────────────────────────

    /// @notice Expands GlobalPool from old layout to new layout (adds reinvest_request).
    /// @dev    Call once after program upgrade. Safe to delete from code after migration.
    pub fn migrate_pool(ctx: Context<MigratePool>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        pool.reinvest_request = None;
        Ok(())
    }
}

// ══════════════════════════════════════════════════════════════════════════
//  PRIVATE HELPERS
// ══════════════════════════════════════════════════════════════════════════

// ── Session guard ─────────────────────────────────────────────────────────

#[inline]
fn check_session_token(token: &Account<SessionToken>) -> Result<()> {
    require!(Clock::get()?.unix_timestamp < token.expires_at, BlitzError::SessionExpired);
    Ok(())
}

// ── Refund helper ─────────────────────────────────────────────────────────

/// Transfers `pct`% of `bet` from pool to `dest`, then syncs balance.
fn send_refund<'info>(
    pool: &mut Account<'info, GlobalPool>,
    dest: &AccountInfo<'info>,
    bet:  u64,
    pct:  u64,
) -> Result<()> {
    let refund = bet.saturating_mul(pct) / 100;
    require!(pool.total_balance >= refund, BlitzError::InsufficientLiquidity);
    let pool_ai = pool.to_account_info();
    **pool_ai.try_borrow_mut_lamports()? -= refund;
    **dest.try_borrow_mut_lamports()?    += refund;
    sync_balance(pool, &pool_ai)
}

// ── Referrer check ────────────────────────────────────────────────────────

#[inline(always)]
fn is_valid_referrer(referrer: Pubkey, player: Pubkey) -> bool {
    referrer != system_program::ID && referrer != player
}

// ── Balance sync ──────────────────────────────────────────────────────────

/// @dev Derives `total_balance` from physical lamports every time funds move.
///      Single source of truth — eliminates accounting desync.
fn sync_balance(pool: &mut Account<GlobalPool>, ai: &AccountInfo) -> Result<()> {
    let rent     = Rent::get()?.minimum_balance(ai.data_len());
    let physical = ai.lamports().saturating_sub(rent);
    let reserved = pool.house_fees_earned.saturating_add(pool.jackpot_balance);
    require!(physical >= reserved, BlitzError::AccountingBroken);
    pool.total_balance = physical.saturating_sub(reserved);
    Ok(())
}

// ── Fee schedule ──────────────────────────────────────────────────────────

fn get_fee_bps(pool_balance: u64, has_ref: bool) -> (u64, u64, u64) {
    match (pool_balance < PHASE1_THRESHOLD, pool_balance < PHASE2_THRESHOLD, has_ref) {
        (true,  _,    true)  => (50,  150, 50), // Phase 0 + ref
        (true,  _,    false) => (200, 0,   50), // Phase 0 solo
        (false, true, true)  => (50,  100, 50), // Phase 1 + ref
        (false, true, false) => (150, 0,   50), // Phase 1 solo
        (false, false,true)  => (50,  75,  25), // Phase 2 + ref
        (false, false,false) => (125, 0,   25), // Phase 2 solo
    }
}

// ── Auto-reinvest split ───────────────────────────────────────────────────

/// Returns (claimable, reinvested). INVARIANT: claimable + reinvested == house_cut.
fn split_house_fees(pool_balance: u64, house_cut: u64, bet: u64) -> (u64, u64) {
    let operational = (bet.saturating_mul(OPERATIONAL_BPS) / 10_000).min(house_cut);
    let remainder   = house_cut.saturating_sub(operational);
    if pool_balance < PHASE1_THRESHOLD {
        (operational, remainder)                                             // Phase 0: lock all
    } else if pool_balance < PHASE2_THRESHOLD {
        let reinvest = remainder / 2;
        (operational.saturating_add(remainder.saturating_sub(reinvest)), reinvest) // Phase 1: 50/50
    } else {
        (house_cut, 0)                                                       // Phase 2: all claimable
    }
}

// ── Payout numerator ──────────────────────────────────────────────────────

#[inline(always)]
fn payout_num(pool_balance: u64) -> u64 {
    if      pool_balance < PHASE1_THRESHOLD { 9_750 }
    else if pool_balance < PHASE2_THRESHOLD { 9_800 }
    else                                    { 9_850 }
}

// ── Unified payout formula ────────────────────────────────────────────────

/// @notice Core payout calculator shared by all four games.
/// @param bet              Wager in lamports.
/// @param win_chance_num   Numerator of win probability fraction.
/// @param win_chance_den   Denominator of win probability fraction.
/// @param pool_balance     Selects the phase retention multiplier.
#[inline(always)]
fn calc_payout(bet: u64, win_chance_num: u64, win_chance_den: u64, pool_balance: u64) -> u64 {
    if win_chance_num == 0 { return 0; }
    ((bet as u128)
        .saturating_mul(payout_num(pool_balance) as u128)
        .saturating_mul(win_chance_den as u128)
        / (win_chance_num as u128)
        / 10_000) as u64
}

// ── Config validation ─────────────────────────────────────────────────────

fn validate_game_config(game_type: u8, cfg: &[u8; 3]) -> Result<()> {
    match game_type {
        0 => require!(*cfg == [0, 0, 0],              BlitzError::InvalidGameConfig),
        1 => {
            require!(cfg[0] < 16,                     BlitzError::InvalidCoordinate);
            require!(cfg[1] < 16,                     BlitzError::InvalidCoordinate);
            require!(cfg[2] <= 3,                     BlitzError::InvalidRadius);
        }
        2 => {
            require!(cfg[1] <= 1,                     BlitzError::InvalidGameConfig);
            if cfg[1] == 0 {
                require!(cfg[0] >= 2 && cfg[0] <= 95, BlitzError::InvalidDiceTarget);
            } else {
                require!(cfg[0] >= 4 && cfg[0] <= 97, BlitzError::InvalidDiceTarget);
            }
        }
        3 => {
            require!(cfg[0] >= 1 && cfg[0] <= 6,     BlitzError::InvalidTowerFloors);
            require!(cfg[1] & !((1u8 << cfg[0]).wrapping_sub(1)) == 0, BlitzError::InvalidGameConfig);
        }
        _ => return Err(BlitzError::InvalidGameType.into()),
    }
    Ok(())
}

// ── Unified resolver ──────────────────────────────────────────────────────

/// Validates the reveal, extracts the BLAKE3 seed, resolves the game.
/// Returns (won, gross_payout, GameOutcome, seed).
fn resolve<'a>(
    game_type:    u8,
    session:      &Account<'a, GameSession>,
    slot_hashes:  &AccountInfo<'a>,
    nonce:        &[u8; 32],
    pool_balance: u64,
) -> Result<(bool, u64, GameOutcome, [u8; 32])> {
    require!(session.game_type == game_type, BlitzError::WrongGameType);
    let clock = Clock::get()?;
    let seed  = extract_and_validate_seed(session, slot_hashes, &clock, nonce, game_type)?;

    Ok(match game_type {
        0 => {
            let roll  = u64::from_le_bytes(seed[0..8].try_into().unwrap()) % 100;
            let won   = roll < 50;
            let gross = calc_payout(session.bet_lamports, 50, 100, pool_balance);
            (won, if won { gross } else { 0 }, GameOutcome::Flip { roll: roll as u8 }, seed)
        }
        1 => {
            let sx  = seed[0] % 16;
            let sy  = seed[1] % 16;
            let won = session.target_x.abs_diff(sx).max(session.target_y.abs_diff(sy)) <= session.target_radius;
            let gross = if won {
                let w = session.target_radius as u64 * 2 + 1;
                calc_payout(session.bet_lamports, w * w, 256, pool_balance)
            } else { 0 };
             (won, gross, GameOutcome::Sector { strike_x: sx, strike_y: sy }, seed)
        }
        2 => {
            let roll      = u64::from_le_bytes(seed[0..8].try_into().unwrap()) % 100;
            let target    = session.target_x as u64;
            let is_over   = session.target_y == 1;
            let won       = if is_over { roll > target } else { roll < target };
            let win_range = if is_over { 99u64.saturating_sub(target) } else { target };
            let gross     = calc_payout(session.bet_lamports, win_range, 100, pool_balance);
             (won, if won { gross } else { 0 }, GameOutcome::Dice { roll: roll as u8, target: target as u8, is_over }, seed)
        }
        3 => {
            let floors = session.target_x as usize;
            let path   = session.target_y;
            let (mut death, mut traps) = (0u8, 0u8);
            for i in 0..floors {
                let trap = seed[i] % 2;
                traps   |= trap << i;
                if death == 0 && (path >> i) & 1 == trap { death = (i + 1) as u8; }
            }
            let won   = death == 0;
            let gross = calc_payout(session.bet_lamports, 1, 1u64 << floors, pool_balance);
             (won, if won { gross } else { 0 }, GameOutcome::Tower { floors: session.target_x, death_floor: death, path, traps }, seed)
        }
        _ => return Err(BlitzError::InvalidGameType.into()),
    })
}

// ── Settlement core ───────────────────────────────────────────────────────

/// @dev MONEY INVARIANT:
///      bet already in pool (deposited at place_bet).
///      Win:  gross_payout + ref_cut exit the pool physically.
///      Loss: only ref_cut exits.
///      jackpot_cut and house_cut are internal compartment moves only — lamports stay.
///
///      Steps: (1) math → (2) jackpot → (3) solvency → (4) transfers → (5) compartments → (6) analytics → (7) sync
fn settle<'info>(
    pool:         &mut Account<'info, GlobalPool>,
    player_ai:    &AccountInfo<'info>,
    referrer_ai:  &AccountInfo<'info>,
    session:      &Account<GameSession>,
    won:          bool,
    gross_payout: u64,
    seed:         [u8; 32],
) -> Result<()> {
    let has_ref  = is_valid_referrer(session.referrer, session.player);
    let (house_bps, ref_bps, jackpot_bps) = get_fee_bps(pool.total_balance, has_ref);
    let bet      = session.bet_lamports;

    // (1) Math
    let jackpot_cut   = bet.saturating_mul(jackpot_bps) / 10_000;
    let mut house_cut = bet.saturating_mul(house_bps) / 10_000;
    let mut ref_cut   = 0u64;
    if has_ref {
        let potential = bet.saturating_mul(ref_bps) / 10_000;
        if referrer_ai.lamports() >= 50_000_000 && potential >= 1_000_000 {
            ref_cut = potential;
        } else {
            house_cut = house_cut.saturating_add(potential);
        }
    }

    // (2) Jackpot trigger — uses seed bytes 24..28 (independent of game bytes 0..8)
    let mut jackpot_prize = 0u64;
    if bet >= JACKPOT_MIN_BET && pool.jackpot_balance >= JACKPOT_MIN_POOL {
        let roll      = u32::from_le_bytes(seed[24..28].try_into().unwrap()) as u64;
        let threshold = (bet.saturating_mul(JACKPOT_RATE) / JACKPOT_BASE).min(u32::MAX as u64 / 200);
        if roll < threshold {
            jackpot_prize = pool.jackpot_balance.saturating_mul(90) / 100;
        }
    }

    // (3) Solvency
    let physical_out  = if won { gross_payout } else { 0 } + ref_cut + jackpot_prize;
    let internal_move = jackpot_cut + house_cut;
    let rent      = Rent::get()?.minimum_balance(pool.to_account_info().data_len());
    let available = pool.to_account_info().lamports()
        .saturating_sub(rent)
        .saturating_sub(pool.house_fees_earned)
        .saturating_sub(pool.jackpot_balance);
    require!(available >= physical_out + internal_move, BlitzError::InsufficientLiquidity);

    // (4) Physical transfers
    if physical_out > 0 {
        **pool.to_account_info().try_borrow_mut_lamports()? -= physical_out;
        let player_gets = if won { gross_payout } else { 0 } + jackpot_prize;
        if player_gets > 0 { **player_ai.try_borrow_mut_lamports()? += player_gets; }
        if ref_cut > 0 {
            match referrer_ai.try_borrow_mut_lamports() {
                Ok(mut l) => **l += ref_cut,
                Err(_)    => **player_ai.try_borrow_mut_lamports()? += ref_cut,
            }
        }
    }

    // (5) Internal compartments
    pool.jackpot_balance  = pool.jackpot_balance.saturating_sub(jackpot_prize).saturating_add(jackpot_cut);
    let post_transfer_balance = pool.total_balance.saturating_sub(if won { gross_payout + ref_cut } else { ref_cut });
    let (claimable, reinvested) = split_house_fees(post_transfer_balance, house_cut, bet);
    pool.house_fees_earned = pool.house_fees_earned.saturating_add(claimable);
    pool.total_reinvested  = pool.total_reinvested.saturating_add(reinvested);

    // (6) Analytics — on-chain RTP: total_paid_out × 10_000 / total_wagered
    if won {
        pool.total_wins     = pool.total_wins.saturating_add(1);
        pool.total_paid_out = pool.total_paid_out.saturating_add(gross_payout);
        if gross_payout > pool.biggest_win { pool.biggest_win = gross_payout; }
    }
    if jackpot_prize > 0 {
        pool.total_jackpot_won = pool.total_jackpot_won.saturating_add(jackpot_prize);
        pool.total_paid_out    = pool.total_paid_out.saturating_add(jackpot_prize);
        emit!(JackpotWon { player: session.player, amount: jackpot_prize });
    }

     // (7) Sync
    let pool_ai = pool.to_account_info();
    sync_balance(pool, &pool_ai)
}

// ── Seed extraction & validation ──────────────────────────────────────────

fn extract_and_validate_seed<'info>(
    session:    &Account<'info, GameSession>,
    slot_hashes: &AccountInfo<'info>,
    clock:      &Clock,
    nonce:      &[u8; 32],
    game_type:  u8,
) -> Result<[u8; 32]> {
    require!(session.game_state == 0,             BlitzError::SessionNotPending);
    require!(session.game_type  == game_type,     BlitzError::WrongGameType);
    require!(clock.slot >= session.resolve_slot + SLOT_SPREAD * 2 + 1, BlitzError::TooEarlyToReveal);
    require!(clock.slot <= session.forfeit_slot,  BlitzError::RevealWindowExpired);
    require!(clock.slot.saturating_sub(session.resolve_slot) < 490, BlitzError::SlotTooOld);
    require!(hash::hash(nonce).to_bytes() == session.commitment, BlitzError::InvalidNonce);

     let seed = build_seed(slot_hashes, session.resolve_slot, nonce, session.bet_lamports)?;
    Ok(seed)
}

/// BLAKE3(nonce || hash[T] || hash[T+10] || hash[T+20] || target_slot || bet_lamports)
/// Three hashes × SLOT_SPREAD → each from a different validator leader rotation.
fn build_seed(
    slot_hashes_ai: &AccountInfo,
    target_slot:    u64,
    nonce:          &[u8; 32],
    bet_lamports:   u64,
) -> Result<[u8; 32]> {
    let data = slot_hashes_ai.data.borrow();
    let n    = u64::from_le_bytes(data[0..8].try_into().unwrap()) as usize;
    let mut hashes = [[0u8; 32]; 3];

    for offset in 0u64..3 {
        let slot = target_slot + offset * SLOT_SPREAD;
        let idx  = (0..n.min(512)).find(|&i| {
            u64::from_le_bytes(data[8 + i*40..16 + i*40].try_into().unwrap()) == slot
        });
        match idx {
            Some(i) => hashes[offset as usize] = data[16 + i*40..48 + i*40].try_into().unwrap(),
            None    => return Err(BlitzError::SlotHashNotFound.into()),
        }
    }

    let mut h = blake3::Hasher::new();
    h.update(nonce);
    h.update(&hashes[0]);
    h.update(&hashes[1]);
    h.update(&hashes[2]);
    h.update(&target_slot.to_le_bytes());
    h.update(&bet_lamports.to_le_bytes());
    Ok(*h.finalize().as_bytes())
}

// ── Event emitter ─────────────────────────────────────────────────────────

fn emit_outcome(player: Pubkey, won: bool, payout: u64, outcome: &GameOutcome) {
    match outcome {
        GameOutcome::Flip   { roll }                             => emit!(FlipSettled   { player, won, roll:     *roll,     payout }),
        GameOutcome::Sector { strike_x, strike_y }              => emit!(SectorSettled { player, won, strike_x: *strike_x, strike_y: *strike_y, payout }),
        GameOutcome::Dice   { roll, target, is_over }           => emit!(DiceSettled   { player, won, roll:     *roll,     target: *target, payout, is_over: *is_over }),
        GameOutcome::Tower  { floors, death_floor, path, traps} => emit!(TowerSettled  { player, won, floors:   *floors,   death_floor: *death_floor, payout, path: *path, traps: *traps }),
    }
}

// ══════════════════════════════════════════════════════════════════════════
//  PUBLIC UTILITIES (used by client-side bet sizing)
// ══════════════════════════════════════════════════════════════════════════

/// Coordinated max bet — never advertises a bet that `payout_cap` would reject.
pub fn get_max_bet(pool: u64, game: u8, cfg: &[u8; 3]) -> u64 {
    let cap     = get_max_payout_cap(pool);
    let pct_lim = if pool < 5_000_000_000 {
        pool / 100 // <5 SOL: 1% survival mode
    } else {
        match game {
            0 | 2 => pool.saturating_mul(3) / 100, // Flip / Dice:   3%
            _     => pool.saturating_mul(2) / 100, // Sector / Tower: 2%
        }
    };
    let worst_1sol = get_worst_payout(1_000_000_000, game, cfg);
    let cap_lim    = if worst_1sol > 0 { cap.saturating_mul(1_000_000_000) / worst_1sol } else { pct_lim };
    pct_lim.min(cap_lim)
}

/// Dynamic payout cap — tiered by pool health. No hard ceiling.
pub fn get_max_payout_cap(pool: u64) -> u64 {
    match pool {
        p if p < 5_000_000_000   => p.saturating_mul(3)  / 100,
        p if p < 20_000_000_000  => p.saturating_mul(5)  / 100,
        p if p < 100_000_000_000 => p.saturating_mul(8)  / 100,
        p if p < 500_000_000_000 => p.saturating_mul(10) / 100,
        p                        => p.saturating_mul(12) / 100,
    }
}

/// Smooth linear resolve delay: +1 slot per 0.02 SOL, clamped to [10, 55].
pub fn get_resolve_slot(slot: u64, bet: u64) -> u64 {
    slot + (10u64).saturating_add(bet / 20_000_000).min(55)
}

/// Worst-case payout using Phase-2 numerator (most conservative).
pub fn get_worst_payout(bet: u64, game: u8, cfg: &[u8; 3]) -> u64 {
    match game {
        0 => calc_payout(bet, 50, 100, PHASE2_THRESHOLD),
        1 => { let w = cfg[2].min(3) as u64 * 2 + 1; calc_payout(bet, w * w, 256, PHASE2_THRESHOLD) }
        2 => {
            let t  = if cfg[1] == 0 { cfg[0].max(2) } else { cfg[0].max(4) } as u64;
            let wc = if cfg[1] == 1 { 99u64.saturating_sub(t) } else { t };
            calc_payout(bet, wc, 100, PHASE2_THRESHOLD)
        }
        3 => calc_payout(bet, 1, 1u64 << cfg[0].max(1).min(6), PHASE2_THRESHOLD),
        _ => 0,
    }
}

// ══════════════════════════════════════════════════════════════════════════
//  ACCOUNTS
// ══════════════════════════════════════════════════════════════════════════

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = authority, space = 8 + GlobalPool::LEN, seeds = [b"global_pool"], bump)]
    pub pool:           Account<'info, GlobalPool>,
    #[account(mut)] pub authority:      Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct FundPool<'info> {
    #[account(mut, seeds = [b"global_pool"], bump = pool.bump)]
    pub pool:           Account<'info, GlobalPool>,
    #[account(mut)] pub funder:         Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(game_type: u8, commitment: [u8; 32], bet_lamports: u64)]
pub struct PlaceBet<'info> {
    #[account(mut)] pub player:   Signer<'info>,
    /// CHECK: Optional referrer — pass player's own key if none.
    pub referrer: AccountInfo<'info>,
    #[account(mut, seeds = [b"global_pool"], bump = pool.bump)]
    pub pool:     Account<'info, GlobalPool>,
    #[account(init, payer = player, space = 8 + GameSession::LEN,
              seeds = [b"session", player.key().as_ref(), commitment.as_ref()], bump)]
    pub session:        Account<'info, GameSession>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RevealGame<'info> {
    #[account(mut)] pub player:   Signer<'info>,
    /// CHECK: Must match session.referrer. Writable to receive commission.
    #[account(mut, address = session.referrer)] pub referrer: AccountInfo<'info>,
    #[account(mut, seeds = [b"global_pool"], bump = pool.bump)] pub pool: Account<'info, GlobalPool>,
    #[account(mut, has_one = player, close = player)] pub session: Account<'info, GameSession>,
    /// CHECK: Address-validated sysvar — not injectable.
    #[account(address = slot_hashes::ID)] pub slot_hashes: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct RevealDelegated<'info> {
    #[account(mut)] pub delegate: Signer<'info>,
    /// CHECK: Validated via has_one constraints on session + session_token.
    #[account(mut)] pub player:   AccountInfo<'info>,
    /// CHECK: Must match session.referrer. Writable to receive commission.
    #[account(mut, address = session.referrer)] pub referrer: AccountInfo<'info>,
    #[account(mut, seeds = [b"global_pool"], bump = pool.bump)] pub pool: Account<'info, GlobalPool>,
    #[account(mut, has_one = player, close = player)] pub session: Account<'info, GameSession>,
    #[account(seeds = [b"session_key", player.key().as_ref()], bump = session_token.bump,
              has_one = delegate, has_one = player)]
    pub session_token: Account<'info, SessionToken>,
    /// CHECK: Address-validated sysvar — not injectable.
    #[account(address = slot_hashes::ID)] pub slot_hashes: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct CreateSession<'info> {
    #[account(mut)] pub player:   Signer<'info>,
    /// CHECK: Ephemeral key generated client-side.
    #[account(mut)] pub delegate: AccountInfo<'info>,
    #[account(init, payer = player, space = 8 + SessionToken::LEN,
              seeds = [b"session_key", player.key().as_ref()], bump)]
    pub session_token:  Account<'info, SessionToken>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CloseSession<'info> {
    #[account(mut)] pub player:   Signer<'info>,
    /// CHECK: Validated via session_token address constraint.
    #[account(mut, address = session_token.delegate)] pub delegate: AccountInfo<'info>,
    #[account(mut, close = player, seeds = [b"session_key", player.key().as_ref()],
              bump = session_token.bump, has_one = player)]
    pub session_token: Account<'info, SessionToken>,
}

#[derive(Accounts)]
pub struct ClaimForfeit<'info> {
    #[account(mut, seeds = [b"global_pool"], bump = pool.bump)] pub pool: Account<'info, GlobalPool>,
    /// Rent returned to pool, not caller — eliminates griefing incentive.
    #[account(mut, close = pool)] pub session: Account<'info, GameSession>,
    #[account(mut)] pub caller: Signer<'info>,
}

#[derive(Accounts)]
pub struct VoluntaryForfeit<'info> {
    #[account(mut, seeds = [b"global_pool"], bump = pool.bump)] pub pool: Account<'info, GlobalPool>,
    #[account(mut, close = player, has_one = player)] pub session: Account<'info, GameSession>,
    #[account(mut)] pub player: Signer<'info>,
}

#[derive(Accounts)]
pub struct EmergencyRefund<'info> {
    #[account(mut, seeds = [b"global_pool"], bump = pool.bump)] pub pool: Account<'info, GlobalPool>,
    #[account(mut, close = player, has_one = player)] pub session: Account<'info, GameSession>,
    #[account(mut)] pub player: Signer<'info>,
}

#[derive(Accounts)]
pub struct BotRefund<'info> {
    #[account(mut, seeds = [b"global_pool"], bump = pool.bump)] pub pool: Account<'info, GlobalPool>,
    #[account(mut, close = player)] pub session: Account<'info, GameSession>,
    /// CHECK: Lamports returned to original player.
    #[account(mut, address = session.player)] pub player: AccountInfo<'info>,
    #[account(mut)] pub caller: Signer<'info>,
}

#[derive(Accounts)]
pub struct AdminOnly<'info> {
    #[account(mut, seeds = [b"global_pool"], bump = pool.bump, has_one = authority)]
    pub pool:      Account<'info, GlobalPool>,
    #[account(mut)] pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct ClaimHouseFeesCtx<'info> {
    #[account(mut, seeds = [b"global_pool"], bump = pool.bump, has_one = authority)]
    pub pool:      Account<'info, GlobalPool>,
    #[account(mut)] pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct ExecuteAuthorityTransfer<'info> {
    #[account(mut, seeds = [b"global_pool"], bump = pool.bump)] pub pool: Account<'info, GlobalPool>,
    /// New authority must sign — prevents transfer to an inaccessible wallet.
    #[account(mut)] pub new_authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct MigratePool<'info> {
    #[account(mut,
              seeds = [b"global_pool"],
              bump = pool.bump,
              has_one = authority,
              realloc = 8 + GlobalPool::LEN,
              realloc::payer = authority,
              realloc::zero = true)]
    pub pool:           Account<'info, GlobalPool>,
    #[account(mut)] pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

// ══════════════════════════════════════════════════════════════════════════
//  STATE
// ══════════════════════════════════════════════════════════════════════════

/// @notice Single global PDA for all protocol state.
///
/// On-chain RTP (Return-to-Player):
///   rtp_bps = total_paid_out × 10_000 / total_wagered
///   Computable directly from chain — no server trust required.
///
/// Pause timelock:
///   pause_expires_at = now + MAX_PAUSE_DURATION (24h) when paused.
///   place_bet auto-expires a forgotten pause on the next call.
#[account]
pub struct GlobalPool {
    // ── Core ──────────────────────────────────────────────────────────────
    pub authority:             Pubkey,                    // 32
    pub total_balance:         u64,                       // 8
    pub jackpot_balance:       u64,                       // 8
    pub total_wagered:         u64,                       // 8
    pub house_fees_earned:     u64,                       // 8  — claimable portion only
    pub paused:                bool,                      // 1
    pub withdrawal_request:    Option<WithdrawalRequest>, // 1+24 = 25
    pub bump:                  u8,                        // 1
    // ── Analytics ─────────────────────────────────────────────────────────
    pub total_bets:            u64,                       // 8
    pub total_wins:            u64,                       // 8
    pub total_jackpot_won:     u64,                       // 8
    pub biggest_win:           u64,                       // 8
    pub total_paid_out:        u64,                       // 8  — RTP numerator
    // ── Authority transfer ─────────────────────────────────────────────────
    pub pending_authority:     Option<Pubkey>,            // 1+32 = 33
    pub authority_transfer_at: i64,                       // 8
    // ── Auto-reinvest tracking ────────────────────────────────────────────
    pub total_reinvested:      u64,                       // 8
    pub operational_extracted: u64,                       // 8
    pub reinvest_request:      Option<WithdrawalRequest>, // 1+24 = 25
    // ── Pause timelock ────────────────────────────────────────────────────
    pub pause_expires_at:      i64,                       // 8
}

impl GlobalPool {
    pub const LEN: usize =
        32 + 8 + 8 + 8 + 8 + 1 + 25 + 1 +  // core       = 91
        8 + 8 + 8 + 8 + 8 +                 // analytics  = 40
        33 + 8 +                             // auth xfer  = 41
        8 + 8 + 25 +                         // reinvest   = 41
        8;                                   // pause      = 8
    // total = 221 bytes
}

#[account]
pub struct GameSession {
    pub player:        Pubkey,    // 32
    pub referrer:      Pubkey,    // 32
    pub bet_lamports:  u64,       // 8
    pub commitment:    [u8; 32],  // 32
    pub commit_slot:   u64,       // 8
    pub resolve_slot:  u64,       // 8
    pub forfeit_slot:  u64,       // 8
    pub game_type:     u8,        // 1
    pub game_state:    u8,        // 1  — 0=pending, 2=settled
    pub target_x:      u8,        // 1
    pub target_y:      u8,        // 1
    pub target_radius: u8,        // 1
    pub bump:          u8,        // 1
}
impl GameSession { pub const LEN: usize = 134; }

#[account]
pub struct SessionToken {
    pub player:     Pubkey, // 32
    pub delegate:   Pubkey, // 32
    pub expires_at: i64,    // 8
    pub bump:       u8,     // 1
}
impl SessionToken { pub const LEN: usize = 73; }

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct WithdrawalRequest {
    pub amount:       u64, // 8
    pub requested_at: i64, // 8
    pub unlocks_at:   i64, // 8
}

// ══════════════════════════════════════════════════════════════════════════
//  ERRORS
// ══════════════════════════════════════════════════════════════════════════

#[error_code]
pub enum BlitzError {
    #[msg("Contract is paused")]                                             ContractPaused,
    #[msg("Pool balance too low (min 0.1 SOL)")]                             PoolTooLow,
    #[msg("Bet too small (min 0.01 SOL)")]                                   BetTooSmall,
    #[msg("Bet exceeds per-game limit")]                                     BetExceedsLimit,
    #[msg("Invalid game type (0–3)")]                                        InvalidGameType,
    #[msg("Invalid game config")]                                            InvalidGameConfig,
    #[msg("Invalid coordinate (0–15)")]                                      InvalidCoordinate,
    #[msg("Invalid radius (0–3)")]                                           InvalidRadius,
    #[msg("Session not pending")]                                            SessionNotPending,
    #[msg("Session not active")]                                             SessionNotActive,
    #[msg("Reveal window expired")]                                          RevealWindowExpired,
    #[msg("Too early to reveal — slot hashes not finalised yet")]            TooEarlyToReveal,
    #[msg("Wrong game type for this instruction")]                           WrongGameType,
    #[msg("Invalid nonce — commitment mismatch")]                            InvalidNonce,
    #[msg("Insufficient liquidity in pool")]                                 InsufficientLiquidity,
    #[msg("Slot hash not found in sysvar")]                                  SlotHashNotFound,
    #[msg("Forfeit not available yet")]                                      ForfeitNotAvailable,
    #[msg("Withdrawal too large (max 20% of pool)")]                        WithdrawalTooLarge,
    #[msg("A pending withdrawal already exists")]                            PendingWithdrawal,
    #[msg("No withdrawal request exists")]                                   NoWithdrawalRequest,
    #[msg("Timelock has not expired yet")]                                   TimelockActive,
    #[msg("Session key has expired")]                                        SessionExpired,
    #[msg("Invalid session duration (1s–24h)")]                             InvalidSessionDuration,
    #[msg("Gas funding too high (max 0.01 SOL)")]                           GasTooHigh,
    #[msg("Invalid dice target")]                                            InvalidDiceTarget,
    #[msg("Referrer must be a regular wallet, not a PDA")]                  InvalidReferrer,
    #[msg("Slot hash too old (>490 slots) — use emergency_refund")]         SlotTooOld,
    #[msg("Caller is not the session player")]                               NotSessionPlayer,
    #[msg("Payout exceeds pool safety cap")]                                 PayoutExceedsPoolCap,
    #[msg("Tower floors must be 1–6")]                                       InvalidTowerFloors,
    #[msg("Accounting invariant violated — contact support")]                AccountingBroken,
    #[msg("Invalid authority — cannot transfer to self or default pubkey")] InvalidAuthority,
    #[msg("Slot hash still available — use voluntary_forfeit")]              SlotHashStillAvailable,
    #[msg("Slot hash expired — use emergency_refund instead")]               UseEmergencyRefund,
}

// ══════════════════════════════════════════════════════════════════════════
//  EVENTS
// ══════════════════════════════════════════════════════════════════════════

#[event] pub struct PoolFunded                 { pub amount: u64,       pub funder: Pubkey }
#[event] pub struct BetPlaced                  { pub player: Pubkey,    pub game_type: u8, pub amount: u64, pub resolve_slot: u64 }
#[event] pub struct FlipSettled                { pub player: Pubkey,    pub won: bool, pub roll: u8, pub payout: u64 }
#[event] pub struct DiceSettled                { pub player: Pubkey,    pub won: bool, pub roll: u8, pub target: u8, pub payout: u64, pub is_over: bool }
#[event] pub struct SectorSettled              { pub player: Pubkey,    pub won: bool, pub strike_x: u8, pub strike_y: u8, pub payout: u64 }
#[event] pub struct TowerSettled               { pub player: Pubkey,    pub won: bool, pub floors: u8, pub death_floor: u8, pub payout: u64, pub path: u8, pub traps: u8 }
#[event] pub struct BetForfeited               { pub player: Pubkey,    pub amount: u64 }
#[event] pub struct JackpotWon                 { pub player: Pubkey,    pub amount: u64 }
#[event] pub struct WithdrawalRequested        { pub amount: u64,       pub unlocks_at: i64 }
#[event] pub struct WithdrawalExecuted         { pub amount: u64 }
#[event] pub struct HouseFeesClaimed           { pub amount: u64,       pub authority: Pubkey }
#[event] pub struct ReinvestRequested          { pub amount: u64,       pub unlocks_at: i64 }
#[event] pub struct ReinvestExecuted           { pub amount: u64 }
#[event] pub struct SessionCreated             { pub player: Pubkey,    pub delegate: Pubkey, pub expires_at: i64 }
#[event] pub struct ContractPaused             { pub authority: Pubkey, pub expires_at: i64 }
#[event] pub struct ContractUnpaused           { pub authority: Pubkey }
#[event] pub struct AuthorityTransferProposed  { pub current: Pubkey,   pub proposed: Pubkey, pub unlocks_at: i64 }
#[event] pub struct AuthorityTransferCancelled { pub authority: Pubkey }
#[event] pub struct AuthorityTransferred       { pub old_authority: Pubkey, pub new_authority: Pubkey }