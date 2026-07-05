//! SecureDeploy — a hardened upgrade-governance program.
//!
//! Every account struct and handler below is annotated with the specific
//! Solana attack class it defends against. See `../../AUDIT.md` for the full
//! threat model.
#![allow(unexpected_cfgs)] // anchor's cfg(feature = "anchor-debug") etc.

use anchor_lang::prelude::*;

pub mod error;
pub mod state;

use error::SecureError;
use state::{validate_guardians, Approval, ConfigError, Governance, Proposal, MAX_GUARDIANS};

declare_id!("9x3Dcnv4yXcGL6PZaPyRLbjnMfRJ4v1Yqkf5fbX8ToYA");

/// Map a pure-validation [`ConfigError`] onto a program error.
fn map_config_err(e: ConfigError) -> SecureError {
    match e {
        ConfigError::Empty => SecureError::EmptyGuardianSet,
        ConfigError::TooMany => SecureError::TooManyGuardians,
        ConfigError::Duplicate => SecureError::DuplicateGuardian,
        ConfigError::InvalidThreshold => SecureError::InvalidThreshold,
    }
}

#[program]
pub mod securedeploy_core {
    use super::*;

    /// Create the governance account. Guarded against re-initialization by
    /// Anchor's `init` (a second call fails because the account already exists).
    pub fn initialize(
        ctx: Context<Initialize>,
        guardians: Vec<Pubkey>,
        threshold: u8,
        timelock_seconds: i64,
    ) -> Result<()> {
        require!(timelock_seconds >= 0, SecureError::InvalidTimelock);
        validate_guardians(&guardians, threshold).map_err(|e| error!(map_config_err(e)))?;

        let gov = &mut ctx.accounts.governance;
        gov.authority = ctx.accounts.authority.key();
        gov.pending_authority = Pubkey::default();
        gov.guardians = guardians;
        gov.threshold = threshold;
        gov.timelock_seconds = timelock_seconds;
        gov.paused = false;
        gov.proposal_count = 0;
        gov.bump = ctx.bumps.governance;
        Ok(())
    }

    /// Rotate the guardian set / threshold. Authority-gated.
    pub fn set_guardians(
        ctx: Context<AdminOnly>,
        guardians: Vec<Pubkey>,
        threshold: u8,
    ) -> Result<()> {
        validate_guardians(&guardians, threshold).map_err(|e| error!(map_config_err(e)))?;
        let gov = &mut ctx.accounts.governance;
        gov.guardians = guardians;
        gov.threshold = threshold;
        Ok(())
    }

    /// Emergency pause toggle. Authority-gated.
    pub fn set_paused(ctx: Context<AdminOnly>, paused: bool) -> Result<()> {
        ctx.accounts.governance.paused = paused;
        Ok(())
    }

    /// Begin a two-step authority transfer.
    pub fn transfer_authority(ctx: Context<AdminOnly>, new_authority: Pubkey) -> Result<()> {
        ctx.accounts.governance.pending_authority = new_authority;
        Ok(())
    }

    /// Complete the two-step authority transfer. Only the pending authority may
    /// call this, which prevents a fat-finger transfer to a wrong/dead key from
    /// bricking governance.
    pub fn accept_authority(ctx: Context<AcceptAuthority>) -> Result<()> {
        let gov = &mut ctx.accounts.governance;
        require!(
            gov.pending_authority != Pubkey::default(),
            SecureError::NoPendingAuthority
        );
        require_keys_eq!(
            gov.pending_authority,
            ctx.accounts.new_authority.key(),
            SecureError::NotPendingAuthority
        );
        gov.authority = gov.pending_authority;
        gov.pending_authority = Pubkey::default();
        Ok(())
    }

    /// Propose a timelocked upgrade. Only a guardian or the authority may
    /// propose. The build hash is pinned at proposal time.
    pub fn propose_upgrade(
        ctx: Context<Propose>,
        program_id: Pubkey,
        build_hash: [u8; 32],
    ) -> Result<()> {
        let gov = &mut ctx.accounts.governance;
        require!(!gov.paused, SecureError::Paused);
        require!(build_hash != [0u8; 32], SecureError::EmptyBuildHash);

        let proposer = ctx.accounts.proposer.key();
        require!(
            proposer == gov.authority || gov.is_guardian(&proposer),
            SecureError::NotGuardian
        );

        let now = Clock::get()?.unix_timestamp;
        let eta = now
            .checked_add(gov.timelock_seconds)
            .ok_or(SecureError::Overflow)?;

        let proposal = &mut ctx.accounts.proposal;
        proposal.id = gov.proposal_count;
        proposal.program_id = program_id;
        proposal.build_hash = build_hash;
        proposal.proposer = proposer;
        proposal.eta = eta;
        proposal.approvals = 0;
        proposal.executed = false;
        proposal.cancelled = false;
        proposal.bump = ctx.bumps.proposal;

        gov.proposal_count = gov
            .proposal_count
            .checked_add(1)
            .ok_or(SecureError::Overflow)?;

        emit!(UpgradeProposed {
            id: proposal.id,
            program_id,
            build_hash,
            eta,
        });
        Ok(())
    }

    /// A guardian approves a proposal. The `Approval` PDA is created with
    /// `init`, so a guardian cannot vote twice (double-vote / replay guard).
    pub fn approve_upgrade(ctx: Context<Approve>, proposal_id: u64) -> Result<()> {
        let gov = &ctx.accounts.governance;
        require!(!gov.paused, SecureError::Paused);

        let guardian = ctx.accounts.guardian.key();
        require!(gov.is_guardian(&guardian), SecureError::NotGuardian);

        let proposal = &mut ctx.accounts.proposal;
        require!(!proposal.executed, SecureError::AlreadyExecuted);
        require!(!proposal.cancelled, SecureError::Cancelled);

        let approval = &mut ctx.accounts.approval;
        approval.proposal_id = proposal_id;
        approval.guardian = guardian;
        approval.bump = ctx.bumps.approval;

        proposal.approvals = proposal
            .approvals
            .checked_add(1)
            .ok_or(SecureError::Overflow)?;

        emit!(UpgradeApproved {
            id: proposal_id,
            guardian,
            approvals: proposal.approvals,
        });
        Ok(())
    }

    /// Execute a proposal once the threshold and timelock are both satisfied.
    ///
    /// In production this is the point where the program would CPI into the
    /// BPF upgradeable loader with the pinned buffer. Here it records the
    /// execution and emits an event so the flow is fully testable; the security
    /// gates (threshold + timelock + pause + reinit) are the audited core.
    pub fn execute_upgrade(ctx: Context<Execute>, _proposal_id: u64) -> Result<()> {
        let gov = &ctx.accounts.governance;
        require!(!gov.paused, SecureError::Paused);

        let proposal = &mut ctx.accounts.proposal;
        require!(!proposal.executed, SecureError::AlreadyExecuted);
        require!(!proposal.cancelled, SecureError::Cancelled);
        require!(
            proposal.approvals >= gov.threshold,
            SecureError::ThresholdNotMet
        );

        let now = Clock::get()?.unix_timestamp;
        require!(now >= proposal.eta, SecureError::TimelockActive);

        proposal.executed = true;
        emit!(UpgradeExecuted {
            id: proposal.id,
            program_id: proposal.program_id,
            build_hash: proposal.build_hash,
        });
        Ok(())
    }

    /// Cancel a not-yet-executed proposal. Authority-gated.
    pub fn cancel_proposal(ctx: Context<Cancel>, _proposal_id: u64) -> Result<()> {
        let proposal = &mut ctx.accounts.proposal;
        require!(!proposal.executed, SecureError::AlreadyExecuted);
        proposal.cancelled = true;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = Governance::LEN,
        seeds = [Governance::SEED],
        bump
    )]
    pub governance: Account<'info, Governance>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

/// Authority-only context. `has_one = authority` ties the signer to the stored
/// authority — the canonical access-control check.
#[derive(Accounts)]
pub struct AdminOnly<'info> {
    #[account(
        mut,
        seeds = [Governance::SEED],
        bump = governance.bump,
        has_one = authority @ SecureError::Unauthorized
    )]
    pub governance: Account<'info, Governance>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct AcceptAuthority<'info> {
    #[account(mut, seeds = [Governance::SEED], bump = governance.bump)]
    pub governance: Account<'info, Governance>,
    pub new_authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct Propose<'info> {
    #[account(mut, seeds = [Governance::SEED], bump = governance.bump)]
    pub governance: Account<'info, Governance>,
    #[account(
        init,
        payer = proposer,
        space = Proposal::LEN,
        seeds = [Proposal::SEED, governance.proposal_count.to_le_bytes().as_ref()],
        bump
    )]
    pub proposal: Account<'info, Proposal>,
    #[account(mut)]
    pub proposer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(proposal_id: u64)]
pub struct Approve<'info> {
    #[account(seeds = [Governance::SEED], bump = governance.bump)]
    pub governance: Account<'info, Governance>,
    #[account(
        mut,
        seeds = [Proposal::SEED, proposal_id.to_le_bytes().as_ref()],
        bump = proposal.bump
    )]
    pub proposal: Account<'info, Proposal>,
    #[account(
        init,
        payer = guardian,
        space = Approval::LEN,
        seeds = [Approval::SEED, proposal_id.to_le_bytes().as_ref(), guardian.key().as_ref()],
        bump
    )]
    pub approval: Account<'info, Approval>,
    #[account(mut)]
    pub guardian: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(proposal_id: u64)]
pub struct Execute<'info> {
    #[account(seeds = [Governance::SEED], bump = governance.bump)]
    pub governance: Account<'info, Governance>,
    #[account(
        mut,
        seeds = [Proposal::SEED, proposal_id.to_le_bytes().as_ref()],
        bump = proposal.bump
    )]
    pub proposal: Account<'info, Proposal>,
    pub caller: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(proposal_id: u64)]
pub struct Cancel<'info> {
    #[account(
        seeds = [Governance::SEED],
        bump = governance.bump,
        has_one = authority @ SecureError::Unauthorized
    )]
    pub governance: Account<'info, Governance>,
    #[account(
        mut,
        seeds = [Proposal::SEED, proposal_id.to_le_bytes().as_ref()],
        bump = proposal.bump
    )]
    pub proposal: Account<'info, Proposal>,
    pub authority: Signer<'info>,
}

#[event]
pub struct UpgradeProposed {
    pub id: u64,
    pub program_id: Pubkey,
    pub build_hash: [u8; 32],
    pub eta: i64,
}

#[event]
pub struct UpgradeApproved {
    pub id: u64,
    pub guardian: Pubkey,
    pub approvals: u8,
}

#[event]
pub struct UpgradeExecuted {
    pub id: u64,
    pub program_id: Pubkey,
    pub build_hash: [u8; 32],
}

/// Compile-time guard: keep the account sized for the documented maximum.
const _: () = assert!(MAX_GUARDIANS == 16);
