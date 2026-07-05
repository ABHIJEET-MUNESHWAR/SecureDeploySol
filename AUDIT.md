# SecureDeploySol — Threat Model & Audit Writeup

This document is a self-audit of the `securedeploy-core` Anchor program against
the common Solana / SVM attack classes. Each class lists the **attack**, the
**defense** as implemented, and a **code reference**.

Program id: `9x3Dcnv4yXcGL6PZaPyRLbjnMfRJ4v1Yqkf5fbX8ToYA`

The program governs privileged program upgrades: a **guardian multisig** must
reach a **threshold** of distinct approvals, and a **timelock** must elapse,
before an upgrade proposal (which pins a **verifiable build hash**) can execute.

## Attack-class matrix

| Code | Class | Defense | Reference |
|---|---|---|---|
| SVM-01 | Missing signer check | Every privileged handler takes a `Signer<'info>`; `accept_authority` requires the *pending* authority's signature. | [`lib.rs` account structs](anchor/programs/securedeploy-core/src/lib.rs) |
| SVM-02 | Missing owner / account-substitution check | Accounts are typed (`Account<'info, Governance>`), so Anchor verifies the owning program and the 8-byte discriminator on deserialize. | account structs |
| SVM-03 | Account confusion / wrong PDA | All stateful accounts are PDAs with fixed seeds + stored canonical `bump`; the `Approval` PDA binds `(proposal_id, guardian)`. | `state.rs`, `Approve` |
| SVM-04 | Arbitrary CPI injection | No user-supplied program is invoked; `system_program` is the typed `Program<'info, System>`. The (documented) upgrade CPI would target the fixed BPF loader only. | `Initialize`, `Propose` |
| SVM-05 | PDA seed collision | Seeds are domain-separated by a distinct static prefix per account type (`governance` / `proposal` / `approval`). | `state.rs` `SEED` consts |
| SVM-06 | Integer overflow | `checked_add` on `proposal_count` and `approvals`; `overflow-checks = true` in the release profile. | `propose_upgrade`, `approve_upgrade` |
| SVM-07 | Reinitialization | `Governance` and each `Approval` use `init` (not `init_if_needed`), so re-init fails. A guardian therefore cannot vote twice. | `Initialize`, `Approve` |
| SVM-08 | Type cosplay | Distinct `#[account]` types have distinct discriminators; a `Proposal` cannot be passed where a `Governance` is expected. | `state.rs` |
| SVM-09 | Upgrade-authority abuse | No single key can upgrade: threshold multisig **plus** a timelock **plus** an emergency pause gate every execution; authority transfer is two-step. | `execute_upgrade` |
| SVM-10 | Unbounded account / rent-exhaustion DoS | The guardian vector is bounded by `MAX_GUARDIANS = 16` and the account is sized for the maximum, so no attacker-controlled reallocation is possible. | `state.rs` `LEN`, `validate_guardians` |

## Defense-in-depth flow

An upgrade cannot execute unless **all** of the following hold:

1. `!governance.paused` — emergency stop is off.
2. `approvals >= threshold` — enough distinct guardians approved (each approval
   is a unique `Approval` PDA, so double-voting is impossible).
3. `now >= proposal.eta` — the timelock window has elapsed, giving the community
   time to react to a malicious or buggy proposal.
4. The proposal is neither `executed` nor `cancelled`.

The pinned `build_hash` lets any observer verify (off-chain, via
`Dockerfile.anchor` + `sha256sum`) that the artifact about to be deployed is the
exact one that was reviewed.

## Validated invariants (tests)

- Guardian-set validation rejects empty, oversized, duplicate, and
  out-of-range-threshold configurations
  ([`state.rs` tests](anchor/programs/securedeploy-core/src/state.rs),
  [`program_logic.rs`](anchor/programs/securedeploy-core/tests/program_logic.rs)).
- Off-chain property tests assert the execution gate is satisfied **iff**
  `approvals >= threshold && now >= eta`
  ([`governance_props.rs`](crates/securedeploy-types/tests/governance_props.rs)).
- Engine tests cover the full propose → approve → execute path plus every reject
  branch: double-vote, non-guardian, below-threshold, active timelock, pause,
  and cancel
  ([`engine_flow.rs`](crates/securedeploy-core/tests/engine_flow.rs)).

## Residual risks / out of scope

- **Guardian key management** is out of scope; the program assumes guardian
  private keys are held securely (ideally on independent HSMs).
- The **execute step records and emits** rather than performing the live
  `bpf_loader_upgradeable` CPI, so the audited surface is the governance gate.
  Wiring the loader CPI (with the buffer account and the fixed loader program id)
  is the documented production step.
- A **TypeScript `anchor test`** exercising the full BPF transaction path is on
  the roadmap; current coverage is host-side logic + off-chain integration.
