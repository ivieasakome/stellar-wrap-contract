//! Privileged administration: ownership, pausing, upgrades and contract-wide
//! configuration.
//!
//! Every function here is admin-gated. [`read_admin`] panics with
//! [`ContractError::NotInitialized`] when no admin is stored, so an
//! uninitialized contract has no privileged surface rather than an open one.
//!
//! # Ownership
//!
//! [`update_admin`] replaces the admin in one transaction — fast, and
//! unrecoverable if the address is wrong. Prefer the two-step handover:
//! [`propose_admin`] then [`accept_admin`], where the incoming admin must
//! authorize the acceptance and so proves control before gaining power.
//! [`cancel_proposed_admin`] withdraws a pending proposal; only one may be
//! outstanding.
//!
//! # Role-based access control
//!
//! Privileged entrypoints are gated by the narrowest [`Role`] they need rather
//! than by the single admin key. [`grant_role`] and [`revoke_role`] are
//! admin-only; [`renounce_role`] lets a holder drop its own role, except that
//! the last `Admin` cannot renounce itself (which would brick the contract).
//! [`has_role`] is the read-only membership check. The role-to-entrypoint
//! matrix is documented in `docs/authority-model.md`.
//!
//! # Relationship to the timelock
//!
//! Once [`crate::timelock`] is enabled, [`update_admin`], [`upgrade`],
//! [`propose_admin`] and [`accept_admin`] reject direct calls via
//! [`crate::timelock::require_direct_call_allowed`]; the admin must schedule
//! the equivalent [`crate::storage_types::TimelockAction`], wait out the delay
//! and execute. [`accept_admin`] is blocked too, otherwise a proposal made
//! before the timelock was enabled could be cashed in afterwards and skip the
//! delay.
//!
//! Pausing, fee configuration, key rotation, metadata and migrations stay
//! directly callable by design — they are incident response or reversible
//! configuration.
//!
//! # Pausing, upgrades, migrations
//!
//! [`set_pause`] is the incident switch and [`require_not_paused`] the guard
//! other modules call. Requesting the state already in effect is a silent
//! no-op that emits nothing, so a double-pause is not reported twice.
//!
//! [`apply_upgrade`] is shared by [`upgrade`] and the timelocked path so both
//! bump `ContractVersion` and emit the same audit event. [`migrate`] tracks
//! storage schema versions separately and only moves forward, so a replayed
//! migration cannot corrupt storage.

use soroban_sdk::{contracttype, panic_with_error, symbol_short, Address, BytesN, Env};

use crate::{
    ttl::TTL_TEMP, ContractError, DataKey, TransferFeeConfig, WrapRecord,
};

/// Minimum duration for an admin proposal, in seconds (1 hour).
pub(crate) const MIN_PROPOSAL_DURATION: u64 = 60 * 60;
/// Maximum duration for an admin proposal, in seconds (30 days).
pub(crate) const MAX_PROPOSAL_DURATION: u64 = 30 * 24 * 60 * 60;

/// A privileged capability in the registry.
///
/// Each privileged entrypoint requires exactly one role; see
/// `docs/authority-model.md` for the role-to-entrypoint matrix.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// Full control: grants and revokes every other role.
    Admin,
    /// May mint new wrapped assets.
    Minter,
    /// May revoke wrapped assets.
    Revoker,
    /// May pause and unpause the contract.
    Pauser,
    /// May upgrade the contract WASM.
    Upgrader,
    /// May act on behalf of the bridge (relayed operations).
    Bridge,
}

/// Reads the stored admin or panics with `NotInitialized`.
pub(crate) fn read_admin(e: &Env) -> Address {
    e.storage()
        .instance()
        .get(&DataKey::Admin)
        .unwrap_or_else(|| panic_with_error!(e, ContractError::NotInitialized))
}

/// Returns `true` when `account` currently holds `role`.
///
/// The `Admin` role is implicitly held by the stored admin address, so the
/// contract is never left without an admin even before any explicit grant.
pub(crate) fn has_role(e: &Env, role: Role, account: &Address) -> bool {
    if role == Role::Admin && *account == read_admin(e) {
        return true;
    }
    e.storage()
        .persistent()
        .get(&DataKey::RoleMember(role, account.clone()))
        .unwrap_or(false)
}

/// Requires that `account` holds `role`, authorizing the call.
///
/// Panics with [`ContractError::Unauthorized`] when the role is missing.
pub(crate) fn require_role(e: &Env, role: Role, account: &Address) {
    if !has_role(e, role, account) {
        panic_with_error!(e, ContractError::Unauthorized);
    }
    account.require_auth();
}

/// Admin-only: grant `role` to `account`.
#[allow(deprecated)] // TODO(#718): migrate to #[contractevent]
pub(crate) fn grant_role(e: Env, role: Role, account: Address) {
    let admin = read_admin(&e);
    admin.require_auth();
    e.storage()
        .persistent()
        .set(&DataKey::RoleMember(role, account.clone()), &true);
    e.events().publish(
        (symbol_short!("role"), symbol_short!("granted")),
        (role, account),
    );
}

/// Admin-only: revoke `role` from `account`.
#[allow(deprecated)] // TODO(#718): migrate to #[contractevent]
pub(crate) fn revoke_role(e: Env, role: Role, account: Address) {
    let admin = read_admin(&e);
    admin.require_auth();
    e.storage()
        .persistent()
        .remove(&DataKey::RoleMember(role, account.clone()));
    e.events().publish(
        (symbol_short!("role"), symbol_short!("revoked")),
        (role, account),
    );
}

/// Lets `account` drop its own `role`.
///
/// The last `Admin` cannot renounce itself: doing so would leave the contract
/// with no one able to grant roles or upgrade it. Panics with
/// [`ContractError::Unauthorized`] in that case.
#[allow(deprecated)] // TODO(#718): migrate to #[contractevent]
pub(crate) fn renounce_role(e: Env, role: Role, account: Address) {
    account.require_auth();
    if role == Role::Admin && account == read_admin(&e) {
        // The stored admin is the last admin; renouncing would brick the
        // contract. Refuse rather than silently no-op.
        panic_with_error!(e, ContractError::Unauthorized);
    }
    e.storage()
        .persistent()
        .remove(&DataKey::RoleMember(role, account.clone()));
    e.events().publish(
        (symbol_short!("role"), symbol_short!("revoked")),
        (role, account),
    );
}

/// Initializes the contract with the controlling admin address and the
/// Ed25519 public key used to verify mint signatures.
///
/// # Panics
/// - [`ContractError::AlreadyInitialized`] if the contract was already initialized.
/// - [`ContractError::InvalidAdminPubKey`] if `admin_pubkey` is the all-zero
///   key. An all-zero Ed25519 public key has no known corresponding private
///   key, so accepting it would silently brick every future `mint_wrap` call
///   (no valid signature could ever be produced) while leaving the contract in
///   an "initialized" state. Rejecting it at initialization time prevents this
///   misconfiguration rather than discovering it after deployment.
#[allow(deprecated)] // TODO(#718): migrate to #[contractevent]
pub(crate) fn initialize(e: Env, admin: Address, admin_pubkey: BytesN<32>) {
    if e.storage().instance().has(&DataKey::Admin) {
        panic_with_error!(e, ContractError::AlreadyInitialized);
    }
    if admin_pubkey == BytesN::from_array(&e, &[0u8; 32]) {
        panic_with_error!(e, ContractError::InvalidAdminPubKey);
    }
    e.storage().instance().set(&DataKey::Admin, &admin);
    e.storage()
        .instance()
        .set(&DataKey::AdminPubKey, &admin_pubkey);
    // Store the initial storage schema version (v1).
    e.storage().instance().set(&DataKey::SchemaVersion, &1u32);
    crate::events::publish_event(&e, crate::events::Event::AdminInit(admin));
}

/// Immediate admin replacement.
///
/// Rejected once the timelock controller is enabled — the admin must then use
/// `schedule(TimelockAction::SetAdmin(..))` followed by `execute`.
#[allow(deprecated)] // TODO(#718): migrate to #[contractevent]
pub(crate) fn update_admin(e: Env, new_admin: Address) {
    crate::timelock::require_direct_call_allowed(&e);
    let current_admin = read_admin(&e);
    current_admin.require_auth();
    e.storage().instance().set(&DataKey::Admin, &new_admin);
    e.storage().instance().remove(&DataKey::PendingAdmin);

    e.events().publish(
        (
            symbol_short!("v1"),
            symbol_short!("admin"),
            symbol_short!("updated"),
        ),
        (current_admin, new_admin),
    );
}

/// Pause or unpause the contract.
///
/// Pauses (`paused = true`) or resumes (`paused = false`) the contract and
/// emits a direction-specific event carrying the acting admin.
///
/// A redundant call that requests the state already in effect is a silent
/// no-op: it does **not** emit an event, so monitoring built on these events
/// only sees signals that correspond to an actual state change (a double-pause
/// by two incident responders must not be reported as a second pause).
///
/// Event topics are direction-distinguishable so subscribers can filter by
/// direction instead of decoding a boolean payload:
/// - pause:   `("pause", "paused")`, data = acting admin
/// - unpause: `("pause", "unpaused")`, data = acting admin
#[allow(deprecated)] // TODO(#718): migrate to #[contractevent]
pub(crate) fn set_pause(e: Env, paused: bool) {
    let admin = read_admin(&e);
    admin.require_auth();

    // Return early when the requested state already matches the current state.
    // This makes a redundant pause/unpause a silent no-op instead of emitting
    // an event that does not correspond to a state change.
    if is_paused(&e) == paused {
        return;
    }

    e.storage().instance().set(&DataKey::Paused, &paused);
    crate::events::publish_event(&e, crate::events::Event::AdminPause(paused));
}

/// Admin-only: configure the token-denominated fee charged by `transfer_wrap`.
///
/// An amount of zero enables fee-free transfers without removing the configured
/// token and recipient.
#[allow(deprecated)] // TODO(#718): migrate to #[contractevent]
pub(crate) fn set_transfer_fee(e: Env, token: Address, recipient: Address, amount: i128) {
    read_admin(&e).require_auth();
    if amount < 0 || token == recipient {
        panic_with_error!(e, ContractError::InvalidFeeParams);
    }
    e.storage().instance().set(
        &DataKey::TransferFee,
        &TransferFeeConfig {
            amount,
            recipient: recipient.clone(),
            token: token.clone(),
        },
    );
    e.events()
        .publish((symbol_short!("fee"),), (token, recipient, amount));
}

/// Admin-only: clear the configured transfer fee, returning the contract to an unconfigured state.
#[allow(deprecated)] // TODO(#718): migrate to #[contractevent]
pub(crate) fn clear_transfer_fee(e: Env) {
    read_admin(&e).require_auth();
    e.storage().instance().remove(&DataKey::TransferFee);
    e.events().publish((symbol_short!("fee_clr"),), ());
}

pub(crate) fn is_paused(e: &Env) -> bool {
    e.storage()
        .instance()
        .get(&DataKey::Paused)
        .unwrap_or(false)
}

pub(crate) fn require_not_paused(e: &Env) {
    if is_paused(e) {
        panic_with_error!(e, ContractError::Paused);
    }
}

/// Marks a storage migration as applied. A version can only be applied once and
/// versions must move forward, so an upgrade shipping a migration cannot corrupt
/// storage by replaying it.
pub(crate) fn migrate(e: Env, version: u32) {
    read_admin(&e).require_auth();

    let applied = migration_version(&e);
    if version <= applied {
        panic_with_error!(e, ContractError::MigrationAlreadyApplied);
    }

    e.storage()
        .instance()
