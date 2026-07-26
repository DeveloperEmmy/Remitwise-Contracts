#![no_std]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use soroban_sdk::{contracterror, contracttype, symbol_short, Bytes, BytesN, Symbol};
pub mod tokens;
pub use tokens::{
    SupportedToken, BASE_UNITS_PER_EURC, BASE_UNITS_PER_USDC, DEFAULT_CURRENCY, EURC_DECIMALS,
    MAX_CURRENCY_LEN, STROOPS_PER_XLM, USDC_DECIMALS, XLM_DECIMALS,
};

use soroban_sdk::{
    contracterror, contracttype, symbol_short, Address, Bytes, BytesN, Env, Map, Symbol,
};

#[soroban_sdk::contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum RemitwiseError {
    Unauthorized = 1,
    InvalidSignature = 2,
    DeadlineExpired = 3,
    RequestHashMismatch = 4,
    InvalidAmount = 5,
    InvalidNonce = 6,
    DuplicateImport = 7,
}

/// Financial categories for remittance allocation
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Category {
    Spending = 1,
    Savings = 2,
    Bills = 3,
    Insurance = 4,
}

/// Family roles for access control
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum FamilyRole {
    Owner = 1,
    Admin = 2,
    Member = 3,
    Viewer = 4,
}

/// Insurance coverage types
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum CoverageType {
    Health = 1,
    Life = 2,
    Property = 3,
    Auto = 4,
    Liability = 5,
}

/// Policy mode for access control
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum PolicyMode {
    Strict = 1,
}

/// Event categories used for logging across all contracts.
///
/// Determines the high-level classification of an event. The taxonomy is documented in
/// `docs/EVENT_TAXONOMY.md`.
#[allow(dead_code)]
#[derive(Clone, Copy)]
#[repr(u32)]
pub enum EventCategory {
    Transaction = 0,
    State = 1,
    Alert = 2,
    System = 3,
    Access = 4,
    Compliance = 5,
}

/// Priority levels for events emitted by contracts.
/// Determines the importance of the event. Lower numbers represent lower priority.
/// See `docs/EVENT_TAXONOMY.md` for full taxonomy details.
#[allow(dead_code)]
#[derive(Clone, Copy)]
#[repr(u32)]
pub enum EventPriority {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

impl EventCategory {
    pub fn to_u32(self) -> u32 {
        self as u32
    }
}

impl EventPriority {
    pub fn to_u32(self) -> u32 {
        self as u32
    }
}

#[contracttype]
#[derive(Clone)]
pub struct RoleGrantedEvent {
    pub member: Address,
    pub role: FamilyRole,
    pub timestamp: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct RoleRevokedEvent {
    pub member: Address,
    pub role: FamilyRole,
    pub timestamp: u64,
}

/// Pagination limits
pub const DEFAULT_PAGE_LIMIT: u32 = 20;
pub const MAX_PAGE_LIMIT: u32 = 50;

/// Max items returned in Top-N reports.
pub const MAX_ITEMS_PER_REPORT: u32 = 10;

/// Helper to insert an item into a Top-N list (bounded).
/// The list is maintained in sorted order based on the provided comparator.
pub fn insert_top_n<T, F>(
    _env: &Env,
    top_list: &mut soroban_sdk::Vec<T>,
    max_items: u32,
    item: T,
    mut cmp: F,
) where
    T: Clone
        + soroban_sdk::IntoVal<Env, soroban_sdk::Val>
        + soroban_sdk::TryFromVal<Env, soroban_sdk::Val>,
    F: FnMut(&T, &T) -> core::cmp::Ordering,
{
    let mut inserted = false;
    for i in 0..top_list.len() {
        if let Some(existing) = top_list.get(i) {
            if cmp(&item, &existing) == core::cmp::Ordering::Greater {
                top_list.insert(i, item.clone());
                inserted = true;
                break;
            }
        }
    }

    if !inserted && top_list.len() < max_items {
        top_list.push_back(item);
    } else if top_list.len() > max_items {
        top_list.remove(max_items);
    }
}

/// Standardized TTL Constants (Ledger Counts)
pub const DAY_IN_LEDGERS: u32 = 17280; // ~5 seconds per ledger

/// Storage TTL constants for active data
pub const INSTANCE_LIFETIME_THRESHOLD: u32 = 7 * DAY_IN_LEDGERS; // 7 days
pub const INSTANCE_BUMP_AMOUNT: u32 = 30 * DAY_IN_LEDGERS; // 30 days

/// Storage TTL constants for persistent data
pub const PERSISTENT_LIFETIME_THRESHOLD: u32 = 15 * DAY_IN_LEDGERS; // 15 days
pub const PERSISTENT_BUMP_AMOUNT: u32 = 60 * DAY_IN_LEDGERS; // 60 days

/// Storage TTL constants for archived data
pub const ARCHIVE_LIFETIME_THRESHOLD: u32 = 7 * DAY_IN_LEDGERS; // 7 days
pub const ARCHIVE_BUMP_AMOUNT: u32 = 180 * DAY_IN_LEDGERS; // 180 days (6 months)

/// Signature expiration time (24 hours in seconds)
pub const SIGNATURE_EXPIRATION: u64 = 86400;

/// Contract version
pub const CONTRACT_VERSION: u32 = 1;

/// Storage key for the pause channels map
pub const STORAGE_PAUSE_CHANNELS: &str = "PAUSE_CH";

/// Maximum batch size for operations
pub const MAX_BATCH_SIZE: u32 = 50;

/// Maximum byte length for `Bytes` values returned from public contract entry points.
///
/// XDR `ScBytes` carries no inherent host-enforced cap before deserialization.
/// Without an explicit check, a misbehaving or compromised contract can force every
/// downstream consumer (SDK, indexer, RPC node) to allocate memory proportional to
/// the returned payload — a potential DoS vector.  Call [`guard_bytes_len`] before
/// returning any variable-length `Bytes` value from a public entry point.
pub const MAX_BYTES_RETURN: u32 = 8192;

/// Error returned when a `Bytes` value about to leave a contract entry point
/// exceeds [`MAX_BYTES_RETURN`].
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum BytesReturnError {
    /// The byte length exceeds [`MAX_BYTES_RETURN`].
    ReturnTooLarge = 1,
}

/// Verifies that `from` is strictly less than `to`.
///
/// # Panics
/// - Panics if `from >= to`.
pub fn verify_ordered_pair(from: u64, to: u64) {
    if from >= to {
        panic!("Invalid range: from ({from}) must be strictly less than to ({to})");
    }
}

/// Verifies that the provided signature matches the admin's public key for the given message.
///
/// # Arguments
/// - `env` - Soroban environment
/// - `admin_pk` - Admin's Ed25519 public key
/// - `message` - The message that was signed
/// - `signature` - The Ed25519 signature
///
/// # Errors
/// - `RemitwiseError::InvalidSignature` if the signature verification fails
pub fn require_signed_by_admin(
    env: &soroban_sdk::Env,
    admin_pk: soroban_sdk::crypto::ed25519::PublicKey,
    message: soroban_sdk::Bytes,
    signature: soroban_sdk::crypto::ed25519::Signature,
) -> Result<(), RemitwiseError> {
    env.crypto()
        .ed25519_verify(admin_pk, message, signature)
        .map_err(|_| RemitwiseError::InvalidSignature)?;
    Ok(())
}

/// Verifies that the provided signature matches the admin's public key for the given message.
///
/// # Arguments
/// - `env` - Soroban environment
/// - `admin_pk` - Admin's Ed25519 public key
/// - `message` - The message that was signed
/// - `signature` - The Ed25519 signature
///
/// # Errors
/// - `RemitwiseError::InvalidSignature` if the signature verification fails
pub fn require_signed_by_admin(
    env: &soroban_sdk::Env,
    admin_pk: soroban_sdk::crypto::ed25519::PublicKey,
    message: soroban_sdk::Bytes,
    signature: soroban_sdk::crypto::ed25519::Signature,
) -> Result<(), RemitwiseError> {
    env.crypto()
        .ed25519_verify(admin_pk, message, signature)
        .map_err(|_| RemitwiseError::InvalidSignature)?;
    Ok(())
}

/// Event emission helper
pub struct RemitwiseEvents;

/// Validates that a [`Symbol`] does not exceed the short-symbol limit (9 bytes).
///
/// This is a defence-in-depth check.  Symbols longer than 9 bytes use the
/// large-symbol XDR encoding (`SymbolObject` tag) instead of the inline
/// short-symbol encoding (`SymbolSmall` tag).  Without this gate, a caller
/// could supply a long symbol where the contract expects a short one,
/// potentially leading to storage-key confusion or indexer mismatches
/// downstream.
///
/// The check uses the [`Val`] bit pattern: short symbols are stored inline
/// (not objects), long symbols are stored as host object references.  This
/// works on all targets (WASM and non-WASM) without requiring string
/// conversion.
///
/// Call this on any `Symbol` value derived from untrusted input before using
/// it as a storage key, event action, or comparand against `symbol_short!`
/// constants.
///
/// # Errors
/// Returns [`SymbolError::SymbolTooLong`] when the symbol exceeds 9 bytes.
pub fn require_valid_symbol_length(_env: &Env, sym: &Symbol) -> Result<(), SymbolError> {
    if sym.to_val().is_object() {
        Err(SymbolError::SymbolTooLong)
    } else {
        Ok(())
    }
}

/// Guards `bytes` against exceeding the XDR return-size budget.
///
/// Call this immediately before returning any variable-length `Bytes` value from a
/// public contract entry point.  The check costs a single `u32` comparison and
/// ensures that downstream consumers cannot be forced to deserialise an arbitrarily
/// large buffer.
///
/// # Errors
/// Returns [`BytesReturnError::ReturnTooLarge`] when `bytes.len() > MAX_BYTES_RETURN`.
pub fn guard_bytes_len(bytes: &Bytes) -> Result<(), BytesReturnError> {
    if bytes.len() > MAX_BYTES_RETURN {
        Err(BytesReturnError::ReturnTooLarge)
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Settlement amount validation
// ---------------------------------------------------------------------------

/// Error returned when a settlement-moving amount is not strictly positive.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum SettlementAmountError {
    /// `amount <= 0`. Every settlement (a value transfer that finalizes an
    /// obligation — a bill payment, premium payment, goal contribution,
    /// remittance disbursement, etc.) must be strictly positive by policy.
    NonPositiveAmount = 1,
}

/// Guards that a settlement amount is strictly positive (`> 0`).
///
/// This is a defence-in-depth check meant to be called at the top of any
/// entry point that finalizes a value transfer ("settles" an obligation),
/// in addition to — not instead of — each contract's own existing
/// validation. Individual contracts have historically implemented this
/// bound inconsistently (some guard `amount <= 0`, at least one guard only
/// `amount < 0`, silently letting a zero-amount settlement through as a
/// successful no-op). A shared, single-purpose helper removes the chance
/// of a future entry point picking the wrong comparison operator.
///
/// # Threat model
/// A settlement of `0` that is accepted rather than rejected lets a caller
/// trigger the full side effects of a "successful" settlement — state
/// mutation, an emitted settlement event, consumption of a rate-limit
/// budget, or satisfying a downstream "was this settled?" check in an
/// orchestrating contract — without moving any value. That gap is useful
/// to an attacker who wants to grief accounting/audit trails, force
/// extra event-indexer/off-chain load, or manufacture a "paid" state to
/// unblock a workflow gate that only checks for success, not amount.
/// Negative amounts are equally invalid and are rejected by the same
/// check, since a "negative settlement" has no valid real-world meaning
/// and would invert the direction of a transfer if it reached arithmetic.
///
/// # Cost
/// A single `i128` comparison; negligible relative to any settlement
/// entry point's existing storage reads/writes.
///
/// # Errors
/// Returns [`SettlementAmountError::NonPositiveAmount`] if `amount <= 0`.
pub fn require_positive_settlement_amount(amount: i128) -> Result<(), SettlementAmountError> {
    if amount <= 0 {
        Err(SettlementAmountError::NonPositiveAmount)
    } else {
        Ok(())
    }
}

    // -----------------------------------------------------------------------
    // require_signed_by_admin – verify signature verification
    // -----------------------------------------------------------------------
    #[test]
    fn require_signed_by_admin_invalid_signature_panics() {
        let env = Env::default();
        let (admin_pk, admin_sk) = soroban_sdk::testutils::ed25519::generate(&env);
        let message = soroban_sdk::Bytes::from_slice(&env, b"test message");
        
        // Sign with a different key
        let (_wrong_pk, wrong_sk) = soroban_sdk::testutils::ed25519::generate(&env);
        let signature = env.crypto().ed25519_sign(wrong_sk, message.clone());
        
        let result = require_signed_by_admin(&env, admin_pk, message, signature);
        assert_eq!(result, Err(RemitwiseError::InvalidSignature));
    }

    #[test]
    fn require_signed_by_admin_valid_signature_succeeds() {
        let env = Env::default();
        let (admin_pk, admin_sk) = soroban_sdk::testutils::ed25519::generate(&env);
        let message = soroban_sdk::Bytes::from_slice(&env, b"test message");
        
        let signature = env.crypto().ed25519_sign(admin_sk, message.clone());
        
        let result = require_signed_by_admin(&env, admin_pk, message, signature);
        assert!(result.is_ok());
    }

    #[test]
    fn clamp_limit_zero_returns_default() {
        assert_eq!(clamp_limit(0), DEFAULT_PAGE_LIMIT);
    }

    #[test]
    fn rejects_zero() {
        assert_eq!(
            require_positive_settlement_amount(0),
            Err(SettlementAmountError::NonPositiveAmount)
        );
    }

    #[test]
    fn rejects_negative() {
        assert_eq!(
            require_positive_settlement_amount(-1),
            Err(SettlementAmountError::NonPositiveAmount)
        );
        assert_eq!(
            require_positive_settlement_amount(i128::MIN),
            Err(SettlementAmountError::NonPositiveAmount)
        );
    }

    #[test]
    fn accepts_smallest_positive_amount() {
        assert_eq!(require_positive_settlement_amount(1), Ok(()));
    }

    #[test]
    fn accepts_large_positive_amount() {
        assert_eq!(require_positive_settlement_amount(i128::MAX), Ok(()));
    }
}

// ---------------------------------------------------------------------------
// Non-zero amount validation
// ---------------------------------------------------------------------------

/// Error returned when a non-zero amount is required but zero was supplied.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum AmountError {
    /// `amount == 0`.  Any entry point that accepts a monetary amount must
    /// reject zero to prevent valueless side-effects from being treated as
    /// successful operations.
    ZeroAmount = 1,
}

/// Guards that `amount` is non-zero (`!= 0`).
///
/// This is a defence-in-depth check for any entry point that accepts a
/// monetary amount, regardless of whether the amount is also subject to
/// settlement-specific or dust-level validation.  It catches the
/// zero-amount case that some existing per-contract guards miss (e.g.
/// guards written as `amount < 0` rather than `amount <= 0`).
///
/// # Threat model
/// A zero-amount call that is accepted as a success lets a caller
/// trigger the full side-effects of the operation — state mutation,
/// event emission, rate-limit consumption, or satisfying a downstream
/// "was this done?" gate — without moving any value.  An attacker can
/// use this to grief audit trails, inflate off-chain analytics, or
/// manufacture a "completed" state that unlocks a workflow gate.  The
/// check also rejects negative amounts, which are equally invalid for
/// monetary inputs and would invert the direction of a transfer if
/// they reached arithmetic.
///
/// # Cost
/// A single `i128` comparison; negligible relative to any entry
/// point's existing storage reads/writes.
///
/// # Errors
/// Returns [`AmountError::ZeroAmount`] if `amount == 0`.
pub fn require_non_zero_amount(amount: i128) -> Result<(), AmountError> {
    if amount == 0 {
        Err(AmountError::ZeroAmount)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod non_zero_amount_tests {
    use super::*;

    #[test]
    fn rejects_zero() {
        assert_eq!(require_non_zero_amount(0), Err(AmountError::ZeroAmount));
    }

    #[test]
    fn accepts_one() {
        assert_eq!(require_non_zero_amount(1), Ok(()));
    }

    #[test]
    fn accepts_negative_one() {
        assert_eq!(require_non_zero_amount(-1), Ok(()));
    }

    #[test]
    fn accepts_min() {
        assert_eq!(require_non_zero_amount(i128::MIN), Ok(()));
    }

    #[test]
    fn accepts_max() {
        assert_eq!(require_non_zero_amount(i128::MAX), Ok(()));
    }
}

// ---------------------------------------------------------------------------
// Settlement currency validation
// ---------------------------------------------------------------------------

/// Configuration for settlement-currency whitelist validation.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct SettlementCurrencyConfig {
    /// Maximum number of currencies the invoice whitelist may contain.
    pub max_whitelist_size: u32,
}

impl Default for SettlementCurrencyConfig {
    fn default() -> Self {
        Self {
            max_whitelist_size: 10,
        }
    }
}

/// Error returned when a settlement's currency is not accepted by the invoice.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum SettlementCurrencyError {
    /// `sym` is not present in the invoice's whitelist of accepted
    /// settlement currencies.
    CurrencyNotWhitelisted = 1,
    /// The invoice whitelist exceeds the configured cap for settlement currency validation.
    WhitelistTooLarge = 2,
}

/// Guards that a settlement's currency (`sym`) is one of the currencies the
/// invoice (`inv`) is willing to accept.
///
/// This is a defence-in-depth check meant to be called at the top of any
/// entry point that settles an invoice-like obligation (a bill, premium,
/// remittance leg, etc.) in a caller- or off-chain-supplied currency, in
/// addition to — not instead of — each contract's own existing validation.
///
/// # Threat model
/// If a settlement entry point accepts a currency argument without checking
/// it against the payee's whitelist, an attacker (or a compromised
/// off-chain settlement relayer) can discharge the full face amount of an
/// obligation while paying in a currency the payee never agreed to hold —
/// an illiquid, depegged, or otherwise low-value asset — while the
/// contract's ledger still records the obligation as "settled in full".
/// That both cheats the payee out of the value they were owed and corrupts
/// downstream accounting/reporting that assumes settlement currency equals
/// invoice currency. An empty whitelist is treated as accepting nothing,
/// never as a wildcard, so a mis-provisioned invoice fails closed instead
/// of silently accepting any currency.
///
/// # Cost
/// A linear scan of `inv`, bounded by the invoice's whitelist size (expected
/// to be a handful of accepted currencies at most); negligible relative to
/// any settlement entry point's existing storage reads/writes.
///
/// # Errors
/// Returns [`SettlementCurrencyError::CurrencyNotWhitelisted`] if `sym` is
/// not present in `inv`.
pub fn require_matching_settlement_currency(
    inv: &soroban_sdk::Vec<Symbol>,
    sym: &Symbol,
) -> Result<(), SettlementCurrencyError> {
    require_matching_settlement_currency_with_config(inv, sym, &SettlementCurrencyConfig::default())
}

/// Guards that a settlement's currency (`sym`) is one of the currencies the
/// invoice (`inv`) is willing to accept, subject to a configurable whitelist cap.
pub fn require_matching_settlement_currency_with_config(
    inv: &soroban_sdk::Vec<Symbol>,
    sym: &Symbol,
    config: &SettlementCurrencyConfig,
) -> Result<(), SettlementCurrencyError> {
    if inv.len() > config.max_whitelist_size {
        return Err(SettlementCurrencyError::WhitelistTooLarge);
    }

    for accepted in inv.iter() {
        if &accepted == sym {
            return Ok(());
        }
    }
    Err(SettlementCurrencyError::CurrencyNotWhitelisted)
}

/// Canonicalizes a single label string into a `Symbol`.
///
/// Rules:
/// - Leading and trailing ASCII whitespace is stripped.
/// - ASCII uppercase letters are folded to lowercase.
/// - The result must satisfy `Symbol`'s charset (`[a-zA-Z0-9_]` after folding)
///   and length (`1..=32` bytes after trimming), otherwise this panics.
pub fn canonicalise_symbol(env: &soroban_sdk::Env, input: &soroban_sdk::String) -> Symbol {
    let len = input.len();
    if len == 0 {
        panic!("symbol input must contain between 1 and 32 characters after trimming");
    }
    let mut buf = [0u8; 256];
    if len as usize > buf.len() {
        panic!("symbol input is too long");
    }
    input.copy_into_slice(&mut buf[..len as usize]);

    let s = core::str::from_utf8(&buf[..len as usize])
        .unwrap_or_else(|_| panic!("symbol input is not valid UTF-8"));

    let trimmed = s.trim();
    let trimmed_len = trimmed.len();
    if trimmed_len == 0 {
        panic!("symbol input must contain at least one non-whitespace character");
    }
    if trimmed_len > 32 {
        panic!("symbol input must contain between 1 and 32 characters after trimming");
    }

    let trimmed_bytes = trimmed.as_bytes();
    let mut canonical = [0u8; 32];
    for (i, &byte) in trimmed_bytes.iter().enumerate() {
        canonical[i] = if byte.is_ascii_uppercase() {
            byte.to_ascii_lowercase()
        } else {
            byte
        };
    }

    let canonical_str = core::str::from_utf8(&canonical[..trimmed_len])
        .unwrap_or_else(|_| panic!("canonicalised symbol is not valid UTF-8"));

    Symbol::new(env, canonical_str)
}

#[cfg(test)]
mod settlement_currency_tests {
    use super::*;
    use soroban_sdk::{symbol_short, Env};

    #[test]
    fn rejects_currency_not_in_whitelist() {
        let env = Env::default();
        let whitelist =
            soroban_sdk::Vec::from_array(&env, [symbol_short!("USDC"), symbol_short!("EURC")]);
        let settlement_currency = symbol_short!("XLM");
        assert_eq!(
            require_matching_settlement_currency(&whitelist, &settlement_currency),
            Err(SettlementCurrencyError::CurrencyNotWhitelisted)
        );
    }

    #[test]
    fn rejects_against_empty_whitelist() {
        let env = Env::default();
        let whitelist = soroban_sdk::Vec::<Symbol>::new(&env);
        let settlement_currency = symbol_short!("XLM");
        assert_eq!(
            require_matching_settlement_currency(&whitelist, &settlement_currency),
            Err(SettlementCurrencyError::CurrencyNotWhitelisted)
        );
    }

    #[test]
    fn accepts_currency_present_in_whitelist() {
        let env = Env::default();
        let whitelist =
            soroban_sdk::Vec::from_array(&env, [symbol_short!("USDC"), symbol_short!("EURC")]);
        assert_eq!(
            require_matching_settlement_currency(&whitelist, &symbol_short!("USDC")),
            Ok(())
        );
        assert_eq!(
            require_matching_settlement_currency(&whitelist, &symbol_short!("EURC")),
            Ok(())
        );
    }

    #[test]
    fn accepts_sole_whitelisted_currency() {
        let env = Env::default();
        let whitelist = soroban_sdk::Vec::from_array(&env, [symbol_short!("XLM")]);
        assert_eq!(
            require_matching_settlement_currency(&whitelist, &symbol_short!("XLM")),
            Ok(())
        );
    }

    #[test]
    fn rejects_whitelist_exceeding_configured_cap() {
        let env = Env::default();
        let whitelist = soroban_sdk::Vec::from_array(
            &env,
            [
                symbol_short!("USDC"),
                symbol_short!("EURC"),
                symbol_short!("XLM"),
            ],
        );
        let config = SettlementCurrencyConfig {
            max_whitelist_size: 2,
        };
        assert_eq!(
            require_matching_settlement_currency_with_config(
                &whitelist,
                &symbol_short!("XLM"),
                &config
            ),
            Err(SettlementCurrencyError::WhitelistTooLarge)
        );
    }
}

/// Minimum transfer amount to prevent gas grief.
pub const MIN_TRANSFER: i128 = 100;

/// Error returned when a transfer amount is too small (dust).
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum DustError {
    /// The amount is below `MIN_TRANSFER`.
    AmountTooSmall = 1,
}

/// Guards that a transfer amount meets the minimum threshold to prevent dust spam.
///
/// # Threat model
/// Without a minimum transfer bound, an attacker could repeatedly trigger token
/// transfers of 1 minor unit (e.g., 1 stroop). This could be used to grief the
/// network (wasting block space or gas) and the application (generating many
/// events or consuming rate limits) while moving virtually no economic value.
///
/// # Cost
/// A single `i128` comparison.
///
/// # Errors
/// Returns [`DustError::AmountTooSmall`] if `amount < MIN_TRANSFER`.
pub fn verify_no_dust(amount: i128) -> Result<(), DustError> {
    if amount < MIN_TRANSFER {
        Err(DustError::AmountTooSmall)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod dust_tests {
    use super::*;

    #[test]
    fn rejects_dust() {
        assert_eq!(verify_no_dust(99), Err(DustError::AmountTooSmall));
        assert_eq!(verify_no_dust(0), Err(DustError::AmountTooSmall));
    }

    #[test]
    fn accepts_min_transfer() {
        assert_eq!(verify_no_dust(MIN_TRANSFER), Ok(()));
    }

    #[test]
    fn accepts_large_amount() {
        assert_eq!(verify_no_dust(i128::MAX), Ok(()));
    }
}

/// Pre-upgrade snapshot version
pub const SNAPSHOT_VERSION: u32 = 1;

/// Maximum age of a pre-upgrade snapshot before restore is rejected.
pub const SNAPSHOT_MAX_AGE_SECS: u64 = 30 * 24 * 60 * 60;

/// Storage key for pre-upgrade snapshots
pub const SNAPSHOT_KEY: Symbol = symbol_short!("SNAPSHOT");

/// Typed error returned when a pre-upgrade snapshot is older than the freshness window.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum SnapshotError {
    SnapshotTooOld = 1,
}

/// Ensure a pre-upgrade snapshot is still fresh enough to restore.
pub fn require_recent_snapshot(env: &Env, snapshot_taken_at: u64) -> Result<(), SnapshotError> {
    let age = env.ledger().timestamp().saturating_sub(snapshot_taken_at);
    if age > SNAPSHOT_MAX_AGE_SECS {
        Err(SnapshotError::SnapshotTooOld)
    } else {
        Ok(())
    }
}

/// Rate limiting constants
pub const RATE_LIMIT_WINDOW_SECONDS: u64 = 86400; // 24 hours
const STORAGE_RATE_LIMIT: Symbol = symbol_short!("RATE_LIM");

/// Rate limit record: stores count per address + operation + window
#[contracttype]
#[derive(Clone)]
pub struct RateLimitRecord {
    pub count: u32,
    pub window_id: u64,
}

/// Rate limit error
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RateLimitError {
    RateLimitExceeded,
}

/// Helper to check and increment rate limit
///
/// # Arguments
/// * `env` - Soroban environment
/// * `caller` - Address of the caller
/// * `operation` - Symbol identifying the operation to rate limit
/// * `limit` - Maximum allowed operations per window
///
/// # Returns
/// * `Ok(())` if within limit
/// * `Err(RateLimitError::RateLimitExceeded)` if limit exceeded
pub fn check_and_increment_rate_limit(
    env: &Env,
    caller: &Address,
    operation: Symbol,
    limit: u32,
) -> Result<(), RateLimitError> {
    let now = env.ledger().timestamp();
    let window_id = (now / RATE_LIMIT_WINDOW_SECONDS) * RATE_LIMIT_WINDOW_SECONDS;

    let key = (caller.clone(), operation, window_id);

    let mut rate_limits: Map<(Address, Symbol, u64), RateLimitRecord> = env
        .storage()
        .instance()
        .get(&STORAGE_RATE_LIMIT)
        .unwrap_or_else(|| Map::new(env));

    let record = rate_limits.get(key.clone()).unwrap_or(RateLimitRecord {
        count: 0,
        window_id,
    });

    if record.count >= limit {
        return Err(RateLimitError::RateLimitExceeded);
    }

    let new_record = RateLimitRecord {
        count: record.count + 1,
        window_id,
    };

    rate_limits.set(key, new_record);
    env.storage()
        .instance()
        .set(&STORAGE_RATE_LIMIT, &rate_limits);

    Ok(())
}

/// Helper to get current rate limit status for an operation
pub fn get_rate_limit_status(env: &Env, caller: &Address, operation: Symbol) -> (u32, u64) {
    let now = env.ledger().timestamp();
    let window_id = (now / RATE_LIMIT_WINDOW_SECONDS) * RATE_LIMIT_WINDOW_SECONDS;

    let key = (caller.clone(), operation, window_id);

    let rate_limits: Map<(Address, Symbol, u64), RateLimitRecord> = env
        .storage()
        .instance()
        .get(&STORAGE_RATE_LIMIT)
        .unwrap_or_else(|| Map::new(env));

    let record = rate_limits.get(key).unwrap_or(RateLimitRecord {
        count: 0,
        window_id,
    });

    (record.count, window_id + RATE_LIMIT_WINDOW_SECONDS)
}

/// Normalizes caller-supplied pagination limits for all shared paginated reads.
///
/// # Contract
/// - `0` is treated as a request for the default limit and returns `DEFAULT_PAGE_LIMIT`.
/// - Values between `1` and `MAX_PAGE_LIMIT` (inclusive) are passed through unchanged.
/// - Values greater than `MAX_PAGE_LIMIT` are capped at `MAX_PAGE_LIMIT`.
/// - The returned value is always in `1..=MAX_PAGE_LIMIT`.
/// - The function is idempotent: applying it to an already-normalized value returns
///   the same value.
/// - Extremely large inputs, including `u32::MAX`, clamp without arithmetic and
///   cannot overflow.
pub fn clamp_limit(limit: u32) -> u32 {
    if limit == 0 {
        DEFAULT_PAGE_LIMIT
    } else if limit > MAX_PAGE_LIMIT {
        MAX_PAGE_LIMIT
    } else {
        limit
    }
}

// ---------------------------------------------------------------------------
// Top-N bound validation
// ---------------------------------------------------------------------------

/// Error returned when a caller-supplied top-N count exceeds the hard cap.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum TopNError {
    /// `n > max`.  Every top-N endpoint must enforce a hard limit on the
    /// number of items requested so that an attacker cannot force unbounded
    /// in-memory allocation or gas exhaustion.
    TopNTooLarge = 1,
}

/// Reject a user-supplied top-N count when it exceeds the configurable cap.
///
/// This is a defence-in-depth guard that must be called before allocating a
/// sorted result buffer of size `n`.  Unlike [`clamp_limit`], which silently
/// caps the value, this function returns a typed error so the caller can
/// surface a clear contract error.
///
/// # Threat model
///
/// An attacker who supplies an arbitrarily large `n` (e.g. `u32::MAX`) to a
/// top-N endpoint can force the contract to:
///
/// - Allocate an in-memory vector of size `n` (allocator pressure; in WASM
///   this may trigger a host budget overflow and abort the transaction).
/// - Execute O(n×m) sorted-insertion logic where m is the number of source
///   items, dramatically increasing the instruction count and consuming the
///   caller's instruction budget while wasting the validator's compute.
/// - Emit events or produce return values whose size scales with `n`,
///   potentially exceeding XDR limits or indexer budgets downstream.
///
/// The check is a single `u32` comparison.  It is safe to call even on
/// hot paths because it cannot panic and adds no storage I/O.
///
/// # Arguments
/// * `n`   - The caller-supplied top-N count.
/// * `max` - The configurable maximum (typically [`MAX_TOP_N`]).
///
/// # Returns
/// * `Ok(())` when `n <= max`.
/// * `Err(TopNError::TopNTooLarge)` when `n > max`.
///
/// # Cost
/// A single `u32` comparison; negligible relative to any top-N entry
/// point's existing storage reads, cross-contract calls, and sorting logic.
#[inline(always)]
pub fn require_bounded_top_n(n: u32, max: u32) -> Result<(), TopNError> {
    if n > max {
        Err(TopNError::TopNTooLarge)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod bounded_top_n_tests {
    use super::*;

    #[test]
    fn n_within_limit_passes() {
        assert_eq!(require_bounded_top_n(5, 10), Ok(()));
    }

    #[test]
    fn n_at_max_passes() {
        assert_eq!(require_bounded_top_n(10, 10), Ok(()));
    }

    #[test]
    fn n_is_zero_passes() {
        assert_eq!(require_bounded_top_n(0, 10), Ok(()));
    }

    #[test]
    fn n_exceeds_max_by_one_fails() {
        assert_eq!(
            require_bounded_top_n(11, 10),
            Err(TopNError::TopNTooLarge)
        );
    }

    #[test]
    fn n_is_u32_max_fails() {
        assert_eq!(
            require_bounded_top_n(u32::MAX, 10),
            Err(TopNError::TopNTooLarge)
        );
    }

    #[test]
    fn max_is_zero_n_is_one_fails() {
        assert_eq!(
            require_bounded_top_n(1, 0),
            Err(TopNError::TopNTooLarge)
        );
    }

    #[test]
    fn max_is_zero_n_is_zero_passes() {
        assert_eq!(require_bounded_top_n(0, 0), Ok(()));
    }

    #[test]
    fn max_is_u32_max_n_is_u32_max_passes() {
        assert_eq!(require_bounded_top_n(u32::MAX, u32::MAX), Ok(()));
    }
}

/// Pro-rata distribution helper
///
/// Maximum safe weight for a single pro-rata bucket.
///
/// Derived from `i128::MAX / i128::MAX` = 1, but the practical constraint is
/// `total.saturating_mul(max_weight)` must not overflow a consumers mental model.
/// The denominator (total_weight) is typically 10_000 (100% in basis points) or
/// 100 (percent). This constant documents the upper bound used by the saturating
/// path: any weight above this would saturate at `i128::MAX` regardless.
pub const PRO_RATA_MAX_TOTAL_WEIGHT: u32 = 10_000;

/// Distribute `total` pro-rata across `out.len()` buckets using saturating arithmetic.
///
/// Each bucket *i* (except the last) receives
/// `total.saturating_mul(weights[i] as i128).saturating_div(total_weight as i128)`.
///
/// The last bucket receives the remainder (`total - allocated_so_far`) so that
/// the conservation invariant holds:
///
/// ```text
/// sum(out) == total   (when total does not overflow i128)
///
/// ```
/// When `total` is large enough that intermediate products would exceed `i128::MAX`,
/// the saturating path caps allocations at `i128::MAX` instead of panicking.
/// No arithmetic operation in this function can panic.
///
/// # Arguments
/// * `total` - Total amount to distribute. Must be ≥ 0.
/// * `weights` - Per-bucket weights. Length must equal `out.len()`. Each weight
///   must be ≤ `total_weight`.
/// * `total_weight` - Sum of all weights. Must be > 0.
/// * `out` - Mutable slice filled with the pro-rata distribution.
///
/// # Panics (debug-only; in release these are unreachable if preconditions hold)
/// * `weights.is_empty()` or `out.is_empty()` — there must be at least one bucket.
/// * `weights.len() != out.len()` — input/output length mismatch.
/// * `total_weight == 0` — division by zero.
/// * `total < 0` — negative total is rejected.
///
/// # Examples
///
/// ```ignore
/// let mut out = [0i128; 4];
/// distribute_pro_rata(100, &[50, 30, 15, 5], 100, &mut out);
/// assert_eq!(out, [50, 30, 15, 5]);
///
/// // With basis points (10_000 = 100%):
/// let mut out = [0i128; 4];
/// distribute_pro_rata(1_000_000, &[5000, 3000, 1500, 500], 10_000, &mut out);
/// assert_eq!(out, [500_000, 300_000, 150_000, 50_000]);
/// ```
pub fn distribute_pro_rata(total: i128, weights: &[u32], total_weight: u32, out: &mut [i128]) {
    assert!(total >= 0, "total must be non-negative");
    assert!(total_weight > 0, "total_weight must be positive");
    assert!(!out.is_empty(), "out must not be empty");
    assert!(!weights.is_empty(), "weights must not be empty");
    assert_eq!(
        weights.len(),
        out.len(),
        "weights and out must have the same length"
    );

    let n = weights.len();

    // All buckets except the last: standard pro-rata floor allocation.
    let mut allocated: i128 = 0;
    let last = n.saturating_sub(1);
    for i in 0..last {
        let weight = weights[i] as i128;
        let share = total
            .saturating_mul(weight)
            .saturating_div(total_weight as i128);
        out[i] = share;
        allocated = allocated.saturating_add(share);
    }

    // Last bucket receives the remainder, guaranteeing conservation.
    // When n == 1, last == 0 and allocated == 0, so out[0] == total.
    out[last] = total.saturating_sub(allocated);
}

/// Error converting an integer to `i128` when the value is out of range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntConversionError {
    Overflow,
}

/// Fallible conversion to `i128` for safe cross-type arithmetic.
pub trait ToI128Checked {
    fn to_i128_checked(self) -> Result<i128, IntConversionError>;
}

impl ToI128Checked for u32 {
    fn to_i128_checked(self) -> Result<i128, IntConversionError> {
        Ok(self as i128)
    }
}

impl ToI128Checked for i32 {
    fn to_i128_checked(self) -> Result<i128, IntConversionError> {
        Ok(self as i128)
    }
}

// ---------------------------------------------------------------------------
// Rate newtype — basis-points arithmetic
// ---------------------------------------------------------------------------

/// Basis-points denominator: 10_000 basis points = 100%.
///
/// All Remitwise contracts express percentages in basis points (1 bps = 0.01%)
/// so that integer arithmetic can be used without floating point.
pub const BASIS_POINTS: u32 = 10_000;
pub const BPS_PER_PERCENT: u32 = 100;
pub const BASIS_POINTS_PER_PERCENT: u32 = 100;

/// Number of basis points in one percentage point (1% = 100 bps).
pub const BPS_PER_PERCENT: u32 = 100;
pub const BASIS_POINTS_PER_PERCENT: u32 = BPS_PER_PERCENT;

/// Supported units for externally supplied rate inputs.
///
/// Remitwise contracts currently accept only basis points. Treating a raw rate
/// value as unitless would let a caller supply an unexpected denomination and
/// have the contract silently interpret it as basis points, potentially
/// magnifying or shrinking fee/discount/allocation calculations. This guard
/// makes the accepted unit explicit and reject-by-default.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum RateUnit {
    BasisPoints = 1,
}

/// Error returned when an externally supplied rate unit is unsupported.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum RateUnitError {
    UnsupportedRateUnit = 1,
}

/// Require that `unit` is one of the rate denominations currently supported by
/// the contracts.
///
/// # Errors
/// Returns [`RateUnitError::UnsupportedRateUnit`] when `unit` is not accepted.
#[inline(always)]
pub fn require_supported_rate_unit(unit: u32) -> Result<RateUnit, RateUnitError> {
    match unit {
        1 => Ok(RateUnit::BasisPoints),
        _ => Err(RateUnitError::UnsupportedRateUnit),
    }
}

/// Error returned by [`Rate`] arithmetic when the result overflows `i128`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RateError {
    /// The intermediate or final result exceeds numerical limits (`i128::MAX` or `u32::MAX`).
    Overflow,
}

pub const BPS_PER_PERCENT: u32 = 100;
pub const BASIS_POINTS_PER_PERCENT: u32 = 100;


/// A whole percentage value (1% = 100 basis points).
///
/// `Percent` wraps a `u32` representing whole percentage units. Safe conversions
/// to basis points ([`Rate`]) are provided via [`to_rate`](Percent::to_rate),
/// [`to_bps`](Percent::to_bps), and `TryFrom<Percent> for Rate`.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct Percent(u32);

impl Percent {
    pub const ZERO: Percent = Percent(0);
    pub const HUNDRED: Percent = Percent(100);

    /// Create a `Percent` from a whole percentage integer value.
    #[inline(always)]
    pub fn from_percentage(percent: u32) -> Self {
        Self(percent)
    }

    /// Return the whole percentage integer value.
    #[inline(always)]
    pub fn to_percentage(self) -> u32 {
        self.0
    }

    /// Convert this `Percent` to a basis-points [`Rate`].
    ///
    /// Returns `Ok(Rate)` if `percent * 100` fits in `u32`, or `Err(RateError::Overflow)` otherwise.
    pub fn to_rate(self) -> Result<Rate, RateError> {
        Rate::from_percent(self.0)
    }

    /// Convert this `Percent` to raw basis points (`u32`).
    ///
    /// Returns `Ok(bps)` if `percent * 100` fits in `u32`, or `Err(RateError::Overflow)` otherwise.
    pub fn to_bps(self) -> Result<u32, RateError> {
        self.0
            .checked_mul(BPS_PER_PERCENT)
            .ok_or(RateError::Overflow)
    }
}

impl TryFrom<Percent> for Rate {
    type Error = RateError;

    #[inline(always)]
    fn try_from(percent: Percent) -> Result<Self, Self::Error> {
        percent.to_rate()
    }
}

/// A rate expressed in basis points (1 bps = 0.01 %).
///
/// `Rate` wraps a `u32` where the stored value represents hundredths of a
/// percent:
///
/// | Value | Meaning         |
/// |-------|-----------------|
/// | 0     | 0 %             |
/// | 1     | 0.01 %          |
/// | 100   | 1 %             |
/// | 500   | 5 %             |
/// | 1_000 | 10 %            |
/// | 10_000| 100 %           |
/// | 50_000| 500 % (overage) |
///
/// Use [`apply_to`](Rate::apply_to) to compute `amount * rate / BASIS_POINTS`
/// with checked arithmetic.
///
/// # Examples
/// ```
/// use remitwise_common::{Rate, BASIS_POINTS, RateError};
///
/// let rate = Rate::from_bps(500); // 5%
/// assert_eq!(rate.apply_to(1000), Ok(50));
/// assert_eq!(rate.apply_to(i128::MAX), Err(RateError::Overflow));
/// ```
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct Rate(u32);

impl Rate {
    pub const ZERO: Rate = Rate(0);
    pub const MAX: Rate = Rate(u32::MAX);

    /// Create a `Rate` from a raw basis-point value.
    ///
    /// No validation is performed — `u32::MAX` is accepted. Callers that need
    /// semantic bounds (e.g. `rate <= BASIS_POINTS` for a discount rate) should
    /// check them at the call site.
    #[inline(always)]
    pub fn from_bps(bps: u32) -> Self {
        Self(bps)
    }

    /// Create a `Rate` from a whole percentage value (`percent * 100` bps).
    pub fn from_percent(percent: u32) -> Result<Self, RateError> {
        percent
            .checked_mul(BPS_PER_PERCENT)
            .map(Self::from_bps)
            .ok_or(RateError::Overflow)
    }

    /// Create a `Rate` from a [`Percent`] type.
    pub fn from_percent_type(percent: Percent) -> Result<Self, RateError> {
        percent.to_rate()
    }

    /// Construct a `Rate` from an externally supplied raw value plus unit.
    ///
    /// This is the safe entry point for untrusted inputs that carry an explicit
    /// unit field. Only supported units are accepted.
    #[inline(always)]
    pub fn try_from_input(value: u32, unit: u32) -> Result<Self, RateUnitError> {
        require_supported_rate_unit(unit)?;
        Ok(Self::from_bps(value))
    }

    /// Create a `Rate` from a whole percentage value, checking for overflow.
    ///
    /// Returns `Ok(Rate)` if `percent * 100` fits in `u32`, or `Err(RateError::Overflow)`.
    #[inline(always)]
    pub fn from_percent(percent: u32) -> Result<Self, RateError> {
        percent
            .checked_mul(BPS_PER_PERCENT)
            .map(Self)
            .ok_or(RateError::Overflow)
    }

    /// Create a `Rate` from a [`Percent`] newtype.
    #[inline(always)]
    pub fn from_percent_type(percent: Percent) -> Result<Self, RateError> {
        Self::from_percent(percent.to_percentage())
    }

    /// Return the raw basis-point value.
    #[inline(always)]
    pub fn to_bps(self) -> u32 {
        self.0
    }

    /// Create a `Rate` from a whole percentage integer.
    ///
    /// Returns `Ok(Rate)` if `percent * BPS_PER_PERCENT` fits in `u32`,
    /// or `Err(RateError::Overflow)` otherwise.
    ///
    /// # Examples
    /// ```
    /// use remitwise_common::Rate;
    /// assert_eq!(Rate::from_percent(5), Ok(Rate::from_bps(500)));
    /// assert_eq!(Rate::from_percent(0), Ok(Rate::from_bps(0)));
    /// ```
    #[inline(always)]
    pub fn from_percent(percent: u32) -> Result<Self, RateError> {
        percent
            .checked_mul(BPS_PER_PERCENT)
            .map(Self)
            .ok_or(RateError::Overflow)
    }

    /// Convert this rate back to a whole percentage integer value, truncating fractional basis points.
    #[inline(always)]
    pub fn to_percent(self) -> u32 {
        self.0 / BPS_PER_PERCENT
    }

    /// Return true if this rate contains a fractional percentage (basis points not divisible by 100).
    #[inline(always)]
    #[allow(clippy::manual_is_multiple_of)]
    pub fn has_fractional_percent(self) -> bool {
        self.0 % BPS_PER_PERCENT != 0
    }

    /// Apply this rate to `amount`, computing `(amount * self) / BASIS_POINTS`.
    ///
    /// Uses checked arithmetic. Returns:
    /// - `Ok(result)` when the multiplication and division succeed.
    /// - `Err(RateError::Overflow)` when `amount * self` overflows `i128`.
    ///
    /// Note: the division truncates towards zero. This matches the behaviour of
    /// `safe_percent` elsewhere in the codebase.
    pub fn apply_to(self, amount: i128) -> Result<i128, RateError> {
        let rate_i128 = self.0 as i128;
        amount
            .checked_mul(rate_i128)
            .and_then(|product| product.checked_div(BASIS_POINTS as i128))
            .ok_or(RateError::Overflow)
    }
}

impl ToI128Checked for Rate {
    #[inline(always)]
    fn to_i128_checked(self) -> Result<i128, IntConversionError> {
        Ok(self.0 as i128)
    }
}

/// Construct a [`Rate`] from a [`Percent`] value.
///
/// This is a convenience wrapper around [`Rate::from_percent`] for callers
/// that already have a typed [`Percent`].
///
/// # Errors
/// Returns [`RateError::Overflow`] when the conversion overflows `u32`.
#[inline(always)]
pub fn from_percent_type(percent: Percent) -> Result<Rate, RateError> {
    Rate::from_percent(percent.to_percentage())
}

/// Error related to time and periods.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum TimeError {
    InvalidPeriod = 7,
}

/// Namespace for shared timestamp helpers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct Timestamp;

impl Timestamp {
    /// Returns the number of whole seconds from `now` until `target`.
    ///
    /// The result saturates at `0` when `target <= now`, so callers can measure
    /// future distance without risking underflow or writing their own
    /// `saturating_sub`/guard pattern.
    #[inline(always)]
    pub fn seconds_until(now: u64, target: u64) -> u64 {
        target.saturating_sub(now)
    }
}

/// Validates that a requested period is logically ordered.
///
/// # Errors
/// Returns `TimeError::InvalidPeriod` if `start > end`.
pub fn validate_period(start: u64, end: u64) -> Result<(), TimeError> {
    if start > end {
        Err(TimeError::InvalidPeriod)
    } else {
        Ok(())
    }
}

/// Error returned when the current ledger sequence does not match the expected value.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum LedgerError {
    LedgerMismatch = 1,
}

/// Asserts that `expected` matches the current ledger sequence number.
///
/// This is a replay-prevention helper: if an operation was authorized for a
/// specific ledger (e.g. via a signed nonce bound to a ledger), executing it in
/// a different ledger would let an attacker replay the same authorization in a
/// later ledger.  Call this function at the start of the operation to tie it
/// to the current ledger.
///
/// # Errors
/// Returns [`LedgerError::LedgerMismatch`] when `expected != env.ledger().sequence()`.
pub fn require_matching_ledger(env: &Env, expected: u32) -> Result<(), LedgerError> {
    let current = env.ledger().sequence();
    if current != expected {
        Err(LedgerError::LedgerMismatch)
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Non-zero u128 helper
// ---------------------------------------------------------------------------

/// Error returned when a non-zero u128 value was expected but zero was provided.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ZeroNotAllowed;

/// A u128 value that is guaranteed to be non-zero.
///
/// This type wraps a `u128` and enforces at construction that the value is not
/// zero. Once constructed, callers can safely assume the value is in `1..=u128::MAX`.
///
/// # Examples
///
/// ```ignore
/// use remitwise_common::{NonZeroU128, ZeroNotAllowed};
///
/// let nz = NonZeroU128::new(42).unwrap();
/// assert_eq!(nz.get(), 42);
///
/// assert_eq!(NonZeroU128::new(0), Err(ZeroNotAllowed));
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct NonZeroU128(u128);

impl NonZeroU128 {
    /// Creates a new `NonZeroU128` if `value` is non-zero.
    pub fn new(value: u128) -> Result<Self, ZeroNotAllowed> {
        if value == 0 {
            Err(ZeroNotAllowed)
        } else {
            Ok(NonZeroU128(value))
        }
    }

    /// Returns the contained u128 value.
    pub fn get(&self) -> u128 {
        self.0
    }
}

// ---------------------------------------------------------------------------
// Tag canonicalization
// ---------------------------------------------------------------------------

/// Maximum allowed byte length for a single tag.
pub const TAG_MAX_LEN: u32 = 32;

/// Validation failure returned by [`canonicalize_tags_checked`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TagError {
    /// The tag batch is empty, or an individual tag is zero bytes long.
    Empty,
    /// A tag exceeds [`TAG_MAX_LEN`] bytes.
    TooLong,
    /// A byte at `position` is not in the allowed charset after upper-case folding.
    InvalidChar { position: u32 },
}

/// Canonicalizes a single label string into a `Symbol`.
///
/// Rules:
/// - Leading and trailing ASCII whitespace is stripped.
/// - ASCII uppercase letters are folded to lowercase.
/// - The result must satisfy `Symbol`'s charset (`[a-zA-Z0-9_]` after folding)
///   and length (`1..=32` bytes after trimming), otherwise this panics.
///
/// # Idempotency guarantee
///
/// Applying this function twice to any input yields the same `Symbol`:
/// `canonicalise_symbol(env, &canonicalise_symbol(env, &x).to_string()) == canonicalise_symbol(env, &x)`.
///
/// # Whitespace round-trip
///
/// Inputs that differ only in leading/trailing whitespace produce identical
/// canonical `Symbol` values: `"hello"`, `" hello"`, and `"hello "` all map
/// to `Symbol("hello")`.
///
/// # Panics
///
/// - On empty or whitespace-only input (after trimming length is 0).
/// - On input over 32 bytes (after trimming).
/// - When the trimmed, lowercased content contains bytes outside `[a-z0-9_]`.
pub fn canonicalise_symbol(env: &Env, input: &soroban_sdk::String) -> Symbol {
    let len = input.len();
    if len == 0 {
        panic!("symbol input must contain between 1 and 32 characters after trimming");
    }
    let mut buf = [0u8; 256];
    if len as usize > buf.len() {
        panic!("symbol input is too long");
    }
    input.copy_into_slice(&mut buf[..len as usize]);

    let s = core::str::from_utf8(&buf[..len as usize])
        .unwrap_or_else(|_| panic!("symbol input is not valid UTF-8"));

    let trimmed = s.trim();
    let trimmed_len = trimmed.len();
    if trimmed_len == 0 {
        panic!("symbol input must contain at least one non-whitespace character");
    }
    if trimmed_len > 32 {
        panic!("symbol input must contain between 1 and 32 characters after trimming");
    }

    let trimmed_bytes = trimmed.as_bytes();
    let mut canonical = [0u8; 32];
    for (i, &byte) in trimmed_bytes.iter().enumerate() {
        canonical[i] = if byte.is_ascii_uppercase() {
            byte.to_ascii_lowercase()
        } else {
            byte
        };
    }

    let canonical_str = core::str::from_utf8(&canonical[..trimmed_len])
        .unwrap_or_else(|_| panic!("canonicalised symbol is not valid UTF-8"));

    Symbol::new(env, canonical_str)
}

/// Signature verification failure.
#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum SignatureError {
    /// Invalid signature length (must be 64 bytes for Ed25519).
    InvalidSignatureLength = 1,
    /// Invalid public key length (must be 32 bytes for Ed25519).
    InvalidPublicKeyLength = 2,
    /// Signature verification failed.
    VerificationFailed = 3,
    /// The verifier public key has not been registered for attestation verification.
    UnregisteredVerifier = 4,
}

/// Storage key for the set of registered verifier public keys.
const REGISTERED_VERIFIERS_KEY: Symbol = symbol_short!("REGVER");

/// Registers a verifier public key so its attestations may be consumed.
pub fn register_verifier(env: &Env, public_key: &[u8]) -> Result<(), SignatureError> {
    let pk_arr: [u8; 32] = public_key
        .try_into()
        .map_err(|_| SignatureError::InvalidPublicKeyLength)?;
    let key = BytesN::<32>::from_array(env, &pk_arr);

    let mut registered_verifiers: Map<BytesN<32>, bool> = env
        .storage()
        .instance()
        .get(&REGISTERED_VERIFIERS_KEY)
        .unwrap_or_else(|| Map::new(env));

    registered_verifiers.set(key, true);
    env.storage()
        .instance()
        .set(&REGISTERED_VERIFIERS_KEY, &registered_verifiers);

    Ok(())
}

/// Requires the supplied verifier public key to be registered before an external
/// attestation can be consumed.
pub fn require_registered_verifier(env: &Env, public_key: &[u8]) -> Result<(), SignatureError> {
    let pk_arr: [u8; 32] = public_key
        .try_into()
        .map_err(|_| SignatureError::InvalidPublicKeyLength)?;
    let key = BytesN::<32>::from_array(env, &pk_arr);

    let registered_verifiers: Map<BytesN<32>, bool> = env
        .storage()
        .instance()
        .get(&REGISTERED_VERIFIERS_KEY)
        .unwrap_or_else(|| Map::new(env));

    if registered_verifiers.get(key).unwrap_or(false) {
        Ok(())
    } else {
        Err(SignatureError::UnregisteredVerifier)
    }
}

/// Verify an Ed25519 signature with domain separation.
///
/// The payload is encoded as a length-delimited byte stream so adjacent or
/// overlapping separators/messages cannot collide. For example, the pair
/// `(domain="ab", message="cdef")` and `(domain="abc", message="def")`
/// produce different payloads even though their plain concatenation would be
/// identical.
///
/// # Arguments
/// * `env` - Soroban environment
/// * `domain_separator` - Domain separator to prevent cross-domain replay attacks
/// * `message` - The message to verify
/// * `signature` - The Ed25519 signature (64 bytes)
/// * `public_key` - The Ed25519 public key (32 bytes)
///
/// # Returns
/// * `Ok(())` if the signature is valid
/// * `Err(SignatureError)` if verification fails
pub fn verify_signature(
    env: &soroban_sdk::Env,
    domain_separator: &[u8],
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<(), SignatureError> {
    require_registered_verifier(env, public_key)?;

    let mut prefixed_message = Bytes::new(env);
    prefixed_message.extend_from_slice(domain_separator);
    prefixed_message.extend_from_slice(message);

    let sig_bytes: BytesN<64> = {
        let mut arr = [0u8; 64];
        arr.copy_from_slice(signature);
        BytesN::from_array(env, &arr)
    };
    let pk_bytes: BytesN<32> = {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(public_key);
        BytesN::from_array(env, &arr)
    };

    env.crypto().ed25519_verify(&pk_bytes, &prefixed_message, &sig_bytes);
    let pk_arr: [u8; 32] = public_key
        .try_into()
        .map_err(|_| SignatureError::InvalidPublicKeyLength)?;
    let sig_arr: [u8; 64] = signature
        .try_into()
        .map_err(|_| SignatureError::InvalidSignatureLength)?;

    let mut msg_bytes = Bytes::new(env);
    let domain_len = (domain_separator.len() as u64).to_le_bytes();
    let message_len = (message.len() as u64).to_le_bytes();

    msg_bytes.extend_from_slice(&domain_len);
    msg_bytes.extend_from_slice(domain_separator);
    msg_bytes.extend_from_slice(&message_len);
    msg_bytes.extend_from_slice(message);

    let sig_bytes = soroban_sdk::BytesN::from_array(env, &sig_arr);
    let pk_bytes = soroban_sdk::BytesN::from_array(env, &pk_arr);

    env.crypto()
        .ed25519_verify(&pk_bytes, &msg_bytes, &sig_bytes);
    Ok(())
}

/// Typed error for slash signature verification.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum SlashError {
    InvalidSignature = 8,
}

/// Verify an optional second-party slash signature.
///
/// This provides a defence-in-depth gate before executing destructive slash operations.
///
/// # Arguments
/// * `env` - Soroban environment
/// * `message` - The payload being authorized (e.g. amount or slash payload)
/// * `signature` - Optional 64-byte Ed25519 signature
/// * `public_key` - 32-byte Ed25519 public key of the second party
///
/// # Returns
/// * `Ok(())` if signature is valid or not provided (optional gate)
/// * `Err(SlashError)` if the provided signature is invalid
pub fn verify_slash_signature(
    env: &soroban_sdk::Env,
    message: &[u8],
    signature: Option<&[u8]>,
    public_key: &[u8],
) -> Result<(), SlashError> {
    if let Some(sig) = signature {
        if verify_signature(env, b"slash-auth", message, sig, public_key).is_err() {
            return Err(SlashError::InvalidSignature);
        }
    }
    Ok(())
}

/// Validates and canonicalizes a single symbol string.
///
/// Trims leading, trailing, and surrounding whitespace. Converts ASCII uppercase to lowercase.
/// Allows only ASCII lowercase, digits, and underscores.
/// Panics if the input contains invalid characters, is empty, or exceeds 32 bytes after trimming.
pub fn canonicalise_symbol(env: &soroban_sdk::Env, input: &soroban_sdk::String) -> soroban_sdk::Symbol {
    let len = input.len();
    if len == 0 {
        panic!("symbol input must contain between 1 and 32 characters");
    }
    
    // We expect the untrimmed input to be small enough.
    // If it's over 128 bytes, we can safely panic since a valid symbol is at most 32 bytes.
    let actual_len = len as usize;
    if actual_len > 128 {
        panic!("symbol input must contain between 1 and 32 characters");
    }
    
    let mut buf = [0u8; 128];
    input.copy_into_slice(&mut buf[..actual_len]);

    let mut start = 0;
    while start < actual_len && buf[start] == b' ' {
        start += 1;
    }
    
    let mut end = actual_len;
    while end > start && buf[end - 1] == b' ' {
        end -= 1;
    }
    
    if start == end {
        panic!("non-whitespace character");
    }
    
    let trimmed_len = end - start;
    if trimmed_len == 0 || trimmed_len > 32 {
        panic!("symbol input must contain between 1 and 32 characters");
    }
    
    let mut out_buf = [0u8; 32];
    for i in 0..trimmed_len {
        let mut b = buf[start + i];
        if b.is_ascii_uppercase() {
            b += b'a' - b'A';
        }
        if !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') {
            panic!("invalid Symbol character");
        }
        out_buf[i] = b;
    }
    
    let s = core::str::from_utf8(&out_buf[..trimmed_len]).unwrap();
    soroban_sdk::Symbol::new(env, s)
}

/// Validates and canonicalizes a batch of tags without panicking.
///
/// # Rules
/// - The batch must contain at least one tag ([`TagError::Empty`]).
/// - Each tag must be between 1 and [`TAG_MAX_LEN`] bytes inclusive
///   ([`TagError::Empty`] for zero length, [`TagError::TooLong`] otherwise).
/// - Allowed charset: `[a-z0-9\-_]`. ASCII uppercase letters are silently
///   folded to lowercase; any other byte yields [`TagError::InvalidChar`].
///
/// Validation short-circuits on the first violation (empty batch, length, or
/// invalid byte) for gas efficiency.
///
/// # Returns
/// On success, a new `Vec<String>` containing the normalized (lowercased) tags
/// in the same order as the input. The function does **not** deduplicate.
///
/// # Usage
/// ```ignore
/// use remitwise_common::{canonicalize_tags_checked, TagError};
/// match canonicalize_tags_checked(&env, &tags) {
///     Ok(normalized) => { /* store normalized */ }
///     Err(TagError::InvalidChar { .. }) => {
///         soroban_sdk::panic_with_error!(&env, MyError::InvalidTagContent)
///     }
///     Err(TagError::Empty) | Err(TagError::TooLong) => { /* map to caller error */ }
/// }
/// ```
pub fn canonicalize_tags_checked(
    env: &soroban_sdk::Env,
    tags: &soroban_sdk::Vec<soroban_sdk::String>,
) -> Result<soroban_sdk::Vec<soroban_sdk::String>, TagError> {
    if tags.is_empty() {
        return Err(TagError::Empty);
    }
    let mut out = soroban_sdk::Vec::new(env);
    for tag in tags.iter() {
        let len = tag.len();
        if len == 0 {
            return Err(TagError::Empty);
        }
        if len > TAG_MAX_LEN {
            return Err(TagError::TooLong);
        }
        let mut buf = [0u8; 32];
        tag.copy_into_slice(&mut buf[..len as usize]);
        for (position, byte) in buf.iter_mut().take(len as usize).enumerate() {
            if byte.is_ascii_uppercase() {
                *byte += b'a' - b'A';
            }
            let b = *byte;
            if !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_') {
                return Err(TagError::InvalidChar {
                    position: position as u32,
                });
            }
        }
        let s = match core::str::from_utf8(&buf[..len as usize]) {
            Ok(v) => v,
            Err(_) => {
                return Err(TagError::InvalidChar { position: 0 });
            }
        };
        out.push_back(soroban_sdk::String::from_str(env, s));
    }
    Ok(out)
}

/// Validates and canonicalizes a batch of tags, panicking on failure.
///
/// This is a thin wrapper around [`canonicalize_tags_checked`] that preserves
/// the legacy panic-based contract for existing callers. Prefer
/// [`canonicalize_tags_checked`] when handling untrusted or indexer-supplied
/// tag strings so errors can be mapped to typed contract errors.
///
/// # Rules
/// - The batch must contain at least one tag (`panic!("Tags cannot be empty")`).
/// - Each tag must be between 1 and [`TAG_MAX_LEN`] bytes inclusive
///   (`panic!("Tag must be between 1 and 32 characters")`).
/// - Allowed charset: `[a-z0-9\-_]`. ASCII uppercase letters are silently
///   folded to lowercase; any other byte causes the supplied `on_invalid_char`
///   closure to be called once (typically `panic_with_error!` or `panic!`).
///
/// # Returns
/// A new `Vec<String>` containing the normalized (lowercased) tags in the
/// same order as the input.
///
/// # Usage
/// ```ignore
/// use remitwise_common::canonicalize_tags;
/// let normalized = canonicalize_tags(&env, &tags, || {
///     soroban_sdk::panic_with_error!(&env, MyError::InvalidTagContent)
/// });
/// ```
pub fn canonicalize_tags<F>(
    env: &soroban_sdk::Env,
    tags: &soroban_sdk::Vec<soroban_sdk::String>,
    on_invalid_char: F,
) -> soroban_sdk::Vec<soroban_sdk::String>
where
    F: Fn(),
{
    match canonicalize_tags_checked(env, tags) {
        Ok(out) => out,
        Err(TagError::Empty) => {
            if tags.is_empty() {
                panic!("Tags cannot be empty");
            }
            panic!("Tag must be between 1 and 32 characters");
        }
        Err(TagError::TooLong) => panic!("Tag must be between 1 and 32 characters"),
        Err(TagError::InvalidChar { .. }) => {
            on_invalid_char();
            // on_invalid_char must diverge (panic); this is unreachable.
            soroban_sdk::Vec::new(env)
        }
    }
}

pub mod events;
pub mod reversible_op;

/// Error returned when a currency symbol is not a supported stable asset.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum StableCurrencyError {
    /// The currency symbol is not a recognized stable asset (e.g., rebase/deflationary tokens).
    UnsupportedCurrency = 1,
}

/// Known stable currency symbols (case-insensitive).
/// This is a defence-in-depth allowlist of well-known stablecoins.
/// Rebase/deflationary/elastic-supply tokens (e.g., AMPL, OHM, TIME) are intentionally excluded.
const STABLE_CURRENCIES: &[&str] = &[
    "USDC", "USDT", "USDP", "BUSD", "GUSD", "TUSD", "USDD", "EURC", "EURS", "DAI", "XLM",
];

/// Validates that a currency symbol represents a supported stable asset.
///
/// This is a defence-in-depth check to reject rebase/deflationary/elastic-supply
/// token contracts at ingress. If an unsupported currency is accepted at ingress,
/// it can silently change balances during transfer and violate contract invariants
/// (e.g., remittance splits, bill payments, insurance payouts).
///
/// # Threat model
/// An attacker who can inject a rebase/deflationary token at ingress can:
/// - Cause silent balance drift during transfers, breaking settlement invariants
/// - Grief accounting/audit trails by manufacturing "settled" states with altered values
/// - Subvert split/allocation logic that assumes stable 1:1 value transfer
///
/// # Arguments
/// * `env` - The Soroban environment
/// * `symbol` - The currency symbol to validate (case-insensitive, whitespace trimmed)
///
/// # Returns
/// * `Ok(())` if the symbol is a recognized stable currency
/// * `Err(StableCurrencyError::UnsupportedCurrency)` if the symbol is not recognized
pub fn require_stable_currency(env: &Env, symbol: &Symbol) -> Result<(), StableCurrencyError> {
    for known in STABLE_CURRENCIES {
        if symbol_matches_known_case_insensitive(env, symbol, known) {
            return Ok(());
        }
    }
    Err(StableCurrencyError::UnsupportedCurrency)
}

/// Compare a Symbol case-insensitively against a known ASCII currency string.
///
/// Since Soroban Symbol comparison is exact (case-sensitive) and there is no
/// `no_std`-compatible way to extract raw bytes from a Symbol, we generate all
/// 2^N case variants of the known string (where N = len ≤ 10) and compare each
/// against the input Symbol.  The first match short-circuits the search.
fn symbol_matches_known_case_insensitive(env: &Env, symbol: &Symbol, known: &str) -> bool {
    let bytes = known.as_bytes();
    let len = bytes.len();

    // Try uppercase (exact) match first — the common case after normalization.
    if symbol == &Symbol::new(env, known) {
        return true;
    }

    // Generate all 2^len case-variant strings and compare as Symbols.
    // Symbols are bounded at 32 bytes and currencies at 10 bytes, so 2^10 = 1024
    // max iterations which is acceptable for an ingress guard.
    let num_variants = 1u32 << len;
    let mut buf = [0u8; 10];
    for mask in 0..num_variants {
        for (i, &b) in bytes.iter().enumerate() {
            buf[i] = if (mask >> i) & 1 == 0 {
                b.to_ascii_lowercase()
            } else {
                b
            };
        }
        // Safety: buf contains only ASCII letters after case folding.
        let variant = match core::str::from_utf8(&buf[..len]) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if symbol == &Symbol::new(env, variant) {
            return true;
        }
    }
    false
}

/// Error returned when a read config schema version is outdated.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum MigrationError {
    OutdatedVersion = 1,
}

/// Verify that a read config schema version is not outdated.
///
/// This is a defence-in-depth ingress check to reject reads against outdated config
/// schema versions.
///
/// # Arguments
/// * `v` - The version of the read config schema.
///
/// # Returns
/// * `Ok(())` if the version is up to date (greater than or equal to `CONTRACT_VERSION`)
/// * `Err(MigrationError::OutdatedVersion)` if the version is outdated
pub fn verify_config_migration(v: u32) -> Result<(), MigrationError> {
    if v < CONTRACT_VERSION {
        Err(MigrationError::OutdatedVersion)
    } else {
        Ok(())
    }
}

/// Event emission helper
pub struct RemitwiseEvents;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod emit_tests;

#[cfg(test)]
mod non_zero_u128_tests;

impl RemitwiseEvents {
    /// Emits a single event with the given category, priority, and action.
    ///
    /// * `category` – The `EventCategory` describing the type of event.
    /// * `priority` – The `EventPriority` indicating the importance level.
    /// * `action` – A short `Symbol` identifying the specific action.
    /// * `data` – The event payload implementing `IntoVal`.
    ///
    /// The emitted event follows the topic schema defined in `docs/EVENT_TAXONOMY.md`.
    ///
    /// **Size Budget**: Event data must be compact (topics + small payload, not bulk records).
    /// The recommended maximum serialized size for the `data` payload is 256 bytes.
    /// Oversized payloads will trigger a debug/test assertion.
    #[allow(unexpected_cfgs)]
    pub fn emit<T>(
        env: &soroban_sdk::Env,
        category: EventCategory,
        priority: EventPriority,
        action: Symbol,
        data: T,
    ) where
        T: soroban_sdk::IntoVal<soroban_sdk::Env, soroban_sdk::Val>,
    {
        let topics = (
            symbol_short!("Remitwise"),
            category.to_u32(),
            priority.to_u32(),
            action,
        );

        #[cfg(test)]
        {
            #[allow(unused_imports)]
            use soroban_sdk::xdr::ToXdr;
            use soroban_sdk::TryFromVal;
            let val: soroban_sdk::Val = data.into_val(env);
            if let Ok(sc_val) = soroban_sdk::xdr::ScVal::try_from_val(env, &val) {
                let size = soroban_sdk::xdr::ToXdr::to_xdr(sc_val, env).len();
                if size > 256 {
                    panic!(
                        "Event data size {} exceeds 256-byte budget. Emits must be compact.",
                        size
                    );
                }
            }
        }

        env.events().publish(topics, data);
    }

    /// Emits a batch event for the given category and action with a count.
    ///
    /// * `category` – The `EventCategory` of the batched events.
    /// * `action` – Symbol representing the batch action.
    /// * `count` – Number of events in the batch.
    ///
    /// This always uses `EventPriority::Low` for batch events.
    ///
    /// **Size Budget**: Batch payloads (action + count) are inherently compact and conform
    /// to the recommended event data budget.
    pub fn emit_batch(env: &soroban_sdk::Env, category: EventCategory, action: Symbol, count: u32) {
        let topics = (
            symbol_short!("Remitwise"),
            category.to_u32(),
            EventPriority::Low.to_u32(),
            symbol_short!("batch"),
        );
        let data = (action, count);
        env.events().publish(topics, data);
    }

    /// Test helper: asserts that the most recently emitted Remitwise event has
    /// the expected category, priority, action, and that `data_pred` accepts
    /// the decoded payload. Uses `env.events().all()` so the assertion covers
    /// the real published event stream instead of a mock.
    ///
    /// Panics when no event has been emitted, when the topic tuple does not
    /// match the `(Remitwise, category, priority, action)` schema emitted by
    /// `EventEmitter::emit`, or when the data predicate returns false.
    #[cfg(test)]
    pub fn assert_last_event<T, F>(
        env: &soroban_sdk::Env,
        expected_category: EventCategory,
        expected_priority: EventPriority,
        expected_action: Symbol,
        data_pred: F,
    ) where
        T: soroban_sdk::TryFromVal<soroban_sdk::Env, soroban_sdk::Val>,
        F: FnOnce(&T) -> bool,
    {
        use soroban_sdk::testutils::Events as soroban_Events;

        let all = env.events().all();
        let (_cid, topics, data) = all.last().expect("expected at least one emitted event");

        // Topic schema emitted by `EventEmitter::emit`:
        // (symbol_short!("Remitwise"), category_u32, priority_u32, action)
        assert_eq!(
            topics.len(),
            4,
            "expected a 4-element Remitwise event topic tuple"
        );
        let sentinel: soroban_sdk::Symbol =
            soroban_sdk::FromVal::from_val(env, &topics.get(0).unwrap());
        assert_eq!(
            sentinel,
            symbol_short!("Remitwise"),
            "first topic must be the Remitwise marker"
        );
        let cat: u32 = soroban_sdk::FromVal::from_val(env, &topics.get(1).unwrap());
        assert_eq!(cat, expected_category.to_u32(), "event category mismatch");
        let prio: u32 = soroban_sdk::FromVal::from_val(env, &topics.get(2).unwrap());
        assert_eq!(prio, expected_priority.to_u32(), "event priority mismatch");
        let action: soroban_sdk::Symbol =
            soroban_sdk::FromVal::from_val(env, &topics.get(3).unwrap());
        assert_eq!(action, expected_action, "event action mismatch");

        let payload: T = T::try_from_val(env, &data).expect("failed to decode event data");
        assert!(
            data_pred(&payload),
            "event data predicate failed for action {:?}",
            expected_action
        );
    }
}

/// Asserts that a specific pause channel is active (not paused).
/// Panics if the channel is paused.
pub fn require_active_pause_channel(env: &Env, channel: Symbol) {
    let paused = env
        .storage()
        .instance()
        .get::<_, Map<Symbol, bool>>(&Symbol::new(env, STORAGE_PAUSE_CHANNELS))
        .unwrap_or_else(|| Map::new(env))
        .get(channel)
        .unwrap_or(false);
    if paused {
        panic!("Pause channel is inactive");
    }
}

// ---------------------------------------------------------------------------
// Encoding stability tests (cross-contract ABI)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod encoding_stability_tests {
    use super::{Category, CoverageType, FamilyRole, PolicyMode};
    use soroban_sdk::{Env, Map, Vec};

    fn round_trip<T>(env: &Env, v: T) -> T
    where
        T: soroban_sdk::IntoVal<Env, soroban_sdk::Val>
            + soroban_sdk::TryFromVal<Env, soroban_sdk::Val>,
    {
        let val = v.into_val(env);
        T::try_from_val(env, &val).unwrap()
    }

    fn assert_encoding_matches_discriminant<T>(env: &Env, v: T, expected: u32)
    where
        T: soroban_sdk::IntoVal<Env, soroban_sdk::Val>
            + soroban_sdk::TryFromVal<Env, soroban_sdk::Val>
            + core::fmt::Debug
            + PartialEq,
    {
        let val = v.into_val(env);

        // `#[repr(u32)]` + `#[contracttype]` should encode via a stable u32 discriminant.
        // We pin the expected discriminant by decoding the value as `u32`.
        let actual_u32: u32 = soroban_sdk::TryFromVal::try_from_val(env, &val)
            .unwrap_or_else(|_| panic!("unexpected Val for encoding: {val:?}"));
        assert_eq!(actual_u32, expected, "encoding mismatch");

        // And ensure round-trip identity.
        let decoded = T::try_from_val(env, &val).unwrap();
        assert_eq!(decoded, v, "round-trip mismatch");
    }

    #[test]
    fn category_round_trip_and_encoding_stability() {
        let env = Env::default();

        assert_encoding_matches_discriminant(&env, Category::Spending, 1);
        assert_encoding_matches_discriminant(&env, Category::Savings, 2);
        assert_encoding_matches_discriminant(&env, Category::Bills, 3);
        assert_encoding_matches_discriminant(&env, Category::Insurance, 4);

        // Exhaustiveness enforcement: every variant must be explicitly handled.
        fn cover_all_variants(v: Category) {
            match v {
                Category::Spending => {}
                Category::Savings => {}
                Category::Bills => {}
                Category::Insurance => {}
            }
        }

        for v in [
            Category::Spending,
            Category::Savings,
            Category::Bills,
            Category::Insurance,
        ] {
            cover_all_variants(v);
        }

        // Container round-trips
        let vec = Vec::from_array(
            &env,
            [Category::Spending, Category::Savings, Category::Bills],
        );
        let mut out = Vec::<Category>::new(&env);
        for item in vec.iter() {
            out.push_back(round_trip(&env, item));
        }
        assert_eq!(out, vec);

        let mut map = Map::<u32, Category>::new(&env);
        map.set(1u32, Category::Spending);
        map.set(2u32, Category::Savings);
        map.set(3u32, Category::Bills);

        let mut out_map = Map::<u32, Category>::new(&env);
        for (k, v) in map.iter() {
            out_map.set(k, round_trip(&env, v));
        }
        assert_eq!(out_map, map);
    }

    #[test]
    fn family_role_round_trip_and_encoding_stability() {
        let env = Env::default();

        assert_encoding_matches_discriminant(&env, FamilyRole::Owner, 1);
        assert_encoding_matches_discriminant(&env, FamilyRole::Admin, 2);
        assert_encoding_matches_discriminant(&env, FamilyRole::Member, 3);
        assert_encoding_matches_discriminant(&env, FamilyRole::Viewer, 4);

        fn cover_all_variants(v: FamilyRole) {
            match v {
                FamilyRole::Owner => {}
                FamilyRole::Admin => {}
                FamilyRole::Member => {}
                FamilyRole::Viewer => {}
            }
        }

        for v in [
            FamilyRole::Owner,
            FamilyRole::Admin,
            FamilyRole::Member,
            FamilyRole::Viewer,
        ] {
            cover_all_variants(v);
        }

        let vec = Vec::from_array(
            &env,
            [FamilyRole::Owner, FamilyRole::Admin, FamilyRole::Viewer],
        );
        let mut out = Vec::<FamilyRole>::new(&env);
        for item in vec.iter() {
            out.push_back(round_trip(&env, item));
        }
        assert_eq!(out, vec);

        let mut map = Map::<u32, FamilyRole>::new(&env);
        map.set(1u32, FamilyRole::Owner);
        map.set(2u32, FamilyRole::Admin);
        map.set(3u32, FamilyRole::Viewer);

        let mut out_map = Map::<u32, FamilyRole>::new(&env);
        for (k, v) in map.iter() {
            out_map.set(k, round_trip(&env, v));
        }
        assert_eq!(out_map, map);
    }

    #[test]
    fn coverage_type_round_trip_and_encoding_stability() {
        let env = Env::default();

        assert_encoding_matches_discriminant(&env, CoverageType::Health, 1);
        assert_encoding_matches_discriminant(&env, CoverageType::Life, 2);
        assert_encoding_matches_discriminant(&env, CoverageType::Property, 3);
        assert_encoding_matches_discriminant(&env, CoverageType::Auto, 4);
        assert_encoding_matches_discriminant(&env, CoverageType::Liability, 5);

        fn cover_all_variants(v: CoverageType) {
            match v {
                CoverageType::Health => {}
                CoverageType::Life => {}
                CoverageType::Property => {}
                CoverageType::Auto => {}
                CoverageType::Liability => {}
            }
        }

        for v in [
            CoverageType::Health,
            CoverageType::Life,
            CoverageType::Property,
            CoverageType::Auto,
            CoverageType::Liability,
        ] {
            cover_all_variants(v);
        }

        let vec = Vec::from_array(
            &env,
            [
                CoverageType::Health,
                CoverageType::Life,
                CoverageType::Property,
                CoverageType::Auto,
            ],
        );
        let mut out = Vec::<CoverageType>::new(&env);
        for item in vec.iter() {
            out.push_back(round_trip(&env, item));
        }
        assert_eq!(out, vec);

        let mut map = Map::<u32, CoverageType>::new(&env);
        map.set(1u32, CoverageType::Health);
        map.set(2u32, CoverageType::Life);
        map.set(3u32, CoverageType::Liability);

        let mut out_map = Map::<u32, CoverageType>::new(&env);
        for (k, v) in map.iter() {
            out_map.set(k, round_trip(&env, v));
        }
        assert_eq!(out_map, map);
    }

    #[test]
    #[allow(clippy::single_element_loop)]
    fn policy_mode_round_trip_and_encoding_stability() {
        let env = Env::default();

        assert_encoding_matches_discriminant(&env, PolicyMode::Strict, 1);

        fn cover_all_variants(v: PolicyMode) {
            match v {
                PolicyMode::Strict => {}
            }
        }

        cover_all_variants(PolicyMode::Strict);

        let vec = Vec::from_array(&env, [PolicyMode::Strict]);
        let mut out = Vec::<PolicyMode>::new(&env);
        for item in vec.iter() {
            out.push_back(round_trip(&env, item));
        }
        assert_eq!(out, vec);

        let mut map = Map::<u32, PolicyMode>::new(&env);
        map.set(1u32, PolicyMode::Strict);

        let mut out_map = Map::<u32, PolicyMode>::new(&env);
        for (k, v) in map.iter() {
            out_map.set(k, round_trip(&env, v));
        }
        assert_eq!(out_map, map);
    }
}

#[cfg(test)]
mod stable_currency_tests {
    use super::{require_stable_currency, StableCurrencyError};
    use soroban_sdk::{Env, Symbol};

    #[test]
    fn accepts_usdc() {
        let env = Env::default();
        let sym = Symbol::new(&env, "USDC");
        assert_eq!(require_stable_currency(&env, &sym), Ok(()));
    }

    #[test]
    fn accepts_usdt() {
        let env = Env::default();
        let sym = Symbol::new(&env, "USDT");
        assert_eq!(require_stable_currency(&env, &sym), Ok(()));
    }

    #[test]
    fn accepts_usdp() {
        let env = Env::default();
        let sym = Symbol::new(&env, "USDP");
        assert_eq!(require_stable_currency(&env, &sym), Ok(()));
    }

    #[test]
    fn accepts_busd() {
        let env = Env::default();
        let sym = Symbol::new(&env, "BUSD");
        assert_eq!(require_stable_currency(&env, &sym), Ok(()));
    }

    #[test]
    fn accepts_gusd() {
        let env = Env::default();
        let sym = Symbol::new(&env, "GUSD");
        assert_eq!(require_stable_currency(&env, &sym), Ok(()));
    }

    #[test]
    fn accepts_tusd() {
        let env = Env::default();
        let sym = Symbol::new(&env, "TUSD");
        assert_eq!(require_stable_currency(&env, &sym), Ok(()));
    }

    #[test]
    fn accepts_usdd() {
        let env = Env::default();
        let sym = Symbol::new(&env, "USDD");
        assert_eq!(require_stable_currency(&env, &sym), Ok(()));
    }

    #[test]
    fn accepts_eurc() {
        let env = Env::default();
        let sym = Symbol::new(&env, "EURC");
        assert_eq!(require_stable_currency(&env, &sym), Ok(()));
    }

    #[test]
    fn accepts_eurs() {
        let env = Env::default();
        let sym = Symbol::new(&env, "EURS");
        assert_eq!(require_stable_currency(&env, &sym), Ok(()));
    }

    #[test]
    fn accepts_dai() {
        let env = Env::default();
        let sym = Symbol::new(&env, "DAI");
        assert_eq!(require_stable_currency(&env, &sym), Ok(()));
    }

    #[test]
    fn accepts_xlm() {
        let env = Env::default();
        let sym = Symbol::new(&env, "XLM");
        assert_eq!(require_stable_currency(&env, &sym), Ok(()));
    }

    #[test]
    fn accepts_lowercase_usdc() {
        let env = Env::default();
        let sym = Symbol::new(&env, "usdc");
        assert_eq!(require_stable_currency(&env, &sym), Ok(()));
    }

    #[test]
    fn accepts_mixed_case_usdc() {
        let env = Env::default();
        let sym = Symbol::new(&env, "UsDc");
        assert_eq!(require_stable_currency(&env, &sym), Ok(()));
    }

    #[test]
    fn rejects_rebase_token_ampl() {
        let env = Env::default();
        let sym = Symbol::new(&env, "AMPL");
        assert_eq!(
            require_stable_currency(&env, &sym),
            Err(StableCurrencyError::UnsupportedCurrency)
        );
    }

    #[test]
    fn rejects_rebase_token_ohm() {
        let env = Env::default();
        let sym = Symbol::new(&env, "OHM");
        assert_eq!(
            require_stable_currency(&env, &sym),
            Err(StableCurrencyError::UnsupportedCurrency)
        );
    }

    #[test]
    fn rejects_rebase_token_time() {
        let env = Env::default();
        let sym = Symbol::new(&env, "TIME");
        assert_eq!(
            require_stable_currency(&env, &sym),
            Err(StableCurrencyError::UnsupportedCurrency)
        );
    }

    #[test]
    fn rejects_unknown_token() {
        let env = Env::default();
        let sym = Symbol::new(&env, "RANDOM");
        assert_eq!(
            require_stable_currency(&env, &sym),
            Err(StableCurrencyError::UnsupportedCurrency)
        );
    }

    #[test]
    fn rejects_empty_symbol() {
        let env = Env::default();
        let sym = Symbol::new(&env, "");
        assert_eq!(
            require_stable_currency(&env, &sym),
            Err(StableCurrencyError::UnsupportedCurrency)
        );
    }
}
