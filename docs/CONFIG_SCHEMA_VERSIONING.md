# Configuration Schema Versioning

How we bump configuration schema versions.

## Overview

When the data structure of a contract configuration changes, we must ensure backward compatibility for existing data, or implement a migration path. This document defines the protocol for bumping schema versions.

## Protocol

1. **Versioning in Structure**: Configuration structs should contain a `version: u32` field (or be versioned by suffix).
2. **Migration Entrypoint**: Contracts must implement a `migrate_config` entrypoint (or similar, if applicable) if a breaking change is introduced, or handle it via a `set_config` call that accepts the new version.
3. **Compatibility**: Maintain stability for older versions where possible.

## Example: Bumping a Config Struct

### Original Version (`v1`)

```rust
// In remittance_split/src/lib.rs

#[derive(Clone, Debug, PartialEq, Eq, soroban_sdk::ContractType)]
pub struct SplitConfig {
    pub owner: Address,
    pub spending_percent: u32,
    pub savings_percent: u32,
    pub bills_percent: u32,
    pub insurance_percent: u32,
}
```

### New Version (`v2`)

Add a new field, e.g., `max_transfer_limit`.

```rust
// In remittance_split/src/lib.rs

#[derive(Clone, Debug, PartialEq, Eq, soroban_sdk::ContractType)]
pub struct SplitConfigV2 {
    pub owner: Address,
    pub spending_percent: u32,
    pub savings_percent: u32,
    pub bills_percent: u32,
    pub insurance_percent: u32,
    pub max_transfer_limit: i128, // New field
}
```

### Migration

1. Rename the original struct or add a `V2` suffix.
2. Update the contract's storage key or `set_config` to accept `SplitConfigV2`.
3. If necessary, provide a migration script that reads `SplitConfig` (v1) and writes `SplitConfigV2` (v2) with default values for new fields.

```rust
// Example migration logic (simplified)

pub fn migrate_config(env: Env) {
    let old_config: SplitConfig = env.storage().instance().get(&STORAGE_KEY_CONFIG).unwrap();
    let new_config = SplitConfigV2 {
        owner: old_config.owner,
        spending_percent: old_config.spending_percent,
        savings_percent: old_config.savings_percent,
        bills_percent: old_config.bills_percent,
        insurance_percent: old_config.insurance_percent,
        max_transfer_limit: 1000_000_000, // Default value for v2
    };
    env.storage().instance().set(&STORAGE_KEY_CONFIG, &new_config);
}
```

## Reviewer Checklist

- [ ] Does the new schema introduce breaking changes?
- [ ] Is there an explicit migration path?
- [ ] Have test cases been updated to cover v1 -> v2 migration?
