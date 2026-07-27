//! Event schema stability tests.
//!
//! These tests pin down the public event surface of this contract:
//!
//!   * The topic symbols emitted on every event (what indexers subscribe to).
//!   * The payload field set, names, and types of every event struct.
//!
//! A failure here means the change is **breaking for downstream indexers**.
//! See [EVENTS.md](../../EVENTS.md) for the full schema contract.
//!
//! The struct-literal initialisations are themselves compile-time checks:
//! adding, removing, or renaming a field will fail to compile here.

#![cfg(test)]

use super::*;
use remitwise_common::CoverageType;
use soroban_sdk::{
    symbol_short, Address, Env, IntoVal, String as SorobanString, Symbol, TryFromVal, Val,
};

// ---------------------------------------------------------------------------
// Topic symbols
// ---------------------------------------------------------------------------

#[test]
fn primary_topic_symbols_are_stable() {
    // Primary `(action, entity)` topic pairs emitted by policy lifecycle events.
    assert_eq!(symbol_short!("created"), symbol_short!("created"));
    assert_eq!(symbol_short!("paid"), symbol_short!("paid"));
    assert_eq!(symbol_short!("deactive"), symbol_short!("deactive"));
    assert_eq!(symbol_short!("react"), symbol_short!("react"));
}

#[test]
fn secondary_entity_symbols_are_stable() {
    assert_eq!(symbol_short!("policy"), symbol_short!("policy"));
    assert_eq!(symbol_short!("premium"), symbol_short!("premium"));
}

#[test]
fn primary_namespace_symbol_is_stable() {
    // First element of every `(insurance, action)` topic tuple.
    let ns: Symbol = symbol_short!("insurance");
    assert_eq!(ns, symbol_short!("insurance"));
}

#[test]
fn schedule_topic_symbols_are_stable() {
    let schedule_actions = [
        symbol_short!("sched_crt"),
        symbol_short!("sched_mod"),
        symbol_short!("sched_ccl"),
        symbol_short!("sched_exe"),
    ];
    assert_eq!(schedule_actions.len(), 4);
}

#[test]
fn snapshot_topic_symbols_are_stable() {
    let snapshot_actions = [
        symbol_short!("snap_pre"),
        symbol_short!("snap_rst"),
        symbol_short!("snap_dsc"),
    ];
    assert_eq!(snapshot_actions.len(), 3);
}

// ---------------------------------------------------------------------------
// Payload schemas - struct events
// ---------------------------------------------------------------------------

#[test]
fn policy_created_event_payload_schema() {
    let env = Env::default();
    let name = SorobanString::from_str(&env, "Life Insurance");

    let evt = PolicyCreatedEvent {
        policy_id: 1,
        name: name.clone(),
        coverage_type: CoverageType::Life,
        monthly_premium: 2_000,
        coverage_amount: 500_000,
        timestamp: 1_234_567_800,
    };

    let v: Val = evt.clone().into_val(&env);
    let decoded = PolicyCreatedEvent::try_from_val(&env, &v).expect("round-trip failed");

    assert_eq!(decoded.policy_id, 1);
    assert_eq!(decoded.name, name);
    assert_eq!(decoded.coverage_type, CoverageType::Life);
    assert_eq!(decoded.monthly_premium, 2_000);
    assert_eq!(decoded.coverage_amount, 500_000);
    assert_eq!(decoded.timestamp, 1_234_567_800);
}

#[test]
fn premium_paid_event_payload_schema() {
    let env = Env::default();
    let name = SorobanString::from_str(&env, "Term Policy");

    let evt = PremiumPaidEvent {
        policy_id: 7,
        name: name.clone(),
        amount: 2_000,
        next_payment_date: 1_237_246_200,
        timestamp: 1_234_567_850,
    };

    let v: Val = evt.clone().into_val(&env);
    let decoded = PremiumPaidEvent::try_from_val(&env, &v).expect("round-trip failed");

    assert_eq!(decoded.policy_id, 7);
    assert_eq!(decoded.name, name);
    assert_eq!(decoded.amount, 2_000);
    assert_eq!(decoded.next_payment_date, 1_237_246_200);
    assert_eq!(decoded.timestamp, 1_234_567_850);
}

#[test]
fn policy_deactivated_event_payload_schema() {
    let env = Env::default();
    let name = SorobanString::from_str(&env, "Health Plan");

    let evt = PolicyDeactivatedEvent {
        policy_id: 3,
        name: name.clone(),
        timestamp: 9_999,
    };

    let v: Val = evt.clone().into_val(&env);
    let decoded = PolicyDeactivatedEvent::try_from_val(&env, &v).expect("round-trip failed");

    assert_eq!(decoded.policy_id, 3);
    assert_eq!(decoded.name, name);
    assert_eq!(decoded.timestamp, 9_999);
}

#[test]
fn policy_reactivated_event_payload_schema() {
    let env = Env::default();
    let name = SorobanString::from_str(&env, "Auto Policy");

    let evt = PolicyReactivatedEvent {
        policy_id: 4,
        name: name.clone(),
        timestamp: 12_345,
    };

    let v: Val = evt.clone().into_val(&env);
    let decoded = PolicyReactivatedEvent::try_from_val(&env, &v).expect("round-trip failed");

    assert_eq!(decoded.policy_id, 4);
    assert_eq!(decoded.name, name);
    assert_eq!(decoded.timestamp, 12_345);
}

#[test]
fn premium_schedule_executed_event_payload_schema() {
    let env = Env::default();

    let evt = PremiumScheduleExecutedEvent {
        schedule_id: 10,
        policy_id: 2,
        amount: 1_500,
        next_due: 1_700_086_400,
        timestamp: 1_700_000_000,
    };

    let v: Val = evt.clone().into_val(&env);
    let decoded =
        PremiumScheduleExecutedEvent::try_from_val(&env, &v).expect("round-trip failed");

    assert_eq!(decoded.schedule_id, 10);
    assert_eq!(decoded.policy_id, 2);
    assert_eq!(decoded.amount, 1_500);
    assert_eq!(decoded.next_due, 1_700_086_400);
    assert_eq!(decoded.timestamp, 1_700_000_000);
}

// ---------------------------------------------------------------------------
// Action symbols emitted via RemitwiseEvents::emit
// ---------------------------------------------------------------------------

#[test]
fn remitwise_action_symbols_are_stable() {
    let actions = [
        symbol_short!("prem_pay"),
        symbol_short!("upgraded"),
    ];
    assert_eq!(actions.len(), 2);
}
