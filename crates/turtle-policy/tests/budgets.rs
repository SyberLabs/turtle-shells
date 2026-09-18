use std::sync::{Arc, Barrier};
use std::thread;

use turtle_policy::budget::{BudgetLedger, BudgetMetric};
use turtle_policy::grant::DomainBudgets;
use turtle_policy::ids::OperationKey;

fn ceilings(provider_attempts: u64) -> DomainBudgets {
    DomainBudgets {
        provider_attempts,
        external_mutations: 0,
        inference_output_tokens: 0,
        outbound_payload_bytes: 0,
        memory_mib: Some(64),
        pids: Some(8),
        cpu_millis_per_second: Some(100),
    }
}

#[test]
fn last_unit_has_exactly_one_winner() {
    for trial in 0..20 {
        let ledger = Arc::new(BudgetLedger::new(ceilings(1)));
        let barrier = Arc::new(Barrier::new(2));
        let mut joins = Vec::new();
        for i in 0..2 {
            let ledger = Arc::clone(&ledger);
            let barrier = Arc::clone(&barrier);
            joins.push(thread::spawn(move || {
                barrier.wait();
                let key = OperationKey::new(format!("op-{trial}-{i}")).unwrap();
                ledger.try_reserve(BudgetMetric::ProviderAttempts, 1, &key)
            }));
        }
        let results: Vec<_> = joins.into_iter().map(|j| j.join().unwrap()).collect();
        let wins = results.iter().filter(|r| r.is_ok()).count();
        let losses = results.iter().filter(|r| r.is_err()).count();
        assert_eq!(wins, 1, "trial {trial} wins={wins}");
        assert_eq!(losses, 1, "trial {trial} losses={losses}");
    }
}

#[test]
fn retry_same_key_does_not_double_charge() {
    let ledger = BudgetLedger::new(ceilings(1));
    let key = OperationKey::new("op-retry").unwrap();
    ledger
        .try_reserve(BudgetMetric::ProviderAttempts, 1, &key)
        .unwrap();
    ledger
        .try_reserve(BudgetMetric::ProviderAttempts, 1, &key)
        .unwrap();
    assert_eq!(ledger.reserved(BudgetMetric::ProviderAttempts), 1);
}

#[test]
fn new_operation_key_does_not_reset_ceiling() {
    let ledger = BudgetLedger::new(ceilings(1));
    ledger
        .try_reserve(
            BudgetMetric::ProviderAttempts,
            1,
            &OperationKey::new("op-a").unwrap(),
        )
        .unwrap();
    let err = ledger
        .try_reserve(
            BudgetMetric::ProviderAttempts,
            1,
            &OperationKey::new("op-b").unwrap(),
        )
        .unwrap_err();
    assert_eq!(err.code, turtle_policy::ReasonCode::EBudget);
}

#[test]
fn terminated_sibling_does_not_replenish() {
    let ledger = BudgetLedger::new(ceilings(1));
    let reservation = ledger
        .try_reserve(
            BudgetMetric::ProviderAttempts,
            1,
            &OperationKey::new("op-a").unwrap(),
        )
        .unwrap();
    drop(reservation);
    let err = ledger
        .try_reserve(
            BudgetMetric::ProviderAttempts,
            1,
            &OperationKey::new("op-b").unwrap(),
        )
        .unwrap_err();
    assert_eq!(err.code, turtle_policy::ReasonCode::EBudget);
}
