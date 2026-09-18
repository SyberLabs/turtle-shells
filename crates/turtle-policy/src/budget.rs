//! Simulated cumulative domain budgets. Occupancy limits are not reserved here.

use std::collections::HashMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::grant::DomainBudgets;
use crate::ids::OperationKey;
use crate::reason::{Denial, ReasonCode};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BudgetMetric {
    ProviderAttempts,
    ExternalMutations,
    InferenceOutputTokens,
    OutboundPayloadBytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reservation {
    pub operation_key: OperationKey,
    pub amount: u64,
    pub metric: BudgetMetric,
}

#[derive(Debug)]
struct Inner {
    ceilings: DomainBudgets,
    reserved: HashMap<BudgetMetric, u64>,
    spent: HashMap<BudgetMetric, u64>,
    by_key: HashMap<(String, BudgetMetric), u64>,
}

#[derive(Debug)]
pub struct BudgetLedger {
    inner: Mutex<Inner>,
}

impl BudgetLedger {
    pub fn new(ceilings: DomainBudgets) -> Self {
        Self {
            inner: Mutex::new(Inner {
                ceilings,
                reserved: HashMap::new(),
                spent: HashMap::new(),
                by_key: HashMap::new(),
            }),
        }
    }

    pub fn try_reserve(
        &self,
        metric: BudgetMetric,
        amount: u64,
        operation_key: &OperationKey,
    ) -> Result<Reservation, Denial> {
        if amount == 0 {
            return Ok(Reservation {
                operation_key: operation_key.clone(),
                amount: 0,
                metric,
            });
        }
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = (operation_key.as_str().to_string(), metric);
        if let Some(existing) = inner.by_key.get(&key) {
            return Ok(Reservation {
                operation_key: operation_key.clone(),
                amount: *existing,
                metric,
            });
        }
        let ceiling = ceiling(&inner.ceilings, metric);
        let spent = *inner.spent.get(&metric).unwrap_or(&0);
        let reserved = *inner.reserved.get(&metric).unwrap_or(&0);
        if spent.saturating_add(reserved).saturating_add(amount) > ceiling {
            return Err(Denial::new(
                ReasonCode::EBudget,
                "shared domain budget exhausted",
            ));
        }
        inner.by_key.insert(key, amount);
        *inner.reserved.entry(metric).or_insert(0) += amount;
        Ok(Reservation {
            operation_key: operation_key.clone(),
            amount,
            metric,
        })
    }

    pub fn spent(&self, metric: BudgetMetric) -> u64 {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *inner.spent.get(&metric).unwrap_or(&0)
    }

    pub fn reserved(&self, metric: BudgetMetric) -> u64 {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *inner.reserved.get(&metric).unwrap_or(&0)
    }
}

fn ceiling(domain: &DomainBudgets, metric: BudgetMetric) -> u64 {
    match metric {
        BudgetMetric::ProviderAttempts => domain.provider_attempts,
        BudgetMetric::ExternalMutations => domain.external_mutations,
        BudgetMetric::InferenceOutputTokens => domain.inference_output_tokens,
        BudgetMetric::OutboundPayloadBytes => domain.outbound_payload_bytes,
    }
}
