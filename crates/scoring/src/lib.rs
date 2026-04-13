use serde::Serialize;

use prefire_enrichment::EnrichedEvent;
use prefire_monitor::governance::GovernanceEvent;

/// Individual signal that contributed to the threat score.
#[derive(Debug, Clone, Serialize)]
pub struct Signal {
    pub name: &'static str,
    pub score: u8,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum Verdict {
    Safe,       // 0-30
    Suspicious, // 31-60
    Critical,   // 61-100
}

/// Threat assessment for a governance event.
#[derive(Debug, Clone, Serialize)]
pub struct ThreatScore {
    pub total: u8,
    pub signals: Vec<Signal>,
    pub verdict: Verdict,
}

/// Score an enriched governance event. Returns 0-100 with signal breakdown.
///
/// Design principle: individual signals are weak risk factors. The score only
/// climbs into SUSPICIOUS/CRITICAL when multiple signals combine. This avoids
/// false positives on normal governance activity.
///
/// Signals and max points:
///   Durable nonce (30) -- pre-signed transaction, strongest attack indicator
///   Zero timelock (10) -- risk factor, not attack indicator alone
///   Config change (15) -- membership or threshold modification
///   Vault transfer (10) -- fund movement event
///   Rapid governance (25) -- temporal, requires ScoringContext
///   High-value outflow (10) -- large SOL/token drain (future)
///
/// Removed: "single_signer" -- every Squads tx has 1 signer because each
/// member approves in a separate tx. It always fires. Useless.
pub fn score(enriched: &EnrichedEvent) -> ThreatScore {
    let mut signals = Vec::new();

    // Signal 1: Durable nonce usage (max 30 pts) -- strongest standalone signal
    // Pre-signed transactions are unusual for normal governance and are a
    // hallmark of coordinated attacks (sign days ahead, execute instantly)
    if enriched.uses_durable_nonce {
        signals.push(Signal {
            name: "durable_nonce",
            score: 30,
            reason: "transaction uses AdvanceNonceAccount — may have been pre-signed".to_string(),
        });
    }

    // Signal 2: Zero timelock on a multi-signer multisig (max 10 pts)
    // Risk factor: no delay between approval and execution.
    // Many legit multisigs have zero timelock, so this is a mild signal.
    if let Some(ref config) = enriched.multisig_config {
        if config.time_lock == 0 && config.threshold >= 2 {
            signals.push(Signal {
                name: "zero_timelock",
                score: 10,
                reason: format!(
                    "threshold={} but time_lock=0 — no delay between approval and execution",
                    config.threshold
                ),
            });
        }
    }

    // Signal 3: Config change event (max 15 pts)
    // Higher than vault_transfer because config changes (add member, lower
    // threshold) are the setup phase of a takeover attack.
    if matches!(enriched.event.event, GovernanceEvent::ConfigChange { .. }) {
        signals.push(Signal {
            name: "config_change",
            score: 15,
            reason: format!(
                "config change detected: {}",
                event_description(&enriched.event.event)
            ),
        });
    }

    // Signal 4: Vault transfer event (max 10 pts)
    // Fund movement is the goal of most attacks, but routine vault
    // transfers are normal. This is a component signal.
    if matches!(enriched.event.event, GovernanceEvent::VaultTransfer { .. }) {
        signals.push(Signal {
            name: "vault_transfer",
            score: 10,
            reason: format!(
                "vault transfer detected: {}",
                event_description(&enriched.event.event)
            ),
        });
    }

    let total: u16 = signals.iter().map(|s| s.score as u16).sum();
    let total = total.min(100) as u8;

    let verdict = match total {
        0..=30 => Verdict::Safe,
        31..=60 => Verdict::Suspicious,
        _ => Verdict::Critical,
    };

    ThreatScore {
        total,
        signals,
        verdict,
    }
}

/// Extract the description string from a GovernanceEvent variant.
fn event_description(event: &GovernanceEvent) -> &str {
    match event {
        GovernanceEvent::ProposalCreated { description } => description,
        GovernanceEvent::ProposalApproved { description } => description,
        GovernanceEvent::ProposalActivated { description } => description,
        GovernanceEvent::ConfigChange { description } => description,
        GovernanceEvent::VaultTransfer { description } => description,
    }
}

// --- Temporal correlation (tracks event sequences per multisig) ---

use std::collections::{HashMap, VecDeque};
use solana_sdk::pubkey::Pubkey;

/// Tracks recent events per multisig for temporal pattern detection.
/// The rapid governance signal fires when create → approve → execute
/// happens within a short window.
pub struct ScoringContext {
    /// Recent events per multisig, ordered by block_time.
    recent: HashMap<Pubkey, VecDeque<(GovernanceEvent, i64)>>,
    /// Maximum age of events to keep (seconds).
    max_age_secs: i64,
}

impl ScoringContext {
    pub fn new() -> Self {
        Self {
            recent: HashMap::new(),
            max_age_secs: 3600, // 1 hour window
        }
    }

    /// Record an event and check for rapid governance pattern.
    /// Returns additional score points (0 or 25) for rapid governance.
    pub fn check_rapid_governance(&mut self, enriched: &EnrichedEvent) -> Option<Signal> {
        let block_time = enriched.event.block_time?;
        let multisig = enriched.event.multisig;

        // Don't track if multisig is default (unresolved)
        if multisig == Pubkey::default() {
            return None;
        }

        let events = self.recent.entry(multisig).or_default();

        // Evict old entries
        while let Some(front) = events.front() {
            if block_time.checked_sub(front.1).unwrap_or(0) > self.max_age_secs {
                events.pop_front();
            } else {
                break;
            }
        }

        // Add current event
        events.push_back((enriched.event.event.clone(), block_time));

        // Check for rapid governance: create + approve within 10 minutes
        let has_create = events
            .iter()
            .any(|(e, _)| matches!(e, GovernanceEvent::ProposalCreated { .. }));
        let has_approve = events
            .iter()
            .any(|(e, _)| matches!(e, GovernanceEvent::ProposalApproved { .. }));

        if has_create && has_approve {
            let create_time = events
                .iter()
                .filter(|(e, _)| matches!(e, GovernanceEvent::ProposalCreated { .. }))
                .map(|(_, t)| *t)
                .min()?;
            let approve_time = events
                .iter()
                .filter(|(e, _)| matches!(e, GovernanceEvent::ProposalApproved { .. }))
                .map(|(_, t)| *t)
                .max()?;

            let elapsed = approve_time.checked_sub(create_time).unwrap_or(0);
            if elapsed <= 600 {
                // 10 minutes
                return Some(Signal {
                    name: "rapid_governance",
                    score: 25,
                    reason: format!(
                        "proposal created and approved within {} seconds",
                        elapsed
                    ),
                });
            }
        }

        None
    }
}

/// Score with temporal context. Use this for batch replay or live monitoring
/// where you're processing a stream of events.
pub fn score_with_context(
    enriched: &EnrichedEvent,
    ctx: &mut ScoringContext,
) -> ThreatScore {
    let mut result = score(enriched);

    if let Some(rapid_signal) = ctx.check_rapid_governance(enriched) {
        result.total = (result.total as u16 + rapid_signal.score as u16).min(100) as u8;
        result.signals.push(rapid_signal);
        // Recalculate verdict
        result.verdict = match result.total {
            0..=30 => Verdict::Safe,
            31..=60 => Verdict::Suspicious,
            _ => Verdict::Critical,
        };
    }

    result
}
