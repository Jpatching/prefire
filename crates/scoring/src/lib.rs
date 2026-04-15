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
///   High-value outflow (10) -- large SOL outflow (>100 SOL)
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

    // Signal 5: Config weakened (max 20 pts)
    // A config change that LOWERS the threshold or REMOVES the timelock
    // is a setup-phase signal. Drift's March 27 migration removed the
    // timelock -- this signal would have caught it 5 days before execution.
    if let Some(ref delta) = enriched.config_delta {
        if delta.is_weakened() {
            let mut parts = Vec::new();
            if let Some((old, new)) = delta.threshold_changed {
                if new < old {
                    parts.push(format!("threshold lowered from {} to {}", old, new));
                }
            }
            if let Some((old, new)) = delta.timelock_changed {
                if new < old {
                    parts.push(format!("timelock reduced from {}s to {}s", old, new));
                }
            }
            signals.push(Signal {
                name: "config_weakened",
                score: 20,
                reason: format!(
                    "governance config weakened: {}",
                    parts.join(", ")
                ),
            });
        }
    }

    // Signal 6: Nonce accounts meet threshold (max 25 pts)
    // When enough multisig members have durable nonce accounts to meet
    // the signing threshold, pre-signed transactions can be executed
    // without other members' knowledge. This is the Drift nonce setup
    // pattern (March 23-30).
    if enriched.nonce_threshold_met {
        signals.push(Signal {
            name: "nonce_threshold_met",
            score: 25,
            reason: "members with durable nonce accounts can meet signing threshold \
                     — pre-signed transactions may exist"
                .to_string(),
        });
    }

    // Signal 7: High-value SOL outflow (max 10 pts)
    // Fires when a single account loses >100 SOL in the transaction.
    // Only populated in replay/API paths (live mode has no balance data).
    // Negative value = outflow. 100 SOL = 100_000_000_000 lamports.
    if enriched.sol_outflow_lamports < -100_000_000_000 {
        signals.push(Signal {
            name: "high_value_outflow",
            score: 10,
            reason: format!(
                "large SOL outflow: {} SOL drained from a single account",
                enriched.sol_outflow_lamports.abs() / 1_000_000_000
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

// --- Governance health score (prevention layer) ---

use prefire_enrichment::multisig::MultisigConfig;

/// A risk factor found in the multisig configuration.
#[derive(Debug, Clone, Serialize)]
pub struct Risk {
    pub name: &'static str,
    pub deduction: u8,
    pub reason: String,
}

/// Governance health assessment for a multisig configuration.
/// Higher score = healthier configuration. Lower = more vulnerable.
#[derive(Debug, Clone, Serialize)]
pub struct HealthScore {
    pub total: u8,
    pub risks: Vec<Risk>,
    pub recommendations: Vec<String>,
}

/// Assess a multisig's governance configuration health.
/// Starts at 100 and deducts points for each risk factor.
///
/// This is the PREVENTION layer. It tells teams "you're vulnerable to a
/// Drift-style attack" BEFORE any attack happens. The attack detection
/// (score/score_with_context) is the DETECTION layer -- it fires during
/// an attack. This function fires BEFORE.
pub fn governance_health(config: &MultisigConfig) -> HealthScore {
    let mut risks = Vec::new();
    let mut recommendations = Vec::new();
    // Start at 100 (perfect health) and deduct for each risk.
    // u8 can't go negative, so we track deductions as u16 then clamp.
    let mut deductions: u16 = 0;

    // Risk 1: Zero timelock (-40)
    // The single biggest factor in the Drift exploit. With a timelock,
    // other members have time to notice and veto malicious proposals.
    if config.time_lock == 0 {
        let d = 40;
        risks.push(Risk {
            name: "zero_timelock",
            deduction: d,
            reason: "no delay between proposal approval and execution".to_string(),
        });
        recommendations.push(
            "Add a timelock (recommended: 86400s / 24 hours) to give other members \
             time to review and veto proposals before execution"
                .to_string(),
        );
        deductions += d as u16;
    }

    // Risk 2: Low threshold ratio (-25)
    // threshold / member_count < 0.5 means less than half of members
    // need to approve. Drift was 2/5 = 0.4. Easier to compromise.
    // We use integer math to avoid floating point: threshold * 2 < member_count
    if config.member_count > 0
        && (config.threshold as usize).checked_mul(2).unwrap_or(0) < config.member_count
    {
        let d = 25;
        // checked_add on the ratio numerator: threshold * 100 / member_count
        let pct = (config.threshold as usize)
            .checked_mul(100)
            .and_then(|n| n.checked_div(config.member_count))
            .unwrap_or(0);
        risks.push(Risk {
            name: "low_threshold_ratio",
            deduction: d,
            reason: format!(
                "threshold is {}% of members ({}/{}) — less than majority required to approve",
                pct, config.threshold, config.member_count
            ),
        });
        recommendations.push(format!(
            "Increase threshold to at least {}/{} (>50%) so a majority of members must approve",
            config.member_count / 2 + 1,
            config.member_count
        ));
        deductions += d as u16;
    }

    // Risk 3: Threshold of 1 (-20)
    // Any single member can act alone. Zero redundancy.
    if config.threshold <= 1 && config.member_count > 1 {
        let d = 20;
        risks.push(Risk {
            name: "single_signer_threshold",
            deduction: d,
            reason: format!(
                "threshold=1 on a {}-member multisig — any single member can act alone",
                config.member_count
            ),
        });
        recommendations.push(
            "Increase threshold to at least 2 to require multiple approvals".to_string(),
        );
        deductions += d as u16;
    }

    // Risk 4: Compound risk — zero timelock + low threshold (-15 bonus)
    // This is the EXACT Drift configuration. Flag it explicitly.
    if config.time_lock == 0 && config.threshold < 3 && config.member_count >= 3 {
        let d = 15;
        risks.push(Risk {
            name: "drift_pattern",
            deduction: d,
            reason: format!(
                "zero timelock + threshold={} matches the Drift exploit configuration \
                 ($285M stolen April 2026)",
                config.threshold
            ),
        });
        recommendations.push(
            "This is the exact configuration exploited in the Drift Protocol attack. \
             Priority: add timelock AND increase threshold"
                .to_string(),
        );
        deductions += d as u16;
    }

    // Clamp: score can't go below 0
    let total = 100u16.saturating_sub(deductions).min(100) as u8;

    HealthScore {
        total,
        risks,
        recommendations,
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

// --- Tests ---
// #[cfg(test)] means this entire module is only compiled during `cargo test`.
// Tests can access all items in the parent module (even private ones)
// because they're in the same crate.

#[cfg(test)]
mod tests {
    use super::*;
    use prefire_enrichment::multisig::MultisigConfig;
    use prefire_monitor::governance::{GovernanceEvent, MonitoredEvent};

    /// Helper: build a synthetic MonitoredEvent for testing.
    /// We don't need real RPC data -- we construct the struct directly.
    fn make_event(event: GovernanceEvent, uses_nonce: bool) -> EnrichedEvent {
        let account_keys = vec![Pubkey::new_unique()]; // signer
        if uses_nonce {
            // Add the RecentBlockhashes sysvar to simulate nonce usage.
            // In production, the enrichment crate detects this from real tx data.
            // In tests, we just set the flag directly.
        }

        EnrichedEvent {
            event: MonitoredEvent {
                signature: "test_sig".to_string(),
                slot: 1000,
                block_time: Some(1700000000),
                event,
                multisig: Pubkey::new_unique(),
                signers: vec![Pubkey::new_unique()],
                account_keys,
                log_messages: vec![],
                pre_balances: vec![],
                post_balances: vec![],
                pre_token_balances: vec![],
                post_token_balances: vec![],
            },
            multisig_config: Some(MultisigConfig {
                threshold: 2,
                member_count: 5,
                voter_count: 5,
                time_lock: 0,
            }),
            uses_durable_nonce: uses_nonce,
            sol_outflow_lamports: 0,
            token_transfers: vec![],
            config_delta: None,
            nonce_threshold_met: false,
        }
    }

    #[test]
    fn normal_proposal_approve_scores_safe() {
        // A normal ProposalApprove with no nonce should score low.
        // Only zero_timelock fires (+10).
        let enriched = make_event(
            GovernanceEvent::ProposalApproved {
                description: "ProposalApprove".to_string(),
            },
            false,
        );
        let result = score(&enriched);
        assert_eq!(result.verdict, Verdict::Safe);
        assert!(result.total <= 20, "normal approve scored {}", result.total);
    }

    #[test]
    fn durable_nonce_vault_transfer_scores_suspicious() {
        // Durable nonce (+30) + zero timelock (+10) + vault transfer (+10) = 50
        let enriched = make_event(
            GovernanceEvent::VaultTransfer {
                description: "VaultTransactionCreate".to_string(),
            },
            true,
        );
        let result = score(&enriched);
        assert_eq!(result.total, 50);
        assert_eq!(result.verdict, Verdict::Suspicious);
    }

    #[test]
    fn nonce_plus_rapid_governance_scores_critical() {
        // Simulate the Drift attack sequence:
        // ProposalCreated at T=0, ProposalApproved at T=0 (same second)
        let multisig = Pubkey::new_unique();

        let create_event = EnrichedEvent {
            event: MonitoredEvent {
                signature: "tx1".to_string(),
                slot: 1000,
                block_time: Some(1700000000),
                event: GovernanceEvent::ProposalCreated {
                    description: "ProposalCreate".to_string(),
                },
                multisig,
                signers: vec![],
                account_keys: vec![],
                log_messages: vec![],
                pre_balances: vec![],
                post_balances: vec![],
                pre_token_balances: vec![],
                post_token_balances: vec![],
            },
            multisig_config: Some(MultisigConfig {
                threshold: 2,
                member_count: 5,
                voter_count: 5,
                time_lock: 0,
            }),
            uses_durable_nonce: true,
            sol_outflow_lamports: 0,
            token_transfers: vec![],
            config_delta: None,
            nonce_threshold_met: false,
        };

        let approve_event = EnrichedEvent {
            event: MonitoredEvent {
                signature: "tx1".to_string(),
                slot: 1000,
                block_time: Some(1700000000), // same second!
                event: GovernanceEvent::ProposalApproved {
                    description: "ProposalApprove".to_string(),
                },
                multisig, // same multisig -- temporal tracking works
                signers: vec![],
                account_keys: vec![],
                log_messages: vec![],
                pre_balances: vec![],
                post_balances: vec![],
                pre_token_balances: vec![],
                post_token_balances: vec![],
            },
            multisig_config: Some(MultisigConfig {
                threshold: 2,
                member_count: 5,
                voter_count: 5,
                time_lock: 0,
            }),
            uses_durable_nonce: true,
            sol_outflow_lamports: 0,
            token_transfers: vec![],
            config_delta: None,
            nonce_threshold_met: false,
        };

        let mut ctx = ScoringContext::new();
        // First event: create. Scores 40 (nonce + timelock).
        let r1 = score_with_context(&create_event, &mut ctx);
        assert_eq!(r1.total, 40);

        // Second event: approve. Now rapid_governance fires (+25).
        // nonce(30) + timelock(10) + rapid(25) = 65
        let r2 = score_with_context(&approve_event, &mut ctx);
        assert_eq!(r2.total, 65);
        assert_eq!(r2.verdict, Verdict::Critical);
    }

    #[test]
    fn verdict_boundaries() {
        // Verify the exact boundary values
        assert_eq!(
            match 30u8 {
                0..=30 => Verdict::Safe,
                31..=60 => Verdict::Suspicious,
                _ => Verdict::Critical,
            },
            Verdict::Safe
        );
        assert_eq!(
            match 31u8 {
                0..=30 => Verdict::Safe,
                31..=60 => Verdict::Suspicious,
                _ => Verdict::Critical,
            },
            Verdict::Suspicious
        );
        assert_eq!(
            match 61u8 {
                0..=30 => Verdict::Safe,
                31..=60 => Verdict::Suspicious,
                _ => Verdict::Critical,
            },
            Verdict::Critical
        );
    }

    // --- Governance health score tests ---

    #[test]
    fn drift_config_scores_poorly() {
        // Drift's config: threshold=2, members=5, timelock=0
        let config = MultisigConfig {
            threshold: 2,
            member_count: 5,
            voter_count: 5,
            time_lock: 0,
        };
        let health = governance_health(&config);
        // Should deduct: zero_timelock(-40) + low_ratio(-25) + drift_pattern(-15) = 80
        // Score: 100 - 80 = 20
        assert_eq!(health.total, 20);
        assert!(health.risks.len() >= 3);
        assert!(!health.recommendations.is_empty());
    }

    #[test]
    fn healthy_config_scores_well() {
        // Good config: threshold=4, members=7, timelock=86400 (24h)
        let config = MultisigConfig {
            threshold: 4,
            member_count: 7,
            voter_count: 7,
            time_lock: 86400,
        };
        let health = governance_health(&config);
        // No risks should fire: 4/7 > 50%, timelock > 0, threshold > 1
        assert_eq!(health.total, 100);
        assert!(health.risks.is_empty());
    }

    #[test]
    fn single_signer_multisig_scores_very_poorly() {
        let config = MultisigConfig {
            threshold: 1,
            member_count: 5,
            voter_count: 5,
            time_lock: 0,
        };
        let health = governance_health(&config);
        // zero_timelock(-40) + low_ratio(-25) + single_signer(-20) + drift_pattern(-15) = 100
        assert_eq!(health.total, 0);
    }

    // --- New signal tests ---

    #[test]
    fn config_weakened_fires_on_threshold_lowered() {
        use prefire_enrichment::multisig::ConfigDelta;

        let mut enriched = make_event(
            GovernanceEvent::ConfigChange {
                description: "ConfigMemberRemove".to_string(),
            },
            false,
        );
        enriched.config_delta = Some(ConfigDelta {
            threshold_changed: Some((3, 2)),
            timelock_changed: None,
            members_added: 0,
            members_removed: 1,
        });

        let result = score(&enriched);
        let has_weakened = result.signals.iter().any(|s| s.name == "config_weakened");
        assert!(has_weakened, "config_weakened should fire when threshold lowered");
        // config_change(15) + config_weakened(20) + zero_timelock(10) = 45
        assert_eq!(result.total, 45);
        assert_eq!(result.verdict, Verdict::Suspicious);
    }

    #[test]
    fn config_weakened_fires_on_timelock_removed() {
        use prefire_enrichment::multisig::ConfigDelta;

        let mut enriched = make_event(
            GovernanceEvent::ConfigChange {
                description: "ConfigChangeTimelock".to_string(),
            },
            false,
        );
        enriched.config_delta = Some(ConfigDelta {
            threshold_changed: None,
            timelock_changed: Some((86400, 0)),
            members_added: 0,
            members_removed: 0,
        });

        let result = score(&enriched);
        let has_weakened = result.signals.iter().any(|s| s.name == "config_weakened");
        assert!(has_weakened, "config_weakened should fire when timelock removed");
    }

    #[test]
    fn config_strengthened_does_not_fire() {
        use prefire_enrichment::multisig::ConfigDelta;

        let mut enriched = make_event(
            GovernanceEvent::ConfigChange {
                description: "ConfigChangeThreshold".to_string(),
            },
            false,
        );
        // Threshold RAISED = good change, should NOT fire config_weakened
        enriched.config_delta = Some(ConfigDelta {
            threshold_changed: Some((2, 4)),
            timelock_changed: None,
            members_added: 0,
            members_removed: 0,
        });

        let result = score(&enriched);
        let has_weakened = result.signals.iter().any(|s| s.name == "config_weakened");
        assert!(!has_weakened, "config_weakened should NOT fire when threshold raised");
    }

    #[test]
    fn nonce_threshold_met_fires() {
        let mut enriched = make_event(
            GovernanceEvent::ProposalCreated {
                description: "ProposalCreate".to_string(),
            },
            true,
        );
        enriched.nonce_threshold_met = true;

        let result = score(&enriched);
        let has_signal = result.signals.iter().any(|s| s.name == "nonce_threshold_met");
        assert!(has_signal, "nonce_threshold_met should fire");
        // durable_nonce(30) + zero_timelock(10) + nonce_threshold_met(25) = 65
        assert_eq!(result.total, 65);
        assert_eq!(result.verdict, Verdict::Critical);
    }

    #[test]
    fn nonce_threshold_not_met_does_not_fire() {
        let enriched = make_event(
            GovernanceEvent::ProposalCreated {
                description: "ProposalCreate".to_string(),
            },
            true,
        );
        // nonce_threshold_met defaults to false in make_event

        let result = score(&enriched);
        let has_signal = result.signals.iter().any(|s| s.name == "nonce_threshold_met");
        assert!(!has_signal);
    }

    #[test]
    fn high_value_outflow_fires_on_large_drain() {
        let mut enriched = make_event(
            GovernanceEvent::VaultTransfer {
                description: "VaultTransactionExecute".to_string(),
            },
            true,
        );
        // Simulate 500 SOL drained (negative = outflow)
        enriched.sol_outflow_lamports = -500_000_000_000;

        let result = score(&enriched);
        let has_outflow = result.signals.iter().any(|s| s.name == "high_value_outflow");
        assert!(has_outflow, "high_value_outflow should fire on 500 SOL drain");
        // durable_nonce(30) + zero_timelock(10) + vault_transfer(10) + high_value_outflow(10) = 60
        assert_eq!(result.total, 60);
        assert_eq!(result.verdict, Verdict::Suspicious);
    }

    #[test]
    fn small_outflow_does_not_fire() {
        let mut enriched = make_event(
            GovernanceEvent::VaultTransfer {
                description: "VaultTransactionExecute".to_string(),
            },
            false,
        );
        // 5 SOL outflow -- below 100 SOL threshold
        enriched.sol_outflow_lamports = -5_000_000_000;

        let result = score(&enriched);
        let has_outflow = result.signals.iter().any(|s| s.name == "high_value_outflow");
        assert!(!has_outflow, "high_value_outflow should NOT fire on 5 SOL");
    }
}
