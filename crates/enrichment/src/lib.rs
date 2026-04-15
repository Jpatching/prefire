pub mod multisig;
pub mod nonce;
pub mod snapshot;
pub mod token;

use std::str::FromStr;
use std::sync::Arc;

use serde::Serialize;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use thiserror::Error;

use prefire_monitor::governance::MonitoredEvent;
use prefire_monitor::rpc::SQUADS_PROGRAM_ID;

use crate::multisig::{ConfigDelta, MultisigConfig, MultisigError};
use crate::token::TokenTransferInfo;

#[derive(Debug, Clone, Serialize)]
pub struct EnrichedEvent {
    pub event: MonitoredEvent,
    pub multisig_config: Option<MultisigConfig>,
    pub uses_durable_nonce: bool,
    pub sol_outflow_lamports: i128,
    pub token_transfers: Vec<TokenTransferInfo>,
    /// Set when a ConfigChange event is detected and we can compare to previous config.
    pub config_delta: Option<ConfigDelta>,
    /// True when members with nonce accounts >= multisig threshold.
    /// Only populated when nonce scanning is performed (health/scan paths).
    pub nonce_threshold_met: bool,
}

#[derive(Debug, Error)]
pub enum EnrichmentError {
    #[error("rpc error: {0}")]
    Rpc(#[from] solana_client::client_error::ClientError),
    #[error("multisig fetch failed: {0}")]
    Multisig(#[from] MultisigError),
}

/// Enrich a governance event with on-chain context for scoring.
///
/// 1. Identifies the multisig account from transaction account_keys
/// 2. Fetches multisig config (threshold, members, timelock)
/// 3. Checks for durable nonce usage
/// 4. Extracts SOL/token transfer amounts (for replay mode with full tx data)
pub async fn enrich(
    rpc: &Arc<RpcClient>,
    mut event: MonitoredEvent,
) -> Result<EnrichedEvent, EnrichmentError> {
    // Detect durable nonce from account keys (primary) and log messages (fallback)
    let uses_durable_nonce = nonce::uses_durable_nonce(&event.log_messages, &event.account_keys);

    // Try to identify and fetch the multisig account config.
    // Also writes the resolved multisig pubkey back onto the event
    // so ScoringContext can track events per-multisig for temporal signals.
    let multisig_config = match find_multisig_pubkey(rpc, &event.account_keys).await {
        Some(pubkey) => {
            event.multisig = pubkey;
            match multisig::fetch_multisig_config(rpc, &pubkey).await {
                Ok(account) => Some(MultisigConfig::from(&account)),
                Err(e) => {
                    eprintln!("warning: failed to fetch multisig config: {}", e);
                    None
                }
            }
        }
        None => None,
    };

    // Extract SOL and token outflows from pre/post balance data.
    // Only populated when replaying historical transactions (live mode has empty vecs).
    let sol_outflow_lamports = token::sol_outflow_lamports(
        &event.pre_balances,
        &event.post_balances,
    );
    let token_transfers = token::extract_token_transfers(
        &event.pre_token_balances,
        &event.post_token_balances,
    );

    // Compute config delta for ConfigChange events by comparing to stored snapshot.
    // This detects threshold lowered, timelock removed, etc.
    let config_delta = if matches!(
        event.event,
        prefire_monitor::governance::GovernanceEvent::ConfigChange { .. }
    ) {
        if let (Some(ref new_config), multisig) = (&multisig_config, event.multisig) {
            if multisig != Pubkey::default() {
                let previous = snapshot::load_snapshot(&multisig);
                // Save new snapshot for next comparison
                let _ = snapshot::save_snapshot(&multisig, new_config);
                previous.map(|old| ConfigDelta::compare(&old, new_config))
            } else {
                None
            }
        } else {
            None
        }
    } else {
        // For non-ConfigChange events, still update the snapshot if we have
        // a resolved multisig so the baseline stays current.
        if let Some(ref config) = multisig_config {
            if event.multisig != Pubkey::default() {
                let _ = snapshot::save_snapshot(&event.multisig, config);
            }
        }
        None
    };

    Ok(EnrichedEvent {
        event,
        multisig_config,
        uses_durable_nonce,
        sol_outflow_lamports,
        token_transfers,
        config_delta,
        nonce_threshold_met: false,
    })
}

/// Full enrichment: everything in `enrich()` plus nonce account scanning.
///
/// This scans every multisig member for durable nonce accounts (one RPC call
/// per member) to determine whether nonce holders can meet the signing
/// threshold. Use this for replay, API, and health paths where thoroughness
/// matters. Use `enrich()` for the live WebSocket pipeline where speed matters.
pub async fn enrich_full(
    rpc: &Arc<RpcClient>,
    event: MonitoredEvent,
) -> Result<EnrichedEvent, EnrichmentError> {
    let mut enriched = enrich(rpc, event).await?;

    // Scan member nonce accounts if we resolved a multisig
    if let Some(ref config) = enriched.multisig_config {
        if enriched.event.multisig != Pubkey::default() {
            if let Ok(account) =
                multisig::fetch_multisig_config(rpc, &enriched.event.multisig).await
            {
                let mut members_with_nonces = 0usize;
                for member in &account.members {
                    let nonces = nonce::fetch_nonce_accounts(rpc, &member.key)
                        .await
                        .unwrap_or_default();
                    if !nonces.is_empty() {
                        members_with_nonces += 1;
                    }
                }
                enriched.nonce_threshold_met =
                    members_with_nonces >= config.threshold as usize;
            }
        }
    }

    Ok(enriched)
}

/// Find the Squads multisig account from the transaction's account keys.
/// Checks each Squads-owned account's 8-byte discriminator to confirm
/// it's actually a Multisig (not a Proposal, VaultTransaction, etc).
async fn find_multisig_pubkey(rpc: &RpcClient, account_keys: &[Pubkey]) -> Option<Pubkey> {
    let squads_id = Pubkey::from_str(SQUADS_PROGRAM_ID).ok()?;
    let expected_disc = multisig::multisig_discriminator();

    for key in account_keys {
        if *key == squads_id {
            continue;
        }
        if let Ok(account) = rpc.get_account(key).await {
            if account.owner == squads_id && account.data.len() >= 8 && account.data[..8] == expected_disc {
                return Some(*key);
            }
        }
    }
    None
}
