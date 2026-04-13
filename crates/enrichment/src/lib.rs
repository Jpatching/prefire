pub mod multisig;
pub mod nonce;
pub mod token;

use std::str::FromStr;
use std::sync::Arc;

use serde::Serialize;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use thiserror::Error;

use prefire_monitor::governance::MonitoredEvent;
use prefire_monitor::rpc::SQUADS_PROGRAM_ID;

use crate::multisig::{MultisigConfig, MultisigError};
use crate::token::TokenTransferInfo;

#[derive(Debug, Clone, Serialize)]
pub struct EnrichedEvent {
    pub event: MonitoredEvent,
    pub multisig_config: Option<MultisigConfig>,
    pub uses_durable_nonce: bool,
    pub sol_outflow_lamports: i128,
    pub token_transfers: Vec<TokenTransferInfo>,
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

    let sol_outflow_lamports = 0;
    let token_transfers = vec![];

    Ok(EnrichedEvent {
        event,
        multisig_config,
        uses_durable_nonce,
        sol_outflow_lamports,
        token_transfers,
    })
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
