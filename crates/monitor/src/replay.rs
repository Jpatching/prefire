use std::str::FromStr;

use solana_client::nonblocking::rpc_client::RpcClient;
use solana_client::rpc_config::RpcTransactionConfig;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use solana_transaction_status_client_types::{
    EncodedTransaction, UiMessage, UiTransactionEncoding, UiTransactionTokenBalance,
};
use thiserror::Error;

use crate::governance::{classify_instruction, MonitoredEvent};
use crate::log_parser::extract_squads_instructions;

#[derive(Debug, Error)]
pub enum ReplayError {
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
    #[error("rpc error: {0}")]
    Rpc(#[from] solana_client::client_error::ClientError),
    #[error("transaction has no metadata")]
    NoMeta,
    #[error("no governance events found in transaction")]
    NoEvents,
}

/// Fetch a historical transaction by signature and extract governance events.
/// Returns all MonitoredEvents found in the transaction (usually 1, but a tx
/// can contain multiple Squads instructions).
pub async fn replay_transaction(
    rpc: &RpcClient,
    signature_str: &str,
) -> Result<Vec<MonitoredEvent>, ReplayError> {
    let sig = Signature::from_str(signature_str)
        .map_err(|e| ReplayError::InvalidSignature(e.to_string()))?;

    let config = RpcTransactionConfig {
        encoding: Some(UiTransactionEncoding::Json),
        commitment: Some(CommitmentConfig::confirmed()),
        max_supported_transaction_version: Some(0),
    };

    let tx = rpc.get_transaction_with_config(&sig, config).await?;
    let meta = tx.transaction.meta.ok_or(ReplayError::NoMeta)?;

    // Extract log messages -- meta.log_messages is OptionSerializer, not Option
    let logs: Vec<String> = Option::from(meta.log_messages).unwrap_or_default();

    // Extract balance data for SOL/token outflow detection
    let pre_balances: Vec<u64> = Option::from(meta.pre_balances).unwrap_or_default();
    let post_balances: Vec<u64> = Option::from(meta.post_balances).unwrap_or_default();
    let pre_token_balances: Vec<UiTransactionTokenBalance> =
        Option::from(meta.pre_token_balances).unwrap_or_default();
    let post_token_balances: Vec<UiTransactionTokenBalance> =
        Option::from(meta.post_token_balances).unwrap_or_default();

    // Extract account keys and signers from the transaction message
    let (account_keys, num_signers) = extract_account_info(&tx.transaction.transaction)?;
    let signers = account_keys[..num_signers].to_vec();

    // Extract slot and block_time
    let slot = tx.slot;
    let block_time = tx.block_time;

    // Run through the same parsing pipeline as live mode
    let instruction_names = extract_squads_instructions(&logs);

    let mut events = Vec::new();
    for name in instruction_names {
        if let Some(event) = classify_instruction(&name) {
            events.push(MonitoredEvent {
                signature: signature_str.to_string(),
                slot,
                block_time,
                event,
                multisig: Pubkey::default(), // resolved in enrichment
                signers: signers.clone(),
                account_keys: account_keys.clone(),
                log_messages: logs.clone(),
                pre_balances: pre_balances.clone(),
                post_balances: post_balances.clone(),
                pre_token_balances: pre_token_balances.clone(),
                post_token_balances: post_token_balances.clone(),
            });
        }
    }

    Ok(events)
}

/// Pull account keys and signer count from the encoded transaction.
fn extract_account_info(
    encoded: &EncodedTransaction,
) -> Result<(Vec<Pubkey>, usize), ReplayError> {
    match encoded {
        EncodedTransaction::Json(ui_tx) => match &ui_tx.message {
            UiMessage::Raw(raw) => {
                let keys: Vec<Pubkey> = raw
                    .account_keys
                    .iter()
                    .filter_map(|s| Pubkey::from_str(s).ok())
                    .collect();
                let num_signers = raw.header.num_required_signatures as usize;
                Ok((keys, num_signers))
            }
            UiMessage::Parsed(parsed) => {
                let keys: Vec<Pubkey> = parsed
                    .account_keys
                    .iter()
                    .filter_map(|a| Pubkey::from_str(&a.pubkey).ok())
                    .collect();
                // Parsed accounts are tagged with signer: bool
                let num_signers = parsed
                    .account_keys
                    .iter()
                    .filter(|a| a.signer)
                    .count();
                Ok((keys, num_signers))
            }
        },
        _ => Err(ReplayError::NoMeta),
    }
}
