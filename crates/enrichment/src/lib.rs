pub mod nonce;
pub mod token;

use std::sync::Arc;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use serde::Serialize;
use prefire_monitor::governance::MonitoredEvent;

#[derive(Clone, Serialize, Debug)]
pub struct EnrichedEvent {
    pub event: MonitoredEvent,
    pub actors: Vec<Pubkey>,
    pub nonce: String,
    pub signal: String,
}

pub enum EnrichmentError {
    InvalidSignature(String),
    TransactionFetch(String),
    NonParseable(String),
} 

async fn extract_actors(
    rpc: &RpcClient,
    signature_str: &str,
) -> Result<Vec<Pubkey>, EnrichmentError> {
    // TODO: parse signature_str into Signature type
    // TODO: call rpc.get_transaction_with_config()
    // TODO: extract signers from parsed transaction
    todo!()
}

pub async fn enrich(
    rpc: &Arc<RpcClient>,
    event: MonitoredEvent,
) -> Result<EnrichedEvent, EnrichmentError> {
    // TODO: call extract_actors, then nonce/token scans
    todo!()
}
