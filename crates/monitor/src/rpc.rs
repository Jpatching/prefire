use futures_util::StreamExt;
use solana_client::nonblocking::pubsub_client::PubsubClient;
use solana_client::rpc_config::RpcTransactionLogsConfig;
use solana_client::rpc_config::RpcTransactionLogsFilter;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::pubkey::Pubkey;
use tokio::sync::mpsc;

use crate::governance::{classify_instruction, MonitoredEvent};
use crate::log_parser::extract_squads_instructions;

pub const SQUADS_PROGRAM_ID: &str = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf";

pub async fn subscribe_squads_events(
    ws_url: &str,
) -> Result<mpsc::UnboundedReceiver<MonitoredEvent>, Box<dyn std::error::Error>> {
    let (sender, receiver) = mpsc::unbounded_channel();
    let ws_url = ws_url.to_string();

    tokio::spawn(async move {
        let client = PubsubClient::new(&ws_url).await.expect("ws connect failed");
        let filter = RpcTransactionLogsFilter::Mentions(vec![SQUADS_PROGRAM_ID.to_string()]);
        let config = RpcTransactionLogsConfig {
            commitment: Some(CommitmentConfig::confirmed()),
        };
        let (mut stream, _unsub) = client
            .logs_subscribe(filter, config)
            .await
            .expect("subscribe failed");

        while let Some(response) = stream.next().await {
            let logs: Vec<String> = response.value.logs.clone();
            let names = extract_squads_instructions(&logs);
            let slot = response.context.slot;

            for name in names {
                if let Some(event) = classify_instruction(&name) {
                    let _ = sender.send(MonitoredEvent {
                        signature: response.value.signature.clone(),
                        slot,
                        block_time: None, // not available from logsSubscribe
                        event,
                        multisig: Pubkey::default(), // resolved in enrichment
                        signers: vec![],             // resolved in enrichment
                        account_keys: vec![],        // resolved in enrichment
                        log_messages: logs.clone(),
                    });
                }
            }
        }
    });

    Ok(receiver)
}
