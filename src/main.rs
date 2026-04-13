use std::sync::Arc;

use solana_client::nonblocking::rpc_client::RpcClient;

use prefire_enrichment::enrich;
use prefire_scoring::{score_with_context, ScoringContext, Verdict};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("live");

    match mode {
        "live" => run_live().await,
        other => {
            eprintln!("unknown mode: {}", other);
            eprintln!("usage: prefire live");
            eprintln!("       prefire replay <sig>  (use the replay binary)");
            std::process::exit(1);
        }
    }
}

async fn run_live() -> Result<(), Box<dyn std::error::Error>> {
    println!("prefire — solana governance attack detection");
    println!("mode: live | watching Squads v4 governance events\n");

    let ws_url = std::env::var("SOLANA_WS_URL")?;
    let rpc_url = std::env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".to_string());
    let webhook_url = std::env::var("WEBHOOK_URL").ok();

    let rpc = Arc::new(RpcClient::new(rpc_url));
    let mut scoring_ctx = ScoringContext::new();

    // WebSocket gives us early notification + logs.
    // We replay the full transaction via RPC to get signers/account_keys.
    let mut receiver = prefire_monitor::rpc::subscribe_squads_events(&ws_url).await?;

    while let Some(ws_event) = receiver.recv().await {
        // Replay the full transaction to get complete metadata
        let events = match prefire_monitor::replay::replay_transaction(
            &rpc,
            &ws_event.signature,
        )
        .await
        {
            Ok(events) => events,
            Err(_) => {
                // Fallback: use the WebSocket event as-is (partial data)
                vec![ws_event]
            }
        };

        for event in events {
            let enriched = match enrich(&rpc, event).await {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("enrichment error: {}", e);
                    continue;
                }
            };

            let threat = score_with_context(&enriched, &mut scoring_ctx);

            // Only print events that score above noise floor
            if threat.total < 5 {
                continue;
            }

            let verdict_str = match threat.verdict {
                Verdict::Safe => "SAFE",
                Verdict::Suspicious => "SUSPICIOUS",
                Verdict::Critical => "!! CRITICAL !!",
            };

            println!(
                "[slot {}] {} {}/100 — {:?} | sig: {}",
                enriched.event.slot,
                verdict_str,
                threat.total,
                enriched.event.event,
                &enriched.event.signature[..16],
            );

            for signal in &threat.signals {
                println!("  +{} {}: {}", signal.score, signal.name, signal.reason);
            }

            // Fire webhook for SUSPICIOUS and CRITICAL events
            if threat.total >= 31 {
                if let Some(ref url) = webhook_url {
                    let payload = serde_json::json!({
                        "score": threat.total,
                        "verdict": verdict_str,
                        "signals": threat.signals,
                        "signature": enriched.event.signature,
                        "slot": enriched.event.slot,
                        "event": format!("{:?}", enriched.event.event),
                        "multisig_config": enriched.multisig_config,
                        "uses_durable_nonce": enriched.uses_durable_nonce,
                    });
                    prefire_alerts::webhook::send_webhook(url, &payload).await;
                }
            }
        }
    }

    Ok(())
}
