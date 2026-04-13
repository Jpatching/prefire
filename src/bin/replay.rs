use std::sync::Arc;

use solana_client::nonblocking::rpc_client::RpcClient;

use prefire_enrichment::enrich;
use prefire_scoring::{score_with_context, ScoringContext, Verdict};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: replay <signature> [signature ...]");
        std::process::exit(1);
    }

    let rpc_url = std::env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".to_string());
    let rpc = Arc::new(RpcClient::new(rpc_url));
    let mut scoring_ctx = ScoringContext::new();

    for sig in &args[1..] {
        println!("=== {} ===", sig);

        // Stage 1: Replay — fetch and parse governance events
        let events = match prefire_monitor::replay::replay_transaction(&rpc, sig).await {
            Ok(events) => events,
            Err(e) => {
                eprintln!("  replay error: {}", e);
                continue;
            }
        };

        if events.is_empty() {
            println!("  no governance events found\n");
            continue;
        }

        for event in events {
            println!("  event: {:?}", event.event);
            println!("  slot: {} | block_time: {:?}", event.slot, event.block_time);
            println!("  signers: {:?}", event.signers);

            // Stage 2: Enrich — fetch multisig config, check nonce, etc.
            let enriched = match enrich(&rpc, event).await {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("  enrichment error: {}", e);
                    continue;
                }
            };

            if let Some(ref config) = enriched.multisig_config {
                println!(
                    "  multisig: threshold={}/{} voters, time_lock={}s",
                    config.threshold, config.voter_count, config.time_lock
                );
            }
            if enriched.uses_durable_nonce {
                println!("  ** DURABLE NONCE DETECTED **");
            }

            // Stage 3: Score — combine signals into threat assessment
            let threat = score_with_context(&enriched, &mut scoring_ctx);

            let verdict_marker = match threat.verdict {
                Verdict::Safe => "SAFE",
                Verdict::Suspicious => "SUSPICIOUS",
                Verdict::Critical => "!! CRITICAL !!",
            };

            println!("  SCORE: {}/100 — {}", threat.total, verdict_marker);
            for signal in &threat.signals {
                println!("    +{} {}: {}", signal.score, signal.name, signal.reason);
            }
            println!();
        }
    }

    Ok(())
}
