use std::sync::Arc;

use solana_client::nonblocking::rpc_client::RpcClient;

use prefire_enrichment::enrich;
use prefire_scoring::{score_with_context, ScoringContext, Verdict};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    let batch_mode = args.get(1).map(|s| s.as_str()) == Some("--batch");

    let signatures: Vec<String> = if batch_mode {
        // --batch: read signatures from a JSON file
        let path = args.get(2).ok_or("usage: replay --batch <file.json>")?;
        let content = std::fs::read_to_string(path)?;
        serde_json::from_str(&content)?
    } else if args.len() >= 2 {
        args[1..].to_vec()
    } else {
        eprintln!("usage: replay <signature> [signature ...]");
        eprintln!("       replay --batch <signatures.json>");
        std::process::exit(1);
    };

    let rpc_url = std::env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".to_string());
    let rpc = Arc::new(RpcClient::new(rpc_url));
    let mut scoring_ctx = ScoringContext::new();

    // Collect results for summary table in batch mode
    let mut results: Vec<(String, String, u8, String, bool)> = Vec::new();

    for sig in &signatures {
        if !batch_mode {
            println!("=== {} ===", sig);
        }

        let events = match prefire_monitor::replay::replay_transaction(&rpc, sig).await {
            Ok(events) => events,
            Err(e) => {
                if !batch_mode {
                    eprintln!("  replay error: {}", e);
                }
                results.push((sig[..16].to_string(), "error".into(), 0, "ERR".into(), false));
                continue;
            }
        };

        if events.is_empty() {
            if !batch_mode {
                println!("  no governance events found\n");
            }
            results.push((sig[..16].to_string(), "no events".into(), 0, "-".into(), false));
            continue;
        }

        for event in events {
            let event_desc = format!("{:?}", event.event);

            if !batch_mode {
                println!("  event: {}", event_desc);
                println!("  slot: {} | block_time: {:?}", event.slot, event.block_time);
                println!("  signers: {:?}", event.signers);
            }

            let enriched = match enrich(&rpc, event).await {
                Ok(e) => e,
                Err(e) => {
                    if !batch_mode {
                        eprintln!("  enrichment error: {}", e);
                    }
                    continue;
                }
            };

            if !batch_mode {
                if let Some(ref config) = enriched.multisig_config {
                    println!(
                        "  multisig: threshold={}/{} voters, time_lock={}s",
                        config.threshold, config.voter_count, config.time_lock
                    );
                }
                if enriched.uses_durable_nonce {
                    println!("  ** DURABLE NONCE DETECTED **");
                }
            }

            let threat = score_with_context(&enriched, &mut scoring_ctx);

            let verdict_str = match threat.verdict {
                Verdict::Safe => "SAFE",
                Verdict::Suspicious => "SUSPICIOUS",
                Verdict::Critical => "!! CRITICAL !!",
            };

            if !batch_mode {
                println!("  SCORE: {}/100 — {}", threat.total, verdict_str);
                for signal in &threat.signals {
                    println!("    +{} {}: {}", signal.score, signal.name, signal.reason);
                }
                println!();
            }

            results.push((
                sig[..16].to_string(),
                event_desc,
                threat.total,
                verdict_str.to_string(),
                enriched.uses_durable_nonce,
            ));
        }
    }

    // Print summary table in batch mode
    if batch_mode {
        println!("\n{:-<90}", "");
        println!(
            "{:<18} {:<30} {:>5}  {:<14} {}",
            "SIGNATURE", "EVENT", "SCORE", "VERDICT", "NONCE"
        );
        println!("{:-<90}", "");
        for (sig, event, score, verdict, nonce) in &results {
            let event_short = if event.len() > 28 {
                format!("{}...", &event[..28])
            } else {
                event.clone()
            };
            println!(
                "{:<18} {:<30} {:>3}/100  {:<14} {}",
                sig,
                event_short,
                score,
                verdict,
                if *nonce { "YES" } else { "" }
            );
        }
        println!("{:-<90}", "");

        let total = results.len();
        let critical = results.iter().filter(|r| r.3 == "!! CRITICAL !!").count();
        let suspicious = results.iter().filter(|r| r.3 == "SUSPICIOUS").count();
        let safe = results.iter().filter(|r| r.3 == "SAFE").count();
        println!(
            "\n{} events | {} CRITICAL | {} SUSPICIOUS | {} SAFE",
            total, critical, suspicious, safe
        );
    }

    Ok(())
}
