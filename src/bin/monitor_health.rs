//! Continuous governance health monitor.
//!
//! Polls registered multisigs on an interval, detects configuration changes,
//! and alerts when risk increases. This is the "setup phase detection" layer
//! that would have caught the Drift exploit 5-9 days before execution:
//!
//!   - March 23: Nonce accounts created for Security Council members
//!   - March 27: Config migration removed timelock (health 100 -> 20)
//!   - March 30: New nonce account after config change
//!
//! Usage:
//!   monitor_health                          # polls every 5 minutes
//!   monitor_health --interval 60            # polls every 60 seconds
//!   monitor_health --registry config/registry.json

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;

use prefire_enrichment::multisig::{fetch_multisig_config, ConfigDelta, MultisigConfig};
use prefire_enrichment::nonce::fetch_nonce_accounts;
use prefire_enrichment::snapshot;
use prefire_scoring::governance_health;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    let registry_path = args
        .iter()
        .position(|a| a == "--registry")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("config/registry.json");

    let interval_secs: u64 = args
        .iter()
        .position(|a| a == "--interval")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(300); // 5 minutes default

    let rpc_url = std::env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".to_string());
    let webhook_url = std::env::var("WEBHOOK_URL").ok();
    let rpc = Arc::new(RpcClient::new(rpc_url));

    println!("prefire health monitor starting");
    println!("  registry: {}", registry_path);
    println!("  interval: {}s", interval_secs);
    println!(
        "  webhook:  {}",
        webhook_url.as_deref().unwrap_or("(none — stdout only)")
    );
    println!();

    loop {
        let addresses = load_registry(registry_path);
        if addresses.is_empty() {
            eprintln!("warning: no multisig addresses in registry");
        }

        for (name, addr) in &addresses {
            if let Err(e) = check_multisig(&rpc, name, addr, webhook_url.as_deref()).await {
                eprintln!("error checking {} ({}): {}", name, addr, e);
            }
        }

        tokio::time::sleep(Duration::from_secs(interval_secs)).await;
    }
}

/// Load protocol names and multisig addresses from the registry JSON.
fn load_registry(path: &str) -> Vec<(String, String)> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to read registry {}: {}", path, e);
            return vec![];
        }
    };
    let registry: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("failed to parse registry: {}", e);
            return vec![];
        }
    };

    registry["protocols"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|p| {
            let name = p["name"].as_str()?.to_string();
            let addr = p["multisig_address"].as_str()?.to_string();
            if addr.is_empty() {
                return None;
            }
            Some((name, addr))
        })
        .collect()
}

/// Check a single multisig: fetch config, compare to snapshot, scan nonces, alert on changes.
async fn check_multisig(
    rpc: &RpcClient,
    name: &str,
    address: &str,
    webhook_url: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let pubkey = Pubkey::from_str(address)?;

    let account = fetch_multisig_config(rpc, &pubkey).await?;
    let config = MultisigConfig::from(&account);
    let health = governance_health(&config);

    // Compare to previous snapshot
    let previous = snapshot::load_snapshot(&pubkey);
    let delta = previous
        .as_ref()
        .map(|old| ConfigDelta::compare(old, &config));

    // Save new snapshot
    let _ = snapshot::save_snapshot(&pubkey, &config);

    // Scan nonce accounts for all members
    let mut members_with_nonces = 0usize;
    let mut total_nonces = 0usize;

    for member in &account.members {
        let nonce_addrs = fetch_nonce_accounts(rpc, &member.key)
            .await
            .unwrap_or_default();
        if !nonce_addrs.is_empty() {
            members_with_nonces += 1;
            total_nonces += nonce_addrs.len();
        }
    }

    let nonce_meets_threshold = members_with_nonces >= config.threshold as usize;

    // Determine if anything changed or is concerning
    let config_changed = delta.as_ref().map_or(false, |d| {
        d.threshold_changed.is_some()
            || d.timelock_changed.is_some()
            || d.members_added > 0
            || d.members_removed > 0
    });
    let config_weakened = delta.as_ref().map_or(false, |d| d.is_weakened());

    let health_label = match health.total {
        80..=100 => "HEALTHY",
        50..=79 => "AT RISK",
        _ => "VULNERABLE",
    };

    // Always log current state
    let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
    println!(
        "[{}] {} ({}) — health: {}/100 {} | nonces: {}/{} members | threshold: {}/{}",
        timestamp,
        name,
        address,
        health.total,
        health_label,
        members_with_nonces,
        config.member_count,
        config.threshold,
        config.member_count,
    );

    // Alert on concerning changes
    if config_changed {
        let delta = delta.as_ref().unwrap();
        let mut changes = Vec::new();

        if let Some((old, new)) = delta.threshold_changed {
            changes.push(format!("threshold: {} -> {}", old, new));
        }
        if let Some((old, new)) = delta.timelock_changed {
            changes.push(format!("timelock: {}s -> {}s", old, new));
        }
        if delta.members_added > 0 {
            changes.push(format!("+{} member(s)", delta.members_added));
        }
        if delta.members_removed > 0 {
            changes.push(format!("-{} member(s)", delta.members_removed));
        }

        let severity = if config_weakened { "CRITICAL" } else { "INFO" };
        let msg = format!(
            "[{}] CONFIG CHANGE on {} ({}): {} | new health: {}/100",
            severity,
            name,
            address,
            changes.join(", "),
            health.total,
        );
        println!("  >>> {}", msg);

        // Fire webhook for config weakening
        if config_weakened {
            if let Some(url) = webhook_url {
                let payload = serde_json::json!({
                    "type": "config_weakened",
                    "protocol": name,
                    "multisig": address,
                    "changes": changes,
                    "health_score": health.total,
                    "health_label": health_label,
                    "risks": health.risks,
                    "recommendations": health.recommendations,
                });
                prefire_alerts::webhook::send_webhook(url, &payload).await;
            }
        }
    }

    // Alert on nonce threshold met
    if nonce_meets_threshold && total_nonces > 0 {
        let msg = format!(
            "[CRITICAL] NONCE THRESHOLD MET on {} ({}): {}/{} members with nonces >= threshold {}",
            name, address, members_with_nonces, config.member_count, config.threshold,
        );
        println!("  >>> {}", msg);

        if let Some(url) = webhook_url {
            let payload = serde_json::json!({
                "type": "nonce_threshold_met",
                "protocol": name,
                "multisig": address,
                "members_with_nonces": members_with_nonces,
                "total_nonces": total_nonces,
                "threshold": config.threshold,
                "member_count": config.member_count,
                "health_score": health.total,
            });
            prefire_alerts::webhook::send_webhook(url, &payload).await;
        }
    }

    // Alert on vulnerable health score (first time seeing it)
    if previous.is_none() && health.total < 50 {
        println!(
            "  >>> [WARNING] First scan of {} — health {}/100 ({})",
            name, health.total, health_label
        );
        for rec in &health.recommendations {
            println!("      * {}", rec);
        }
    }

    Ok(())
}
