use std::collections::VecDeque;
use std::str::FromStr;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, Json};
use axum::routing::{get, delete};
use axum::Router;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_client::rpc_client::GetConfirmedSignaturesForAddress2Config;
use solana_client::rpc_config::RpcProgramAccountsConfig;
use solana_client::rpc_filter::{Memcmp, RpcFilterType};
use solana_sdk::bs58;
use solana_sdk::pubkey::Pubkey;

use prefire_enrichment::enrich_full;
use prefire_enrichment::multisig::{fetch_multisig_config, MultisigConfig, MultisigAccount};
use prefire_enrichment::nonce::fetch_nonce_accounts;
use prefire_enrichment::snapshot;
use prefire_scoring::{governance_health, score_with_context, ScoringContext};

use tokio::sync::Mutex;

/// Cached mainnet statistics. Persisted to disk to avoid hammering RPC.
/// getProgramAccounts is the correct Solana-native way to enumerate accounts,
/// but it's an expensive query that hits rate limits on most RPC providers.
/// We run it in the background and cache results.
#[derive(serde::Serialize, serde::Deserialize)]
struct CachedStats {
    total_multisigs: usize,
    zero_timelock_vulnerable: usize,
    high_risk_count: usize,
    last_refreshed: String,
}

const STATS_CACHE_PATH: &str = "data/stats_cache.json";

fn load_cached_stats() -> Option<CachedStats> {
    let data = std::fs::read_to_string(STATS_CACHE_PATH).ok()?;
    serde_json::from_str(&data).ok()
}

fn save_cached_stats(stats: &CachedStats) {
    let _ = std::fs::create_dir_all("data");
    if let Ok(json) = serde_json::to_string_pretty(stats) {
        let _ = std::fs::write(STATS_CACHE_PATH, json);
    }
}

const WATCHLIST_PATH: &str = "data/watchlist.json";

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct WatchEntry {
    address: String,
    name: String,
    webhook_url: Option<String>,
    rpc_url: Option<String>,
    added_at: i64,
}

#[derive(serde::Serialize, Clone)]
struct MonitorEvent {
    timestamp: String,
    address: String,
    name: String,
    event_type: String,
    details: String,
    severity: String,
}

fn load_watchlist() -> Vec<WatchEntry> {
    std::fs::read_to_string(WATCHLIST_PATH)
        .ok()
        .and_then(|data| serde_json::from_str(&data).ok())
        .unwrap_or_default()
}

fn save_watchlist(list: &[WatchEntry]) {
    let _ = std::fs::create_dir_all("data");
    if let Ok(json) = serde_json::to_string_pretty(list) {
        let _ = std::fs::write(WATCHLIST_PATH, json);
    }
}

struct AppState {
    rpc: Arc<RpcClient>,
    rpc_url: String,
    scoring_ctx: Mutex<ScoringContext>,
    stats: Mutex<CachedStats>,
    watchlist: Mutex<Vec<WatchEntry>>,
    events: Mutex<VecDeque<MonitorEvent>>,
    registry: serde_json::Value,
}

#[tokio::main]
async fn main() {
    let rpc_url = std::env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".to_string());
    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());

    let rpc = Arc::new(RpcClient::new(rpc_url.clone()));

    // Load cached stats from disk if available, otherwise show computing state
    let initial_stats = load_cached_stats().unwrap_or(CachedStats {
        total_multisigs: 0,
        zero_timelock_vulnerable: 0,
        high_risk_count: 0,
        last_refreshed: "computing...".to_string(),
    });
    if initial_stats.total_multisigs > 0 {
        println!(
            "loaded cached stats: {} multisigs ({} vulnerable) from {}",
            initial_stats.total_multisigs,
            initial_stats.zero_timelock_vulnerable,
            initial_stats.last_refreshed
        );
    }

    let registry = std::fs::read_to_string("config/registry.json")
        .ok()
        .and_then(|data| serde_json::from_str(&data).ok())
        .unwrap_or(serde_json::json!({"protocols": []}));

    let state = Arc::new(AppState {
        rpc,
        rpc_url,
        scoring_ctx: Mutex::new(ScoringContext::new()),
        stats: Mutex::new(initial_stats),
        watchlist: Mutex::new(load_watchlist()),
        events: Mutex::new(VecDeque::with_capacity(100)),
        registry,
    });

    // Background task: refresh stats every 2 hours.
    // Uses getProgramAccounts which is heavy -- don't run too frequently.
    let bg_state = Arc::clone(&state);
    tokio::spawn(async move {
        // If we already have cached data, wait before first refresh
        let has_cache = bg_state.stats.lock().await.total_multisigs > 0;
        if has_cache {
            tokio::time::sleep(std::time::Duration::from_secs(7200)).await;
        }
        loop {
            println!("refreshing mainnet stats...");
            let refreshed = compute_mainnet_stats(&bg_state.rpc, &bg_state.rpc_url).await;
            if refreshed.total_multisigs > 0 {
                save_cached_stats(&refreshed);
                *bg_state.stats.lock().await = refreshed;
                println!("stats refreshed and cached to disk");
            }
            tokio::time::sleep(std::time::Duration::from_secs(7200)).await;
        }
    });

    // Background task: monitor watchlist every 5 minutes
    let mon_state = Arc::clone(&state);
    tokio::spawn(async move {
        // Wait 30s before first monitoring cycle
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        loop {
            run_monitoring_cycle(&mon_state).await;
            tokio::time::sleep(std::time::Duration::from_secs(300)).await;
        }
    });

    let app = Router::new()
        .route("/", get(dashboard))
        .route("/api/scan/{address}", get(api_scan))
        .route("/api/replay/{signature}", get(api_replay))
        .route("/api/health/{address}", get(api_health))
        .route("/api/stats", get(api_stats))
        .route("/api/registry", get(api_registry))
        .route("/api/watch", get(api_watch_list).post(api_watch_add))
        .route("/api/watch/{address}", delete(api_watch_remove))
        .route("/api/events", get(api_events))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", port);
    println!("prefire API listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

/// Dashboard HTML page
async fn dashboard() -> Html<&'static str> {
    Html(include_str!("../../static/dashboard.html"))
}

/// Scan a multisig for nonce accounts
async fn api_scan(
    State(state): State<Arc<AppState>>,
    Path(address): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let pubkey = address
        .parse::<solana_sdk::pubkey::Pubkey>()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let account = fetch_multisig_config(&state.rpc, &pubkey)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    let config = MultisigConfig::from(&account);

    let mut members = Vec::new();
    let mut members_with_nonces = 0usize;
    let mut total_nonces = 0u64;

    for member in &account.members {
        let nonce_addrs = fetch_nonce_accounts(&state.rpc, &member.key)
            .await
            .unwrap_or_default();
        let nonce_count = nonce_addrs.len() as u64;

        if nonce_count > 0 {
            members_with_nonces += 1;
            total_nonces += nonce_count;
        }

        members.push(serde_json::json!({
            "key": member.key.to_string(),
            "can_vote": member.permissions.can_vote(),
            "can_execute": member.permissions.can_execute(),
            "nonce_accounts": nonce_count,
            "nonce_account_addresses": nonce_addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
        }));
    }

    let risk = if members_with_nonces >= config.threshold as usize {
        "CRITICAL"
    } else if members_with_nonces > 0 {
        "WARNING"
    } else {
        "OK"
    };

    Ok(Json(serde_json::json!({
        "address": address,
        "threshold": config.threshold,
        "member_count": config.member_count,
        "voter_count": config.voter_count,
        "time_lock": config.time_lock,
        "members": members,
        "nonce_summary": {
            "members_with_nonces": members_with_nonces,
            "total_nonce_accounts": total_nonces,
            "risk_level": risk,
        }
    })))
}

/// Full governance health assessment for a multisig.
/// Combines config risk scoring, nonce surveillance, and actionable recommendations.
async fn api_health(
    State(state): State<Arc<AppState>>,
    Path(address): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let pubkey = address
        .parse::<solana_sdk::pubkey::Pubkey>()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let account = fetch_multisig_config(&state.rpc, &pubkey)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    let config = MultisigConfig::from(&account);
    let health = governance_health(&config);

    let health_label = match health.total {
        80..=100 => "HEALTHY",
        50..=79 => "AT RISK",
        _ => "VULNERABLE",
    };

    // Check vault PDAs at indices 0-3 and sum balances
    let squads_program =
        Pubkey::from_str("SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf").unwrap();
    let mut vault_sol_total: f64 = 0.0;
    let mut vaults = Vec::new();
    for idx in 0..4u8 {
        let (vault_pda, _) = Pubkey::find_program_address(
            &[b"multisig", pubkey.as_ref(), b"vault", &[idx]],
            &squads_program,
        );
        if let Ok(lamports) = state.rpc.get_balance(&vault_pda).await {
            let sol = lamports as f64 / 1_000_000_000.0;
            if sol > 0.0 {
                vault_sol_total += sol;
                vaults.push(serde_json::json!({
                    "index": idx,
                    "address": vault_pda.to_string(),
                    "sol_balance": sol,
                }));
            }
        }
    }
    let vault_sol = if vault_sol_total > 0.0 {
        Some(vault_sol_total)
    } else {
        None
    };

    // Fetch most recent signature to determine last activity
    let last_activity = {
        let sig_config = GetConfirmedSignaturesForAddress2Config {
            before: None,
            until: None,
            limit: Some(1),
            commitment: None,
        };
        match state
            .rpc
            .get_signatures_for_address_with_config(&pubkey, sig_config)
            .await
        {
            Ok(sigs) if !sigs.is_empty() => sigs[0].block_time.map(|ts| {
                let dt = chrono::DateTime::from_timestamp(ts, 0).unwrap_or_default();
                let now = chrono::Utc::now();
                let ago = now.signed_duration_since(dt);
                let relative = if ago.num_days() > 0 {
                    format!("{} day(s) ago", ago.num_days())
                } else if ago.num_hours() > 0 {
                    format!("{} hour(s) ago", ago.num_hours())
                } else {
                    format!("{} minute(s) ago", ago.num_minutes().max(1))
                };
                serde_json::json!({
                    "timestamp": dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                    "unix": ts,
                    "relative": relative,
                })
            }),
            _ => None,
        }
    };

    // Scan each member for nonce accounts -- return actual addresses, not just counts
    let mut members = Vec::new();
    let mut members_with_nonces: usize = 0;
    let mut total_nonces: u64 = 0;

    for member in &account.members {
        let nonce_addrs = fetch_nonce_accounts(&state.rpc, &member.key)
            .await
            .unwrap_or_default();
        let nonce_count = nonce_addrs.len() as u64;

        if nonce_count > 0 {
            members_with_nonces += 1;
            total_nonces += nonce_count;
        }

        let perms = format!(
            "{}{}{}",
            if member.permissions.mask & 1 != 0 { "Initiate" } else { "" },
            if member.permissions.can_vote() { " Vote" } else { "" },
            if member.permissions.can_execute() { " Execute" } else { "" },
        );

        members.push(serde_json::json!({
            "key": member.key.to_string(),
            "permissions": perms.trim(),
            "can_vote": member.permissions.can_vote(),
            "can_execute": member.permissions.can_execute(),
            "nonce_accounts": nonce_count,
            "nonce_account_addresses": nonce_addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
        }));
    }

    let nonce_risk = if members_with_nonces >= config.threshold as usize {
        "CRITICAL"
    } else if members_with_nonces > 0 {
        "WARNING"
    } else {
        "OK"
    };

    // Build nonce-specific recommendations
    let mut all_recommendations = health.recommendations.clone();
    if members_with_nonces > 0 {
        all_recommendations.push(format!(
            "{} member(s) have durable nonce accounts. Advance (invalidate) any nonce accounts \
             that are not actively needed to revoke pre-signed transactions.",
            members_with_nonces
        ));
    }
    if members_with_nonces >= config.threshold as usize {
        all_recommendations.push(format!(
            "CRITICAL: {} members with nonce accounts meets or exceeds the threshold of {}. \
             These members could execute pre-signed transactions without other members' knowledge.",
            members_with_nonces, config.threshold
        ));
    }

    // Config history: save versioned snapshot if config changed, then load history
    let previous = snapshot::load_snapshot(&pubkey);
    if previous.as_ref() != Some(&config) {
        let _ = snapshot::save_snapshot_versioned(&pubkey, &config);
    }
    let _ = snapshot::save_snapshot(&pubkey, &config);

    let config_history: Vec<serde_json::Value> = snapshot::load_snapshot_history(&pubkey)
        .into_iter()
        .map(|(ts, cfg)| {
            let dt = chrono::DateTime::from_timestamp(ts, 0).unwrap_or_default();
            serde_json::json!({
                "timestamp": dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                "unix": ts,
                "threshold": cfg.threshold,
                "member_count": cfg.member_count,
                "voter_count": cfg.voter_count,
                "time_lock": cfg.time_lock,
            })
        })
        .collect();

    // Risk context: synthesize vault balance + activity + health into urgency
    let vault_balance = vault_sol.unwrap_or(0.0);
    let is_dormant = last_activity
        .as_ref()
        .and_then(|la| la.get("unix"))
        .and_then(|u| u.as_i64())
        .map(|ts| chrono::Utc::now().timestamp() - ts > 30 * 86400)
        .unwrap_or(true);
    let is_empty = vault_balance < 1.0;

    let (urgency, summary) = match (health.total, is_empty, is_dormant) {
        (0..=49, false, false) => (
            "CRITICAL",
            format!(
                "Active multisig with {:.1} SOL and weak governance. Immediate action needed.",
                vault_balance
            ),
        ),
        (0..=49, false, true) => (
            "HIGH",
            format!(
                "Dormant multisig with {:.1} SOL and weak governance. Fix before resuming activity.",
                vault_balance
            ),
        ),
        (0..=49, true, _) => (
            "LOW",
            "Weak governance config but vault is effectively empty. Low financial risk.".to_string(),
        ),
        (50..=79, false, _) => (
            "MEDIUM",
            format!(
                "Governance could be stronger. {:.1} SOL at moderate risk.",
                vault_balance
            ),
        ),
        _ => (
            "INFO",
            "Governance configuration looks reasonable.".to_string(),
        ),
    };

    Ok(Json(serde_json::json!({
        "address": address,
        "health_score": health.total,
        "health_label": health_label,
        "risk_context": {
            "urgency": urgency,
            "summary": summary,
            "vault_at_risk": !is_empty,
            "is_dormant": is_dormant,
        },
        "config": {
            "threshold": config.threshold,
            "member_count": config.member_count,
            "voter_count": config.voter_count,
            "time_lock": config.time_lock,
        },
        "last_activity": last_activity,
        "risks": health.risks,
        "recommendations": all_recommendations,
        "config_history": config_history,
        "nonce_summary": {
            "members_with_nonces": members_with_nonces,
            "total_nonce_accounts": total_nonces,
            "risk_level": nonce_risk,
        },
        "members": members,
        "vault": {
            "total_sol": vault_sol_total,
            "vaults": vaults,
        },
        "drift_comparison": {
            "note": "Drift Protocol was exploited with threshold=2/5, timelock=0s",
            "drift_threshold": "2/5",
            "drift_timelock": 0,
            "drift_health_score": 35,
            "your_threshold": format!("{}/{}", config.threshold, config.member_count),
            "your_timelock": config.time_lock,
        },
        "fix_links": {
            "squads_settings": format!("https://v4.squads.so/squad/{}/settings", address),
            "squads_dashboard": format!("https://v4.squads.so/squad/{}", address),
        },
    })))
}

/// Replay and score a transaction
async fn api_replay(
    State(state): State<Arc<AppState>>,
    Path(signature): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let events = prefire_monitor::replay::replay_transaction(&state.rpc, &signature)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    let mut results = Vec::new();
    let mut ctx = state.scoring_ctx.lock().await;

    for event in events {
        let enriched = enrich_full(&state.rpc, event)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let threat = score_with_context(&enriched, &mut ctx);

        results.push(serde_json::json!({
            "event": format!("{:?}", enriched.event.event),
            "slot": enriched.event.slot,
            "block_time": enriched.event.block_time,
            "signers": enriched.event.signers.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            "multisig_config": enriched.multisig_config,
            "uses_durable_nonce": enriched.uses_durable_nonce,
            "score": threat.total,
            "verdict": format!("{:?}", threat.verdict),
            "signals": threat.signals,
        }));
    }

    Ok(Json(serde_json::json!({
        "signature": signature,
        "events": results,
    })))
}

/// Live mainnet stats (cached, refreshed every 30 min)
async fn api_stats(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let stats = state.stats.lock().await;
    Json(serde_json::json!({
        "total_multisigs_on_mainnet": stats.total_multisigs,
        "zero_timelock_configs": stats.zero_timelock_vulnerable,
        "high_risk_governance": stats.high_risk_count,
        "last_refreshed": stats.last_refreshed,
        "known_exploits_detected": 1,
        "exploit_name": "Drift Protocol ($285M, April 2026)",
        "signals": [
            "durable_nonce (30 pts)",
            "nonce_threshold_met (25 pts)",
            "rapid_governance (25 pts)",
            "config_weakened (20 pts)",
            "config_change (15 pts)",
            "zero_timelock (10 pts)",
            "vault_transfer (10 pts)",
            "high_value_outflow (10 pts)",
        ],
    }))
}

// --- Watch list endpoints ---

/// Add a multisig to the watch list.
async fn api_watch_add(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let address = body
        .get("address")
        .and_then(|a| a.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let name = body
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or("Unnamed");
    let webhook_url = body.get("webhook_url").and_then(|w| w.as_str());
    let rpc_url = body.get("rpc_url").and_then(|r| r.as_str());

    // Validate it's a real Squads multisig
    let pubkey = address
        .parse::<Pubkey>()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    fetch_multisig_config(&state.rpc, &pubkey)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    let entry = WatchEntry {
        address: address.to_string(),
        name: name.to_string(),
        webhook_url: webhook_url.map(|s| s.to_string()),
        rpc_url: rpc_url.map(|s| s.to_string()),
        added_at: chrono::Utc::now().timestamp(),
    };

    let mut list = state.watchlist.lock().await;
    // Don't add duplicates
    if !list.iter().any(|e| e.address == address) {
        list.push(entry.clone());
        save_watchlist(&list);
    }

    Ok(Json(serde_json::json!({
        "status": "watching",
        "address": address,
        "name": name,
    })))
}

/// List all watched multisigs with current status.
async fn api_watch_list(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let list = state.watchlist.lock().await;
    let entries: Vec<serde_json::Value> = list
        .iter()
        .map(|e| {
            serde_json::json!({
                "address": e.address,
                "name": e.name,
                "has_webhook": e.webhook_url.is_some(),
                "has_custom_rpc": e.rpc_url.is_some(),
                "added_at": e.added_at,
            })
        })
        .collect();
    Json(serde_json::json!({ "watchlist": entries }))
}

/// Remove a multisig from the watch list.
async fn api_watch_remove(
    State(state): State<Arc<AppState>>,
    Path(address): Path<String>,
) -> StatusCode {
    let mut list = state.watchlist.lock().await;
    let before = list.len();
    list.retain(|e| e.address != address);
    if list.len() < before {
        save_watchlist(&list);
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

/// Get recent monitoring events.
async fn api_events(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let events = state.events.lock().await;
    let list: Vec<&MonitorEvent> = events.iter().collect();
    Json(serde_json::json!({ "events": list }))
}

/// Background monitoring cycle: check all watched multisigs for changes.
async fn run_monitoring_cycle(state: &Arc<AppState>) {
    let list = state.watchlist.lock().await.clone();
    if list.is_empty() {
        return;
    }
    println!("monitoring cycle: checking {} watched multisigs", list.len());

    for entry in &list {
        let pubkey = match entry.address.parse::<Pubkey>() {
            Ok(pk) => pk,
            Err(_) => continue,
        };

        // Use entry's RPC if provided, otherwise use default
        let rpc = if let Some(ref custom_url) = entry.rpc_url {
            Arc::new(RpcClient::new(custom_url.clone()))
        } else {
            Arc::clone(&state.rpc)
        };

        // Fetch current config
        let account = match fetch_multisig_config(&rpc, &pubkey).await {
            Ok(a) => a,
            Err(_) => continue,
        };
        let config = MultisigConfig::from(&account);

        // Compare to snapshot
        let previous = snapshot::load_snapshot(&pubkey);
        if let Some(ref prev) = previous {
            if prev != &config {
                // Config changed!
                let mut details = Vec::new();
                if prev.threshold != config.threshold {
                    details.push(format!(
                        "threshold {}/{} -> {}/{}",
                        prev.threshold, prev.member_count, config.threshold, config.member_count
                    ));
                }
                if prev.time_lock != config.time_lock {
                    details.push(format!(
                        "timelock {}s -> {}s",
                        prev.time_lock, config.time_lock
                    ));
                }
                if prev.member_count != config.member_count {
                    details.push(format!(
                        "members {} -> {}",
                        prev.member_count, config.member_count
                    ));
                }

                let severity = if config.threshold < prev.threshold || config.time_lock < prev.time_lock {
                    "CRITICAL"
                } else {
                    "WARNING"
                };

                let event = MonitorEvent {
                    timestamp: chrono::Utc::now()
                        .format("%Y-%m-%d %H:%M:%S UTC")
                        .to_string(),
                    address: entry.address.clone(),
                    name: entry.name.clone(),
                    event_type: "config_changed".to_string(),
                    details: details.join(", "),
                    severity: severity.to_string(),
                };

                println!(
                    "  ALERT [{}]: {} - {}",
                    severity, entry.name, event.details
                );

                // Fire webhook if configured
                if let Some(ref webhook_url) = entry.webhook_url {
                    let payload = serde_json::json!({
                        "embeds": [{
                            "title": format!("Governance Alert: {}", entry.name),
                            "description": event.details,
                            "color": if severity == "CRITICAL" { 15158332 } else { 16776960 },
                            "fields": [
                                { "name": "Address", "value": entry.address, "inline": true },
                                { "name": "Severity", "value": severity, "inline": true },
                            ],
                        }],
                    });
                    let _ = reqwest::Client::new()
                        .post(webhook_url)
                        .json(&payload)
                        .send()
                        .await;
                }

                // Store event
                let mut events = state.events.lock().await;
                if events.len() >= 100 {
                    events.pop_back();
                }
                events.push_front(event);

                // Save versioned snapshot
                let _ = snapshot::save_snapshot_versioned(&pubkey, &config);
            }
        }

        // Always update latest snapshot
        let _ = snapshot::save_snapshot(&pubkey, &config);

        // Check nonce accounts
        let mut members_with_nonces: usize = 0;
        for member in &account.members {
            if let Ok(nonces) = fetch_nonce_accounts(&rpc, &member.key).await {
                if !nonces.is_empty() {
                    members_with_nonces += 1;
                }
            }
        }

        if members_with_nonces >= config.threshold as usize && members_with_nonces > 0 {
            let event = MonitorEvent {
                timestamp: chrono::Utc::now()
                    .format("%Y-%m-%d %H:%M:%S UTC")
                    .to_string(),
                address: entry.address.clone(),
                name: entry.name.clone(),
                event_type: "nonce_threshold_met".to_string(),
                details: format!(
                    "{} members with nonce accounts meets threshold of {}",
                    members_with_nonces, config.threshold
                ),
                severity: "CRITICAL".to_string(),
            };

            println!("  ALERT [CRITICAL]: {} - {}", entry.name, event.details);

            if let Some(ref webhook_url) = entry.webhook_url {
                let payload = serde_json::json!({
                    "embeds": [{
                        "title": format!("CRITICAL: Nonce Threshold Met - {}", entry.name),
                        "description": event.details,
                        "color": 15158332,
                        "fields": [
                            { "name": "Address", "value": entry.address, "inline": true },
                            { "name": "Action", "value": "Investigate immediately. Pre-signed transactions may exist.", "inline": false },
                        ],
                    }],
                });
                let _ = reqwest::Client::new()
                    .post(webhook_url)
                    .json(&payload)
                    .send()
                    .await;
            }

            let mut events = state.events.lock().await;
            if events.len() >= 100 {
                events.pop_back();
            }
            events.push_front(event);
        }
    }
}

/// Registry: show health status of all monitored multisigs.
async fn api_registry(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let protocols = state
        .registry
        .get("protocols")
        .and_then(|p| p.as_array())
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    let squads_program =
        Pubkey::from_str("SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf").unwrap();

    let mut results = Vec::new();
    for protocol in protocols {
        let name = protocol
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("Unknown");
        let addr = protocol
            .get("multisig_address")
            .and_then(|a| a.as_str())
            .unwrap_or("");

        let pubkey = match addr.parse::<Pubkey>() {
            Ok(pk) => pk,
            Err(_) => continue,
        };

        // Fetch config
        let config_result = fetch_multisig_config(&state.rpc, &pubkey).await;
        let (health_score, health_label, threshold_str, time_lock) = match &config_result {
            Ok(account) => {
                let config = MultisigConfig::from(account);
                let health = governance_health(&config);
                let label = match health.total {
                    80..=100 => "HEALTHY",
                    50..=79 => "AT RISK",
                    _ => "VULNERABLE",
                };
                (
                    health.total,
                    label,
                    format!("{}/{}", config.threshold, config.member_count),
                    config.time_lock,
                )
            }
            Err(_) => (0, "ERROR", "?/?".to_string(), 0),
        };

        // Vault balance (check indices 0-3)
        let mut vault_sol: f64 = 0.0;
        for vidx in 0..4u8 {
            let (vpda, _) = Pubkey::find_program_address(
                &[b"multisig", pubkey.as_ref(), b"vault", &[vidx]],
                &squads_program,
            );
            if let Ok(l) = state.rpc.get_balance(&vpda).await {
                vault_sol += l as f64 / 1_000_000_000.0;
            }
        }

        // Last activity
        let last_activity = {
            let sig_config = GetConfirmedSignaturesForAddress2Config {
                before: None,
                until: None,
                limit: Some(1),
                commitment: None,
            };
            match state
                .rpc
                .get_signatures_for_address_with_config(&pubkey, sig_config)
                .await
            {
                Ok(sigs) if !sigs.is_empty() => sigs[0].block_time.map(|ts| {
                    let dt = chrono::DateTime::from_timestamp(ts, 0).unwrap_or_default();
                    let ago = chrono::Utc::now().signed_duration_since(dt);
                    if ago.num_days() > 0 {
                        format!("{} day(s) ago", ago.num_days())
                    } else if ago.num_hours() > 0 {
                        format!("{} hour(s) ago", ago.num_hours())
                    } else {
                        format!("{} min ago", ago.num_minutes().max(1))
                    }
                }),
                _ => None,
            }
        };

        // Urgency
        let is_empty = vault_sol < 1.0;
        let is_dormant = last_activity.is_none();
        let urgency = match (health_score, is_empty, is_dormant) {
            (0..=49, false, false) => "CRITICAL",
            (0..=49, false, true) => "HIGH",
            (0..=49, true, _) => "LOW",
            (50..=79, false, _) => "MEDIUM",
            _ => "INFO",
        };

        results.push(serde_json::json!({
            "name": name,
            "address": addr,
            "health_score": health_score,
            "health_label": health_label,
            "urgency": urgency,
            "vault_sol": vault_sol,
            "threshold": threshold_str,
            "time_lock": time_lock,
            "last_activity": last_activity.unwrap_or_else(|| "unknown".to_string()),
        }));
    }

    Ok(Json(serde_json::json!({ "protocols": results })))
}

/// Query mainnet for real Squads v4 multisig statistics.
///
/// Uses Helius getProgramAccountsV2 (cursor-paginated, 5000/page) if
/// the RPC URL contains "helius". Falls back to standard getProgramAccounts
/// for other providers.
async fn compute_mainnet_stats(rpc: &RpcClient, rpc_url: &str) -> CachedStats {
    if rpc_url.contains("helius") {
        match compute_stats_helius_v2(rpc_url).await {
            Ok(stats) => return stats,
            Err(e) => {
                eprintln!("helius v2 stats failed ({}), falling back to standard gPA", e);
            }
        }
    }
    compute_stats_standard(rpc).await
}

/// Paginated stats via Helius getProgramAccountsV2.
async fn compute_stats_helius_v2(rpc_url: &str) -> Result<CachedStats, String> {
    use prefire_enrichment::multisig::multisig_discriminator;

    let disc = multisig_discriminator();
    let disc_b58 = bs58::encode(&disc).into_string();

    let client = reqwest::Client::new();
    let mut total: usize = 0;
    let mut vulnerable: usize = 0;
    let mut high_risk: usize = 0;
    let mut pagination_key: Option<String> = None;
    let mut page = 0u32;

    loop {
        page += 1;
        let mut config = serde_json::json!({
            "encoding": "base64",
            "filters": [{ "memcmp": { "offset": 0, "bytes": disc_b58 } }],
            "limit": 5000,
        });
        if let Some(ref key) = pagination_key {
            config["paginationKey"] = serde_json::json!(key);
        }

        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "1",
            "method": "getProgramAccountsV2",
            "params": [
                "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf",
                config,
            ],
        });

        let resp = client
            .post(rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("request failed: {}", e))?;

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("json parse failed: {}", e))?;

        if let Some(err) = json.get("error") {
            return Err(format!("RPC error: {}", err));
        }

        let result = json
            .get("result")
            .ok_or_else(|| "no result field in response".to_string())?;

        let accounts = result
            .get("accounts")
            .and_then(|a| a.as_array())
            .ok_or_else(|| "no accounts array".to_string())?;

        if accounts.is_empty() {
            break;
        }

        for acct in accounts {
            total += 1;
            // Decode base64 account data, skip 8-byte discriminator, Borsh-deserialize
            let data_arr = acct
                .get("account")
                .and_then(|a| a.get("data"))
                .and_then(|d| d.as_array());
            if let Some(arr) = data_arr {
                if let Some(b64) = arr.first().and_then(|v| v.as_str()) {
                    if let Ok(bytes) = base64::Engine::decode(
                        &base64::engine::general_purpose::STANDARD,
                        b64,
                    ) {
                        if bytes.len() > 8 {
                            let mut slice = &bytes[8..];
                            if let Ok(ms) =
                                <MultisigAccount as borsh::BorshDeserialize>::deserialize(
                                    &mut slice,
                                )
                            {
                                if ms.time_lock == 0 && ms.threshold >= 2 {
                                    vulnerable += 1;
                                    // High risk: <50% approval needed (the Drift pattern)
                                    let members = ms.members.len();
                                    if members > 0
                                        && (ms.threshold as usize).checked_mul(2).unwrap_or(0)
                                            < members
                                    {
                                        high_risk += 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Next page
        pagination_key = result
            .get("paginationKey")
            .and_then(|k| k.as_str())
            .map(|s| s.to_string());

        if pagination_key.is_none() {
            break;
        }

        println!("  page {}: {} accounts so far ({} vulnerable)", page, total, vulnerable);
    }

    let timestamp = chrono::Utc::now()
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string();
    println!(
        "stats: {} multisigs, {} zero-timelock, {} high-risk (<50% threshold)",
        total, vulnerable, high_risk
    );

    Ok(CachedStats {
        total_multisigs: total,
        zero_timelock_vulnerable: vulnerable,
        high_risk_count: high_risk,
        last_refreshed: timestamp,
    })
}

/// Fallback: standard getProgramAccounts (single call, may hit rate limits).
async fn compute_stats_standard(rpc: &RpcClient) -> CachedStats {
    use prefire_enrichment::multisig::multisig_discriminator;

    let squads_id = match Pubkey::from_str("SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf") {
        Ok(id) => id,
        Err(_) => {
            return CachedStats {
                total_multisigs: 0,
                zero_timelock_vulnerable: 0,
                high_risk_count: 0,
                last_refreshed: "error: invalid program ID".to_string(),
            };
        }
    };

    let disc = multisig_discriminator();
    let config = RpcProgramAccountsConfig {
        filters: Some(vec![RpcFilterType::Memcmp(Memcmp::new_raw_bytes(
            0,
            disc.to_vec(),
        ))]),
        ..Default::default()
    };

    let mut attempts = 0;
    let accounts = loop {
        match rpc
            .get_program_accounts_with_config(&squads_id, config.clone())
            .await
        {
            Ok(accs) => break accs,
            Err(e) => {
                attempts += 1;
                if attempts >= 3 {
                    eprintln!("stats query failed after {} attempts: {}", attempts, e);
                    return CachedStats {
                        total_multisigs: 0,
                        zero_timelock_vulnerable: 0,
                        high_risk_count: 0,
                        last_refreshed: format!("query failed: {} (will retry)", e),
                    };
                }
                let delay = std::time::Duration::from_secs(10 * attempts);
                eprintln!(
                    "stats attempt {} failed ({}), retrying in {}s...",
                    attempts,
                    e,
                    delay.as_secs()
                );
                tokio::time::sleep(delay).await;
            }
        }
    };

    let total = accounts.len();
    let mut vulnerable = 0;
    let mut high_risk: usize = 0;
    for (_pubkey, account) in &accounts {
        if account.data.len() < 9 {
            continue;
        }
        let mut slice = &account.data[8..];
        if let Ok(ms) = <MultisigAccount as borsh::BorshDeserialize>::deserialize(&mut slice) {
            if ms.time_lock == 0 && ms.threshold >= 2 {
                vulnerable += 1;
                let members = ms.members.len();
                if members > 0
                    && (ms.threshold as usize).checked_mul(2).unwrap_or(0) < members
                {
                    high_risk += 1;
                }
            }
        }
    }

    let timestamp = chrono::Utc::now()
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string();
    println!(
        "stats: {} multisigs, {} zero-timelock, {} high-risk (<50% threshold)",
        total, vulnerable, high_risk
    );

    CachedStats {
        total_multisigs: total,
        zero_timelock_vulnerable: vulnerable,
        high_risk_count: high_risk,
        last_refreshed: timestamp,
    }
}

