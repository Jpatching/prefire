use std::str::FromStr;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, Json};
use axum::routing::get;
use axum::Router;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_client::rpc_config::RpcProgramAccountsConfig;
use solana_client::rpc_filter::{Memcmp, RpcFilterType};
use solana_sdk::pubkey::Pubkey;

use prefire_enrichment::enrich_full;
use prefire_enrichment::multisig::{fetch_multisig_config, MultisigConfig, MultisigAccount};
use prefire_enrichment::nonce::fetch_nonce_accounts;
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

struct AppState {
    rpc: Arc<RpcClient>,
    scoring_ctx: Mutex<ScoringContext>,
    stats: Mutex<CachedStats>,
}

#[tokio::main]
async fn main() {
    let rpc_url = std::env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".to_string());
    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());

    let rpc = Arc::new(RpcClient::new(rpc_url));

    // Load cached stats from disk if available, otherwise show computing state
    let initial_stats = load_cached_stats().unwrap_or(CachedStats {
        total_multisigs: 0,
        zero_timelock_vulnerable: 0,
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

    let state = Arc::new(AppState {
        rpc,
        scoring_ctx: Mutex::new(ScoringContext::new()),
        stats: Mutex::new(initial_stats),
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
            println!("refreshing mainnet stats via getProgramAccounts...");
            let refreshed = compute_mainnet_stats(&bg_state.rpc).await;
            if refreshed.total_multisigs > 0 {
                save_cached_stats(&refreshed);
                *bg_state.stats.lock().await = refreshed;
                println!("stats refreshed and cached to disk");
            }
            tokio::time::sleep(std::time::Duration::from_secs(7200)).await;
        }
    });

    let app = Router::new()
        .route("/", get(dashboard))
        .route("/api/scan/{address}", get(api_scan))
        .route("/api/replay/{signature}", get(api_replay))
        .route("/api/health/{address}", get(api_health))
        .route("/api/stats", get(api_stats))
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

    Ok(Json(serde_json::json!({
        "address": address,
        "health_score": health.total,
        "health_label": health_label,
        "config": {
            "threshold": config.threshold,
            "member_count": config.member_count,
            "voter_count": config.voter_count,
            "time_lock": config.time_lock,
        },
        "risks": health.risks,
        "recommendations": all_recommendations,
        "nonce_summary": {
            "members_with_nonces": members_with_nonces,
            "total_nonce_accounts": total_nonces,
            "risk_level": nonce_risk,
        },
        "members": members,
        "drift_comparison": {
            "note": "Drift Protocol was exploited with threshold=2/5, timelock=0s",
            "drift_threshold": "2/5",
            "drift_timelock": 0,
            "drift_health_score": 20,
            "your_threshold": format!("{}/{}", config.threshold, config.member_count),
            "your_timelock": config.time_lock,
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
        "zero_timelock_with_threshold_gte_2": stats.zero_timelock_vulnerable,
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

/// Query mainnet for real Squads v4 multisig statistics.
/// Uses getProgramAccounts with discriminator filter, then deserializes
/// each to check threshold/timelock configuration.
///
/// This is an expensive query (scans all Squads accounts). Runs in background
/// and caches results. Retries with backoff on RPC overload.
async fn compute_mainnet_stats(rpc: &RpcClient) -> CachedStats {
    use prefire_enrichment::multisig::multisig_discriminator;

    let squads_id = match Pubkey::from_str("SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf") {
        Ok(id) => id,
        Err(_) => {
            return CachedStats {
                total_multisigs: 0,
                zero_timelock_vulnerable: 0,
                last_refreshed: "error: invalid program ID".to_string(),
            };
        }
    };

    let disc = multisig_discriminator();

    // Filter by discriminator to only get Multisig accounts (not Proposals,
    // VaultTransactions, etc). This is the most selective filter available.
    let config = RpcProgramAccountsConfig {
        filters: Some(vec![
            RpcFilterType::Memcmp(Memcmp::new_raw_bytes(0, disc.to_vec())),
        ]),
        ..Default::default()
    };

    // Retry with backoff if RPC is overloaded
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
                        last_refreshed: format!(
                            "query failed: {} (will retry in 30 min)",
                            e
                        ),
                    };
                }
                let delay = std::time::Duration::from_secs(10 * attempts);
                eprintln!(
                    "stats query attempt {} failed ({}), retrying in {}s...",
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

    for (_pubkey, account) in &accounts {
        if account.data.len() < 9 {
            continue;
        }
        let mut slice = &account.data[8..];
        if let Ok(ms) = <MultisigAccount as borsh::BorshDeserialize>::deserialize(&mut slice) {
            if ms.time_lock == 0 && ms.threshold >= 2 {
                vulnerable += 1;
            }
        }
    }

    let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
    println!(
        "stats: {} multisigs, {} vulnerable (zero timelock + threshold >= 2)",
        total, vulnerable
    );

    CachedStats {
        total_multisigs: total,
        zero_timelock_vulnerable: vulnerable,
        last_refreshed: timestamp,
    }
}

