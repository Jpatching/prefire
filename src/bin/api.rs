use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, Json};
use axum::routing::get;
use axum::Router;
use solana_client::nonblocking::rpc_client::RpcClient;

use prefire_enrichment::enrich;
use prefire_enrichment::multisig::{fetch_multisig_config, MultisigConfig};
use prefire_scoring::{score_with_context, ScoringContext};

use tokio::sync::Mutex;

struct AppState {
    rpc: Arc<RpcClient>,
    scoring_ctx: Mutex<ScoringContext>,
}

#[tokio::main]
async fn main() {
    let rpc_url = std::env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".to_string());
    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());

    let state = Arc::new(AppState {
        rpc: Arc::new(RpcClient::new(rpc_url)),
        scoring_ctx: Mutex::new(ScoringContext::new()),
    });

    let app = Router::new()
        .route("/", get(dashboard))
        .route("/api/scan/{address}", get(api_scan))
        .route("/api/replay/{signature}", get(api_replay))
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
    for member in &account.members {
        let nonce_count = count_nonce_accounts(&state.rpc, &member.key)
            .await
            .unwrap_or(0);
        members.push(serde_json::json!({
            "key": member.key.to_string(),
            "can_vote": member.permissions.can_vote(),
            "can_execute": member.permissions.can_execute(),
            "nonce_accounts": nonce_count,
        }));
    }

    let members_with_nonces = members
        .iter()
        .filter(|m| m["nonce_accounts"].as_u64().unwrap_or(0) > 0)
        .count();
    let total_nonces: u64 = members
        .iter()
        .map(|m| m["nonce_accounts"].as_u64().unwrap_or(0))
        .sum();

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
        let enriched = enrich(&state.rpc, event)
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

/// Overall stats
async fn api_stats() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "total_multisigs_on_mainnet": 150686,
        "zero_timelock_with_threshold_gte_2": 94442,
        "known_exploits_detected": 1,
        "exploit_name": "Drift Protocol ($285M, April 2026)",
        "signals": [
            "durable_nonce (30 pts)",
            "rapid_governance (25 pts)",
            "config_change (15 pts)",
            "zero_timelock (10 pts)",
            "vault_transfer (10 pts)",
        ],
    }))
}

/// Count nonce accounts for a given authority (reused from scan binary)
async fn count_nonce_accounts(
    rpc: &RpcClient,
    authority: &solana_sdk::pubkey::Pubkey,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    use solana_client::rpc_config::RpcProgramAccountsConfig;
    use solana_client::rpc_filter::{Memcmp, RpcFilterType};
    use std::str::FromStr;

    let system_program =
        solana_sdk::pubkey::Pubkey::from_str("11111111111111111111111111111111")?;

    let config = RpcProgramAccountsConfig {
        filters: Some(vec![
            RpcFilterType::DataSize(80),
            RpcFilterType::Memcmp(Memcmp::new_raw_bytes(8, authority.to_bytes().to_vec())),
        ]),
        ..Default::default()
    };

    let accounts = rpc
        .get_program_accounts_with_config(&system_program, config)
        .await?;

    Ok(accounts.len())
}
