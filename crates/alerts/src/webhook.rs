/// Send a JSON payload to a webhook URL.
/// Used for Discord webhooks, Slack incoming webhooks, or any HTTP endpoint.
/// Fails silently -- alerting should never crash the monitor.
pub async fn send_webhook(url: &str, payload: &serde_json::Value) {
    let client = reqwest::Client::new();

    // Discord webhooks expect { "content": "text" } or { "embeds": [...] }
    // We wrap our payload in a Discord-compatible format
    let discord_payload = serde_json::json!({
        "embeds": [{
            "title": format!(
                "Prefire Alert: {} ({}/100)",
                payload.get("verdict").and_then(|v| v.as_str()).unwrap_or("UNKNOWN"),
                payload.get("score").and_then(|v| v.as_u64()).unwrap_or(0),
            ),
            "color": match payload.get("score").and_then(|v| v.as_u64()).unwrap_or(0) {
                0..=30 => 0x2ECC71,   // green
                31..=60 => 0xF39C12,  // orange
                _ => 0xE74C3C,        // red
            },
            "fields": [
                {
                    "name": "Event",
                    "value": payload.get("event").and_then(|v| v.as_str()).unwrap_or("unknown"),
                    "inline": true,
                },
                {
                    "name": "Durable Nonce",
                    "value": if payload.get("uses_durable_nonce").and_then(|v| v.as_bool()).unwrap_or(false) {
                        "YES"
                    } else {
                        "no"
                    },
                    "inline": true,
                },
                {
                    "name": "Signature",
                    "value": format!(
                        "`{}`",
                        payload.get("signature").and_then(|v| v.as_str()).unwrap_or("unknown")
                    ),
                    "inline": false,
                },
            ],
            "footer": {
                "text": "Prefire — Solana Governance Attack Detection"
            }
        }]
    });

    match client.post(url).json(&discord_payload).send().await {
        Ok(resp) if resp.status().is_success() => {}
        Ok(resp) => {
            eprintln!("webhook returned {}", resp.status());
        }
        Err(e) => {
            eprintln!("webhook error: {}", e);
        }
    }
}
