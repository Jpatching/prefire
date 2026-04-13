use std::str::FromStr;
use std::sync::Arc;

use solana_client::nonblocking::rpc_client::RpcClient;
use solana_client::rpc_config::RpcProgramAccountsConfig;
use solana_client::rpc_filter::{Memcmp, RpcFilterType};
use solana_sdk::pubkey::Pubkey;

use prefire_enrichment::multisig::{fetch_multisig_config, MultisigConfig};

const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
const NONCE_ACCOUNT_SIZE: u64 = 80;
// In a nonce account: 4 bytes version + 4 bytes state + 32 bytes authority
const NONCE_AUTHORITY_OFFSET: usize = 8;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: scan <multisig_address> [multisig_address ...]");
        eprintln!("       scan --registry config/registry.json");
        eprintln!("\nScans multisig members for durable nonce accounts.");
        eprintln!("Nonce accounts enable pre-signed transactions that can");
        eprintln!("be executed at any future time — the Drift attack vector.");
        std::process::exit(1);
    }

    let rpc_url = std::env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".to_string());
    let rpc = Arc::new(RpcClient::new(rpc_url));

    let multisig_addresses: Vec<String> = if args.get(1).map(|s| s.as_str()) == Some("--registry") {
        let path = args.get(2).ok_or("usage: scan --registry <file.json>")?;
        let content = std::fs::read_to_string(path)?;
        let registry: serde_json::Value = serde_json::from_str(&content)?;
        registry["protocols"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|p| p["multisig_address"].as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect()
    } else {
        args[1..].to_vec()
    };

    if multisig_addresses.is_empty() {
        eprintln!("no multisig addresses provided");
        std::process::exit(1);
    }

    let mut total_nonce_accounts = 0;
    let mut total_members_with_nonces = 0;

    for addr in &multisig_addresses {
        let pubkey = Pubkey::from_str(addr)?;
        println!("=== Multisig: {} ===", addr);

        // Fetch multisig config and full member list
        let account = match fetch_multisig_config(&rpc, &pubkey).await {
            Ok(a) => a,
            Err(e) => {
                eprintln!("  error fetching multisig: {}", e);
                continue;
            }
        };

        let config = MultisigConfig::from(&account);
        println!(
            "  threshold: {}/{} members ({} voters) | time_lock: {}s\n",
            config.threshold, config.member_count, config.voter_count, config.time_lock
        );

        let mut members_with_nonces = 0;
        let mut nonces_for_this_multisig = 0;

        for member in &account.members {
            let perms = format!(
                "{}{}{}",
                if member.permissions.mask & 1 != 0 { "I" } else { "" },
                if member.permissions.can_vote() { "V" } else { "" },
                if member.permissions.can_execute() { "E" } else { "" },
            );

            // Scan for nonce accounts where this member is the authority
            let nonce_count =
                count_nonce_accounts(&rpc, &member.key).await.unwrap_or(0);

            let marker = if nonce_count > 0 { " !!!" } else { "" };
            println!(
                "  [{}] {} — {} nonce accounts{}",
                perms, member.key, nonce_count, marker
            );

            if nonce_count > 0 {
                members_with_nonces += 1;
                nonces_for_this_multisig += nonce_count;
            }
        }

        println!();

        if members_with_nonces > 0 {
            let can_meet_threshold = members_with_nonces >= config.threshold as usize;

            if can_meet_threshold {
                println!(
                    "  !!! CRITICAL: {} members with nonce accounts >= threshold of {}",
                    members_with_nonces, config.threshold
                );
                println!(
                    "  These members could execute pre-signed governance transactions"
                );
                println!(
                    "  without other members' knowledge. {} nonce accounts total.",
                    nonces_for_this_multisig
                );
            } else {
                println!(
                    "  WARNING: {} member(s) with nonce accounts ({} total)",
                    members_with_nonces, nonces_for_this_multisig
                );
                println!(
                    "  Below threshold of {} — cannot unilaterally execute.",
                    config.threshold
                );
                println!("  Monitor for additional nonce account creation.");
            }

            if config.time_lock == 0 {
                println!(
                    "  RISK FACTOR: time_lock=0 — no delay between approval and execution"
                );
            }
        } else {
            println!("  OK: No members have active nonce accounts.");
        }

        println!();
        total_nonce_accounts += nonces_for_this_multisig;
        total_members_with_nonces += members_with_nonces;
    }

    // Summary
    println!("{:-<60}", "");
    println!(
        "Scanned {} multisig(s): {} member(s) with nonce accounts, {} nonce accounts total",
        multisig_addresses.len(),
        total_members_with_nonces,
        total_nonce_accounts,
    );

    Ok(())
}

/// Count durable nonce accounts where `authority` is the nonce authority.
/// Uses getProgramAccounts with filters: dataSize=80 + memcmp at offset 8.
async fn count_nonce_accounts(
    rpc: &RpcClient,
    authority: &Pubkey,
) -> Result<usize, Box<dyn std::error::Error>> {
    let system_program = Pubkey::from_str(SYSTEM_PROGRAM)?;

    let config = RpcProgramAccountsConfig {
        filters: Some(vec![
            RpcFilterType::DataSize(NONCE_ACCOUNT_SIZE),
            RpcFilterType::Memcmp(Memcmp::new_raw_bytes(
                NONCE_AUTHORITY_OFFSET,
                authority.to_bytes().to_vec(),
            )),
        ]),
        ..Default::default()
    };

    let accounts = rpc
        .get_program_accounts_with_config(&system_program, config)
        .await?;

    Ok(accounts.len())
}
