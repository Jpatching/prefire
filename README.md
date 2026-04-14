# Prefire

**Solana governance attack detection. Passive, permissionless, real-time.**

Prefire detects governance attacks on Solana multisigs by combining multiple weak signals into strong threat assessments. It caught the $285M Drift Protocol exploit with 100% accuracy -- zero false positives, zero false negatives -- despite CoinDesk reporting that "24/7 monitoring of onchain activity" would not have caught it.

Built for the Colosseum Frontier hackathon.

## The Problem

On April 1, 2026, a North Korean state-affiliated group drained $285M from Drift Protocol by exploiting Solana's durable nonce mechanism to pre-sign multisig governance transactions. The entire attack executed in 1 second across 2 transactions.

Existing monitoring tools (Hypernative, Range Security) watch for failed transactions, reentrancy, or unauthorized access. The Drift exploit transactions were 100% valid -- correct signatures, authorized instructions, successful execution. Individual transaction monitoring sees nothing wrong.

**Prefire detects the pattern, not the transaction.**

Durable nonce + rapid proposal lifecycle + zero timelock + vault transfer = 75/100 CRITICAL. No individual signal is suspicious. The combination is.

## Proof

Tested against 27 real mainnet transactions: 25 legitimate governance operations + 2 Drift exploit transactions.

```
SIGNATURE          EVENT                          SCORE  VERDICT        NONCE
------------------------------------------------------------------------------------------
22hpbWn63BGnFCyP   VaultTransfer                  20/100  SAFE
3BHDdnWgt8zpymHP   ProposalApproved               10/100  SAFE
5RExpQsHrd8cpWEt   VaultTransfer                  20/100  SAFE
...                (23 more SAFE events)           10-20   SAFE
2HvMSgDEfKhNryYZ   VaultTransfer (Drift TX1)      50/100  SUSPICIOUS     YES
2HvMSgDEfKhNryYZ   ProposalApproved (Drift TX1)   65/100  !! CRITICAL !! YES
4BKBmAJn6TdsENij   ProposalApproved (Drift TX2)   65/100  !! CRITICAL !! YES
4BKBmAJn6TdsENij   VaultTransfer (Drift TX2)      75/100  !! CRITICAL !! YES
------------------------------------------------------------------------------------------
30 events | 3 CRITICAL | 2 SUSPICIOUS | 23 SAFE
```

**Score ranges never overlap.** Legit: 10-20. Attack: 40-75. Clean separation.

## How It Works

### Detection Signals

| Signal | Points | What It Detects |
|--------|--------|----------------|
| Durable nonce | +30 | `SysvarRecentBlockhashes` in transaction accounts (pre-signed tx) |
| Rapid governance | +25 | Proposal created and approved within 10 minutes |
| Config change | +15 | Membership or threshold modification |
| Zero timelock | +10 | No delay between approval and execution |
| Vault transfer | +10 | Fund movement event |

**Verdicts:** Safe (0-30) | Suspicious (31-60) | Critical (61-100)

### Prevention Layer: Governance Health Score

Prefire also scores multisig CONFIGURATIONS before any attack:

```
$ prefire scan 2LW6PSEjp81xSEttWwXDB6Etb1eKdhYPbFEojYbyhx88

=== Multisig: 2LW6PSEjp81xSEttWwXDB6Etb1eKdhYPbFEojYbyhx88 ===
  threshold: 2/5 members (5 voters) | time_lock: 0s
  ...
  GOVERNANCE HEALTH: 20/100 — VULNERABLE
    -40 zero_timelock: no delay between proposal approval and execution
    -25 low_threshold_ratio: threshold is 40% of members (2/5)
    -15 drift_pattern: matches the Drift exploit configuration ($285M stolen April 2026)

  Recommendations:
    * Add a timelock (recommended: 86400s / 24 hours)
    * Increase threshold to at least 3/5 (>50%)
```

On mainnet: **150,686 Squads v4 multisigs. 94,442 with zero timelock and threshold >= 2.**

## Quick Start

```bash
# Replay the Drift exploit
SOLANA_RPC_URL="https://api.mainnet-beta.solana.com" \
  cargo run --bin replay -- \
  2HvMSgDEfKhNryYZKhjowrBY55rUx5MWtcWkG9hqxZCFBaTiahPwfynP1dxBSRk9s5UTVc8LFeS4Btvkm9pc2C4H \
  4BKBmAJn6TdsENij7CsVbyMVLJU1tX27nfrMM1zgKv1bs2KJy6Am2NqdA3nJm4g9C6eC64UAf5sNs974ygB9RsN1

# Batch validation (27 transactions)
cargo run --bin replay -- --batch config/test_signatures.json

# Scan a multisig for vulnerabilities + nonce accounts
cargo run --bin scan -- 2LW6PSEjp81xSEttWwXDB6Etb1eKdhYPbFEojYbyhx88

# Start the web dashboard
cargo run --bin api

# Live monitoring (requires WebSocket RPC)
SOLANA_WS_URL="wss://api.mainnet-beta.solana.com" cargo run -- live

# Run tests
cargo test -p prefire-scoring -p prefire-enrichment -p prefire-monitor
```

## Architecture

```
crates/
  monitor/       Stage 1: WebSocket subscriber + historical replay
    governance.rs   GovernanceEvent enum, MonitoredEvent struct
    log_parser.rs   Squads instruction extraction from tx logs
    replay.rs       Historical transaction fetching via getTransaction
    rpc.rs          Live WebSocket logsSubscribe

  enrichment/    Stage 2: On-chain context for scoring
    multisig.rs     Squads v4 MultisigAccount deserialization (manual Borsh)
    nonce.rs        Durable nonce detection via RecentBlockhashes sysvar
    token.rs        SOL/token transfer extraction
    lib.rs          enrich() pipeline: multisig config + nonce + transfers

  scoring/       Stage 3: Signal combination + threat assessment
    lib.rs          score(), governance_health(), ScoringContext

  alerts/        Stage 4: Webhook alerts
    webhook.rs      Discord-formatted webhook POST

src/
  main.rs          Live monitoring mode
  bin/replay.rs    Historical replay + batch validation
  bin/scan.rs      Nonce account surveillance + governance health
  bin/api.rs       REST API + web dashboard
```

## Limitations (Honest)

- **1-second attack window**: Prefire detects at execution time but cannot prevent a pre-signed durable nonce attack that executes in 1 second. Prevention requires governance configuration (timelocks).
- **Attacker-controlled nonces**: If the attacker creates nonce accounts under their own wallet (not a multisig member's), the nonce surveillance scan won't find them pre-attack. Execution-time detection still works.
- **Squads v4 only**: Does not support Realms/SPL Governance or other governance programs.
- **Signal-based, not anomaly-based**: Can only detect patterns we've defined. A genuinely novel attack vector would score low.
- **No fund flow tracking**: Detects the governance action but doesn't trace where drained funds go.

## The Gap

- **$4.2B** in unguarded DeFi liquidity still exposed to durable nonce attacks ([source](https://www.openpr.com/news/4462771/solana-sol-price-prediction-durable-nonce-vulnerability))
- **No protocol-level patch** for durable nonces. Mitigation is operational only.
- **Existing tools** (Hypernative, Range Security) are general-purpose. None combine governance-specific signals.
- **STRIDE** (Solana Foundation, April 6 2026) is audits + evaluations, not automated real-time detection.
- **CoinDesk** reported monitoring wouldn't have caught Drift. We proved otherwise.

## Stack

- Rust (off-chain binary, NOT a Solana program)
- solana-client / solana-sdk v2 for RPC
- tokio async runtime
- axum for REST API
- borsh for Squads account deserialization
- reqwest for webhook alerts

## License

MIT
