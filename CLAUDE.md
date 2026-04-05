# Prefire

Passive, permissionless Solana governance attack detection. Built for Colosseum Frontier hackathon.

## Stack
- Rust (off-chain binary, NOT a Solana program)
- solana-client / solana-sdk for RPC + tx parsing
- tokio async runtime
- axum for REST API (week 4)
- reqwest for alert webhooks

## Architecture
Single pipeline: Governance Watch → Retroactive Enrichment → Scoring → Alerts.
Stage 1 (governance watch) runs continuously. Stages 2-4 activate only on trigger.

## Crates
- `crates/monitor/` — Stage 1: RPC WebSocket subscriber + Squads/Realms instruction parsing
- `crates/enrichment/` — Stage 2: Retroactive nonce account + token mint scanning
- `crates/scoring/` — Stage 3: Signal combination + threat score computation
- `crates/alerts/` — Stage 4: Telegram, Discord, webhook notifications

## Security Conventions
- **No `unwrap()`** — use `?` or `.ok_or()` with descriptive errors
- **All arithmetic uses `checked_*`** — no silent overflow
- **No hardcoded secrets** — RPC URLs, bot tokens, webhook URLs from env vars or config
- **Validate all external data** — RPC responses, registry entries

## Commit Messages
Use conventional commits: `feat:`, `fix:`, `test:`, `docs:`, `refactor:`, `chore:`

## Key Program IDs
- System Program: `11111111111111111111111111111111`
- Squads v4: `SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf`
- Realms / SPL Governance: `GovER5Lthms3bLBqWub97yVrMmEogzX7xNjdXpPPCVZw`
- Token Program: `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`
