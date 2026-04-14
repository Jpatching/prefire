# Prefire Roadmap: From Detection to Prevention

## Where We Are (Hackathon MVP)

Prefire detects governance attacks at **execution time** and scores multisig **configuration risk**. Proven against the $285M Drift exploit with 100% accuracy.

**The honest gap**: execution-time detection gives you 1 second to react. That's not enough. Accounts are already drained by the time the alert fires.

This roadmap focuses on what's needed to detect and stop attacks at the **setup phase** -- days or weeks before execution.

---

## Phase 1: Transaction-Level Nonce Surveillance (Prevention)

**Problem**: Current nonce scan only checks if multisig MEMBERS own nonce accounts. In the Drift attack, the ATTACKER created the nonce accounts under their own wallet. Our scan misses this.

**Solution**: Monitor all transactions involving a registered multisig's accounts. When any transaction involving a multisig member uses a durable nonce, flag it -- regardless of who owns the nonce account.

### What to build:
- **Transaction history scanner**: For each registered multisig member, fetch recent transaction history via `getSignaturesForAddress`
- **Nonce-in-transaction detector**: For each transaction, check if `SysvarRecentBlockhashes` is in the account keys (same detection we use in the scoring engine)
- **Alert**: "Member X of multisig Y signed a transaction using a durable nonce on [date]. This transaction has not yet been submitted to the multisig."
- **Continuous mode**: Poll member transaction history every N minutes for new durable nonce activity

### Why this catches the Drift setup:
The compromised Drift signers pre-signed the exploit transactions using durable nonces. Those signing events would appear in the signers' transaction history. Even though the nonce accounts belong to the attacker, the SIGNING activity by multisig members is visible.

### Limitation:
If the attacker has the signer sign on a compromised device and the signing happens entirely off-chain (transaction never submitted until the attack), this won't catch it. The Drift attack may have worked this way -- the signers approved on compromised devices, the signed bytes were exfiltrated, and only the attacker's submission transactions appear on-chain. This is the fundamental limitation of on-chain monitoring against off-chain social engineering.

---

## Phase 2: Proposal Content Simulation

**Problem**: We detect that a ProposalCreate happened, but we don't know WHAT the proposal does. A proposal to transfer 1 SOL to a known address is different from a proposal to transfer the entire vault to an unknown address.

**Solution**: When a proposal is created, simulate what it would do if executed.

### What to build:
- **Vault transaction parser**: Decode the instruction data inside `VaultTransactionCreate` to understand what the proposed transaction would do
- **Transfer analysis**: Calculate the value of proposed transfers (SOL amount, token amounts, USD value via price feed)
- **Destination analysis**: Check if the destination address has any on-chain history, is associated with known protocols, or is freshly created
- **Scoring integration**: Add signals for high-value transfers and unknown destinations

### New scoring signals:
| Signal | Points | Fires When |
|--------|--------|-----------|
| High-value transfer | +15 | Proposed transfer > 50% of vault balance |
| Unknown destination | +10 | Destination address has < 5 historical transactions |
| Admin transfer | +20 | Proposal changes program authority or upgrade key |

---

## Phase 3: Baseline Behavior + Anomaly Detection

**Problem**: Signal-based detection only catches patterns we've defined. A novel attack vector scores low.

**Solution**: Build per-multisig behavioral baselines. Flag deviations.

### What to build:
- **Event history database**: Store all governance events per multisig in SQLite (event type, timestamp, signers, score)
- **Baseline computation**: Calculate normal patterns per multisig:
  - Average time between proposal create and approval
  - Typical number of proposals per week
  - Usual signers and their activity patterns
  - Normal transfer sizes
- **Anomaly signals**: Fire when current activity deviates from baseline
  - "This multisig normally takes 48 hours to approve. This proposal was approved in 0 seconds."
  - "This member has never signed a governance transaction before."
  - "Transfer size is 100x the average for this multisig."

### Scoring integration:
| Signal | Points | Fires When |
|--------|--------|-----------|
| Abnormal approval speed | +20 | Approval time < 10% of historical average |
| New signer | +10 | Signer has no history with this multisig |
| Unusual transfer size | +15 | Transfer > 5x historical average |

---

## Phase 4: Protocol Integration Layer

**Problem**: Security teams don't run CLI tools. Protocols need Prefire integrated into their operational workflows.

### What to build:
- **REST API** (started): Expand with WebSocket streaming, historical queries, multisig registration
- **Protocol registry**: Teams register their multisig addresses. Prefire monitors them continuously.
- **Alert routing**: Configurable per-protocol: Slack, Discord, PagerDuty, email, webhook
- **Circuit breaker hooks**: When CRITICAL fires, call a protocol-specific endpoint to trigger emergency pause. Requires per-protocol integration:
  - Protocol exposes a "pause" instruction
  - Prefire holds a pre-signed pause transaction (via its own durable nonce, ironically)
  - On CRITICAL, submit the pause transaction
- **Dashboard**: Real-time event feed, score history per multisig, governance health trends

---

## Phase 5: Ecosystem Coverage

**Problem**: Only Squads v4 supported. Other governance programs are also targets.

### What to build:
- **Realms / SPL Governance**: Instruction parsing for the Realms program (`GovER5Lthms3bLBqWub97yVrMmEogzX7xNjdXpPPCVZw`). Mango Markets was exploited via Realms governance.
- **Marinade Native Staking**: Custom governance for validator management
- **Program upgrade authorities**: Detect when a program's upgrade authority is transferred (common precursor to rug pulls)
- **Token mint authority changes**: Detect when mint authority is transferred or minting occurs outside normal patterns

---

## Phase 6: SIRN Integration

**Problem**: Detection alone doesn't stop attacks. Response coordination does.

### What to build:
- **SIRN API integration**: Feed CRITICAL alerts to the Solana Incident Response Network (OtterSec, Neodyme, Squads, ZeroShadow)
- **Incident playbook**: When CRITICAL fires, auto-generate an incident report:
  - What happened (event timeline)
  - What's at risk (vault balances, protocol TVL)
  - Who to contact (multisig members)
  - Recommended actions (advance nonces, pause protocol, alert exchanges)
- **Fund tracing**: Track where drained funds go (bridge transfers, DEX swaps, exchange deposits)

---

## What Cannot Be Solved By On-Chain Monitoring

Being honest about hard limits:

1. **Off-chain social engineering**: If an attacker compromises a signer's device and extracts signed transaction bytes without any on-chain footprint, no monitor can detect it. The only defense is operational security (hardware wallets, air-gapped signing, security training).

2. **1-second execution window**: A pre-signed durable nonce attack submits and completes in 1 second. Automated circuit breakers MIGHT beat it. Human response cannot.

3. **Legitimate durable nonce usage**: Cold wallet signing, institutional custody workflows, and multi-day governance processes legitimately use durable nonces. Prefire flags these as SUSPICIOUS, not CRITICAL. The false positive concern is real but manageable -- SUSPICIOUS means "investigate," not "panic."

4. **Zero-day governance bugs**: If the Squads program itself has an unaudited vulnerability, Prefire can't detect exploitation of unknown code paths. This requires formal verification (STRIDE covers this).

---

## Priority Order

| Phase | Impact | Effort | Timeline |
|-------|--------|--------|----------|
| 1. Transaction-level nonce surveillance | Highest -- catches setup phase | Medium | 1-2 weeks |
| 2. Proposal content simulation | High -- understands attack intent | Medium | 1-2 weeks |
| 3. Baseline behavior + anomaly detection | High -- catches novel attacks | High | 3-4 weeks |
| 4. Protocol integration layer | Critical for adoption | High | 2-3 weeks |
| 5. Ecosystem coverage (Realms, etc.) | Medium -- expands market | Medium | 2-3 weeks |
| 6. SIRN integration | High -- enables response | Low | 1 week |

**Phase 1 is the immediate priority.** It's the difference between "we detect attacks" and "we detect attack SETUP." That's the pitch that gets security teams to adopt.
