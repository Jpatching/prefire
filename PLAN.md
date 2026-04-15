# Prefire: Current State, Issues, and Next Steps

Last verified: 2026-04-15 against live Solana mainnet

---

## What verifiably works (tested live)

### Health check (`GET /api/health/{address}`)
- Fetches real multisig config from mainnet via RPC
- Correctly scores governance health (0-100)
- Returns actionable recommendations
- Shows nonce account addresses per member
- Compares config to Drift's at time of exploit

**Live test result** (active multisig `FvCjcnh9...`, tx minutes ago):
```
Score: 45/100 VULNERABLE
Config: threshold=2/3, timelock=0s
Risk: -40 zero_timelock
Risk: -15 drift_pattern
Rec: Add a timelock (recommended: 86400s / 24 hours)
```

### Transaction replay (`GET /api/replay/{signature}`)
- Fetches real historical transactions from mainnet
- Extracts governance events (ProposalCreate, ProposalApprove, ConfigChange, VaultTransfer)
- Scores each event with 8 signals
- SOL/token outflow now extracted from transaction metadata

**Live test result** (recent active tx):
```
event: ProposalApproved
multisig: threshold=2/3, time_lock=0s
SCORE: 10/100 SAFE
  +10 zero_timelock
```

### Nonce scanning (`GET /api/scan/{address}`)
- Returns real nonce account pubkeys per member (not just counts)
- Flags when nonce holders can meet signing threshold

### Dashboard
- All three features render correctly (health, scan, replay)
- Stats section shows live data with refresh timestamp

### Tests
- 23 tests across 3 crates, all passing
- 5 binaries compile with zero warnings

---

## Known issues to fix

### 1. `drift_pattern` signal is too aggressive
**Problem**: Fires on ANY multisig with `timelock=0 + threshold<3 + members>=3`. This catches a 2/3 multisig (66% majority -- reasonable) the same as Drift's 2/5 (40% -- dangerous).

**Fix**: Tighten to only fire when `threshold * 2 < member_count` (less than 50% approval needed). The `low_threshold_ratio` signal already checks this, but `drift_pattern` doesn't. Either:
- Remove `drift_pattern` and rely on `low_threshold_ratio` + `zero_timelock` combination
- Or change `drift_pattern` condition to `threshold * 2 < member_count`

**File**: `crates/scoring/src/lib.rs:232-248`

### 2. No activity context on multisigs
**Problem**: An abandoned, already-exploited multisig (like Drift's) shows the same "VULNERABLE" as a live one managing $100M. No way to distinguish.

**Fix**: Add a "last activity" check. After fetching multisig config, query `getSignaturesForAddress` for the multisig to see when it was last used. Display this in the health response:
- "Last activity: 2 hours ago" (active, risk matters)
- "Last activity: 14 days ago" (possibly abandoned, lower urgency)
- "No recent activity" (dormant)

**Files**: `crates/enrichment/src/lib.rs` or `src/bin/api.rs` health handler

### 3. Stats endpoint fails on free RPC tier
**Problem**: `getProgramAccounts` for the entire Squads program hits Helius rate limits ("account index service overloaded"). Retry logic works but free tier can't handle it.

**Options**:
- Pre-compute stats with a dedicated script, cache to `data/stats_cache.json`
- Use Helius DAS API if available for this use case
- Accept that stats refresh takes multiple retries with backoff
- For hackathon: run the scan once during off-peak, cache the result

**File**: `src/bin/api.rs` `compute_mainnet_stats()`

### 4. Recommendations are generic
**Problem**: Every zero-timelock multisig gets "Add a timelock (24h)". Doesn't account for:
- Vault balance (is there anything worth stealing?)
- Activity level (is this actively used?)
- Member count context (2/3 is fine, 2/10 is not)

**Fix**: Make recommendations contextual. Instead of static strings, generate them based on the full picture. e.g.:
- "Your 2/5 threshold means only 40% approval is needed. Increase to 3/5 (60%)"
- If vault has >$1M: "High-value vault with zero timelock. Critical priority."

### 5. Dashboard should be the primary interface
**Problem**: Some features only work well in CLI (scan output with nonce addresses, health monitoring daemon logs). Dashboard should show everything.

**Improvements needed**:
- Health check should be the default/hero section (currently it's after stats)
- Add "recent activity" indicator per multisig
- Add ability to save/bookmark multisig addresses for monitoring
- Show example multisig addresses users can try

---

## Next improvements (prioritized for hackathon)

### Priority 1: Fix scoring accuracy
- Tighten `drift_pattern` to only fire on <50% threshold
- Add last-activity timestamp to health response
- Make recommendations proportional to risk

### Priority 2: Dashboard as the demo surface
- Add example addresses users can click to try
- Make health check the hero section
- Show a "How it works" flow: paste address -> see risk -> get recommendations
- Better mobile/responsive layout for demo presentations

### Priority 3: Registry-based monitoring view
- Show all registered multisigs and their health on one dashboard page
- Color-coded risk indicators
- Config change history per multisig

### Priority 4: Pre-compute stats
- Write a standalone script that runs `getProgramAccounts`, caches to disk
- API loads from cache, shows "last computed: X hours ago"
- Run during off-peak hours or with paid RPC tier

### Priority 5: Proposal content simulation (ROADMAP Phase 2)
- Decode what vault transactions WOULD DO if executed
- "This proposal transfers 50,000 SOL to address X"
- Strongest differentiation from existing tools

---

## What security teams would pay for

Based on Drift post-mortem recommendations from OtterSec, BlockSec, Chainalysis:

1. **Continuous governance health monitoring** -- "your multisig config changed, here's the risk delta" (we have this in `monitor_health`)
2. **Pre-attack pattern detection** -- "nonce accounts were created for 2 of your 5 signers" (we have this)
3. **Actionable recommendations** -- not just "you're at risk" but specific config changes (we have this, needs refinement)
4. **Proposal intent analysis** -- "this proposal would transfer your entire vault to an unknown address" (not built yet, highest value add)
5. **Integration with existing workflows** -- Slack/Discord alerts, PagerDuty (webhook exists, routing config not built)

---

## Hackathon demo flow

1. Open dashboard
2. Stats show live mainnet numbers (if cached) with "X multisigs vulnerable"
3. Paste a LIVE active multisig address into health check
4. Show risk score, breakdown, recommendations
5. "This is the same pattern as Drift before the exploit"
6. Replay a Drift exploit transaction to show detection
7. "We catch the setup phase, not just the execution"
