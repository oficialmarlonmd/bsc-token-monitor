# BSC Token Monitor

A comprehensive Python-based **Binance Smart Chain (BSC) token security analyzer
and monitoring system** built for educational purposes.

> ⚠️ **Disclaimer**: This project is for **educational purposes only**.
> Interacting with DeFi protocols carries significant financial risk.
> Never invest money you cannot afford to lose.  Always test with small
> amounts first.

---

## Features

| Component | Description |
|---|---|
| **Token Security Validator** | LP burn check, ownership renouncement, honeypot detection, risk scoring |
| **Contract Analysis Engine** | BSCScan ABI/source fetch, hidden function detection, tax extraction |
| **Web3 Integration** | BSC RPC connection, transaction simulation, buy/sell execution |
| **Data Models** | `TokenInfo`, `SecurityAudit`, `TransactionRecord`, `MonitoringLog` |
| **Monitoring & Alerting** | Real-time block polling, PairCreated event detection |
| **Decision Engine** | JSON output ready for Claude / external AI agents |
| **Database** | SQLite-backed transaction and audit history |

---

## Project Structure

```
bsc-token-monitor/
├── main.py                  # Entry point (CLI)
├── requirements.txt         # Python dependencies
├── .env.example             # Environment variable template
├── src/
│   ├── __init__.py
│   ├── models.py            # Data models
│   ├── web3_client.py       # BSC/Web3 interaction layer
│   ├── contract_analyzer.py # BSCScan + contract inspection
│   ├── security_validator.py# Security pipeline & risk scoring
│   ├── decision_engine.py   # JSON decision output
│   ├── database.py          # SQLite persistence
│   └── monitor.py           # Real-time block monitor
└── tests/
    ├── test_models.py
    ├── test_security_validator.py
    ├── test_contract_analyzer.py
    ├── test_decision_engine.py
    └── test_database.py
```

---

## Quick Start

### 1. Clone and install dependencies

```bash
git clone https://github.com/oficialmarlonmd/bsc-token-monitor.git
cd bsc-token-monitor
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env and fill in your values
```

Required values in `.env`:

| Variable | Description |
|---|---|
| `RPC_URL` | BSC RPC endpoint (e.g. `https://bsc-dataseed1.binance.org/`) |
| `WSS_URL` | WebSocket RPC URL (for real-time monitoring) |
| `PRIVATE_KEY` | Your wallet private key (**never commit this!**) |
| `WALLET_ADDRESS` | Your BSC wallet address |
| `BSCSCAN_API_KEY` | Free key from [bscscan.com](https://bscscan.com/myapikey) |

### 3. Run the monitor

```bash
# Start block monitoring (read-only, no auto-buy)
python main.py

# Audit a specific token
python main.py --audit 0xYourTokenAddress

# Enable auto-buy (USE WITH EXTREME CAUTION)
python main.py --auto-buy
```

---

## Security Checks

The security pipeline evaluates each token against these criteria:

| Check | Penalty | Description |
|---|---|---|
| Honeypot detected | +50 | Sell simulation fails |
| Hidden functions | +30 | `mint`, `setTax`, `blacklistAddress`, etc. |
| Sell tax > 10% | +25 | High sell tax indicates a scam |
| LP not burned | +20 | Creator can rug-pull liquidity |
| Liquidity < 5 BNB | +15 | Insufficient liquidity |
| Ownership not renounced | +10 | Owner can change fees/rules |
| Creator unknown | +5 | Not in trusted whitelist |

**Decision thresholds:**
- `risk_score <= 25` → **BUY**
- `risk_score > 25` → **SKIP**

---

## Decision Engine Output

The decision engine produces a JSON object compatible with Claude and other AI agents:

```json
{
  "decision": "BUY",
  "confidence_score": 85,
  "reason": "All checks passed",
  "suggested_gas_price": "6.0 Gwei",
  "risk_score": 15,
  "token_address": "0x...",
  "checks": {
    "lp_burned": true,
    "ownership_renounced": true,
    "honeypot_detected": false,
    "hidden_functions": [],
    "sell_tax_percent": 3.0,
    "buy_tax_percent": 3.0,
    "liquidity_bnb": 25.5,
    "creator_whitelisted": false
  },
  "audited_at": "2024-01-15T10:30:00Z"
}
```

---

## Claude Integration

Use `DecisionEngine.claude_prompt(audit)` to generate a structured prompt
for Claude or another LLM to perform a secondary review:

```python
from src.security_validator import SecurityValidator
from src.decision_engine import DecisionEngine

validator = SecurityValidator()
engine = DecisionEngine()

audit = validator.validate("0xYourTokenAddress")
prompt = engine.claude_prompt(audit)
# Send `prompt` to Claude API for a second opinion
```

---

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

---

## Implementation Stack

- **[web3.py](https://web3py.readthedocs.io/)** – blockchain interaction
- **[requests](https://docs.python-requests.org/)** – BSCScan API calls
- **[aiohttp](https://docs.aiohttp.org/)** – async HTTP (optional)
- **[python-dotenv](https://pypi.org/project/python-dotenv/)** – env management
- **sqlite3** – built-in transaction logging

---

## Security Best Practices

- Store your `PRIVATE_KEY` **only** in the `.env` file — never in source code
- Always run `simulate_sell` before executing a real buy
- Start with small BNB amounts (`BUY_AMOUNT_BNB=0.01`) for testing
- Use a dedicated trading wallet with limited funds
- Test on BSC Testnet before mainnet deployment