"""
Data models for the BSC Token Monitor system.

These dataclasses define the structure of every piece of information
the system collects, audits, and records during its operation.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional


# ---------------------------------------------------------------------------
# TokenInfo
# ---------------------------------------------------------------------------

@dataclass
class TokenInfo:
    """
    Core information about a BEP-20 token on Binance Smart Chain.

    Attributes:
        contract_address: The on-chain address of the token contract (checksummed).
        symbol:           Token ticker symbol (e.g. "PEPE").
        name:             Full token name (e.g. "PepeCoin").
        decimals:         Number of decimal places (typically 18).
        total_supply:     Total token supply as an integer (raw, not divided by decimals).
        creator:          Wallet address that deployed the contract.
        discovered_at:    UTC timestamp when the token was first noticed.
        pair_address:     PancakeSwap LP pair address (BNB/Token), if available.
    """

    contract_address: str
    symbol: str
    name: str
    decimals: int
    total_supply: int
    creator: str
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    pair_address: Optional[str] = None


# ---------------------------------------------------------------------------
# SecurityAudit
# ---------------------------------------------------------------------------

@dataclass
class SecurityAudit:
    """
    Result of a comprehensive security analysis performed on a token.

    Risk score ranges
    -----------------
    0  – 30  : LOW RISK   (generally safe to consider)
    31 – 60  : MEDIUM RISK (proceed with caution)
    61 – 85  : HIGH RISK   (very likely a scam/rug-pull)
    86 – 100 : CRITICAL    (do not interact)

    Attributes:
        token_address:         Address of the audited token.
        liquidity_bnb:         Total BNB locked in the LP pool.
        lp_burned:             True if LP tokens were sent to the burn address.
        ownership_renounced:   True if owner() returns the zero address.
        honeypot_detected:     True if sell simulation failed (can't sell).
        hidden_functions:      List of suspicious function names found in ABI/source.
        sell_tax_percent:      Estimated sell tax (0–100).
        buy_tax_percent:       Estimated buy tax (0–100).
        creator_whitelisted:   True if creator is in the trusted whitelist.
        risk_score:            Computed risk score (0–100, higher = more risky).
        decision:              "BUY" or "SKIP".
        reason:                Human-readable explanation of the decision.
        audited_at:            UTC timestamp of the audit.
    """

    token_address: str
    liquidity_bnb: float = 0.0
    lp_burned: bool = False
    ownership_renounced: bool = False
    honeypot_detected: bool = False
    hidden_functions: List[str] = field(default_factory=list)
    sell_tax_percent: float = 0.0
    buy_tax_percent: float = 0.0
    creator_whitelisted: bool = False
    risk_score: int = 0
    decision: str = "SKIP"
    reason: str = ""
    audited_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# TransactionRecord
# ---------------------------------------------------------------------------

@dataclass
class TransactionRecord:
    """
    A record of a buy or sell transaction executed by the bot.

    Attributes:
        tx_type:       "BUY" or "SELL".
        token_address: Contract address of the token traded.
        token_symbol:  Ticker symbol for readability.
        amount_bnb:    BNB value involved in the trade.
        token_amount:  Number of tokens bought or sold (raw integer).
        gas_price_gwei: Gas price used, in Gwei.
        gas_used:      Actual gas consumed by the transaction.
        tx_hash:       Transaction hash on BSC.
        status:        "SUCCESS", "FAILED", or "PENDING".
        timestamp:     UTC time the transaction was submitted.
        profit_loss_bnb: Realised PnL in BNB for SELL transactions (can be negative).
    """

    tx_type: str                          # "BUY" | "SELL"
    token_address: str
    token_symbol: str
    amount_bnb: float
    token_amount: int
    gas_price_gwei: float
    gas_used: int = 0
    tx_hash: str = ""
    status: str = "PENDING"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    profit_loss_bnb: Optional[float] = None


# ---------------------------------------------------------------------------
# MonitoringLog
# ---------------------------------------------------------------------------

@dataclass
class MonitoringLog:
    """
    Aggregate log produced during a monitoring session.

    Attributes:
        session_id:        Unique identifier for this monitoring run.
        started_at:        UTC time the session began.
        ended_at:          UTC time the session ended (None if still running).
        blocks_scanned:    Number of BSC blocks inspected.
        tokens_discovered: List of TokenInfo objects found in the session.
        security_alerts:   Free-text alert messages raised during the session.
        transactions:      All TransactionRecords executed in the session.
        total_profit_bnb:  Net PnL across all trades (sum of profit_loss_bnb).
    """

    session_id: str
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ended_at: Optional[datetime] = None
    blocks_scanned: int = 0
    tokens_discovered: List[TokenInfo] = field(default_factory=list)
    security_alerts: List[str] = field(default_factory=list)
    transactions: List[TransactionRecord] = field(default_factory=list)
    total_profit_bnb: float = 0.0

    def add_alert(self, message: str) -> None:
        """Append a security alert and print it to stdout."""
        self.security_alerts.append(message)
        print(f"[ALERT] {message}")

    def calculate_profit(self) -> float:
        """Recalculate and return total PnL across all SELL transactions."""
        self.total_profit_bnb = sum(
            tx.profit_loss_bnb
            for tx in self.transactions
            if tx.tx_type == "SELL" and tx.profit_loss_bnb is not None
        )
        return self.total_profit_bnb
