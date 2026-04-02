"""
SQLite database layer for BSC Token Monitor.

Persists:
- SecurityAudit records (token risk assessments)
- TransactionRecord records (buy/sell history with PnL)

The schema is intentionally minimal and uses plain INSERT/SELECT
rather than an ORM to keep the dependency count low.
"""

import logging
import os
import sqlite3
from datetime import datetime
from typing import List, Optional

from dotenv import load_dotenv

from .models import SecurityAudit, TransactionRecord

load_dotenv()

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = os.getenv("DB_PATH", "data/monitor.db")


class Database:
    """
    Thin wrapper around a SQLite database for audit and transaction storage.

    Parameters
    ----------
    db_path : str
        Path to the SQLite file.  Parent directories are created if needed.
    """

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._conn: Optional[sqlite3.Connection] = None
        self._init_schema()

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
        """
        Return the persistent SQLite connection (create it if needed).

        Thread-safety note: ``check_same_thread=False`` allows the connection
        to be reused across calls, but this instance is **not thread-safe**.
        Each thread should create its own ``Database`` instance to avoid
        race conditions.
        """
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_schema(self) -> None:
        """Create tables if they do not already exist."""
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS security_audits (
                id                    INTEGER PRIMARY KEY AUTOINCREMENT,
                token_address         TEXT NOT NULL,
                liquidity_bnb         REAL DEFAULT 0,
                lp_burned             INTEGER DEFAULT 0,
                ownership_renounced   INTEGER DEFAULT 0,
                honeypot_detected     INTEGER DEFAULT 0,
                hidden_functions      TEXT DEFAULT '',
                sell_tax_percent      REAL DEFAULT 0,
                buy_tax_percent       REAL DEFAULT 0,
                creator_whitelisted   INTEGER DEFAULT 0,
                risk_score            INTEGER DEFAULT 0,
                decision              TEXT DEFAULT 'SKIP',
                reason                TEXT DEFAULT '',
                audited_at            TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS transactions (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                tx_type           TEXT NOT NULL,
                token_address     TEXT NOT NULL,
                token_symbol      TEXT DEFAULT '',
                amount_bnb        REAL DEFAULT 0,
                token_amount      INTEGER DEFAULT 0,
                gas_price_gwei    REAL DEFAULT 0,
                gas_used          INTEGER DEFAULT 0,
                tx_hash           TEXT DEFAULT '',
                status            TEXT DEFAULT 'PENDING',
                timestamp         TEXT NOT NULL,
                profit_loss_bnb   REAL
            );
        """)
        conn.commit()
        logger.debug("Database schema initialised at %s", self.db_path)

    # ------------------------------------------------------------------
    # SecurityAudit persistence
    # ------------------------------------------------------------------

    def save_audit(self, audit: SecurityAudit) -> int:
        """
        Insert a SecurityAudit row and return the new row id.
        """
        conn = self._get_conn()
        cur = conn.execute(
            """
            INSERT INTO security_audits
                (token_address, liquidity_bnb, lp_burned, ownership_renounced,
                 honeypot_detected, hidden_functions, sell_tax_percent,
                 buy_tax_percent, creator_whitelisted, risk_score,
                 decision, reason, audited_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                audit.token_address,
                audit.liquidity_bnb,
                int(audit.lp_burned),
                int(audit.ownership_renounced),
                int(audit.honeypot_detected),
                ",".join(audit.hidden_functions),
                audit.sell_tax_percent,
                audit.buy_tax_percent,
                int(audit.creator_whitelisted),
                audit.risk_score,
                audit.decision,
                audit.reason,
                audit.audited_at.isoformat(),
            ),
        )
        conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def get_audit(self, token_address: str) -> Optional[SecurityAudit]:
        """
        Retrieve the most recent SecurityAudit for *token_address*.

        Returns None if no record exists.
        """
        conn = self._get_conn()
        row = conn.execute(
            """
            SELECT * FROM security_audits
            WHERE token_address = ?
            ORDER BY audited_at DESC
            LIMIT 1
            """,
            (token_address,),
        ).fetchone()

        if row is None:
            return None

        audit = SecurityAudit(token_address=row["token_address"])
        audit.liquidity_bnb = row["liquidity_bnb"]
        audit.lp_burned = bool(row["lp_burned"])
        audit.ownership_renounced = bool(row["ownership_renounced"])
        audit.honeypot_detected = bool(row["honeypot_detected"])
        audit.hidden_functions = (
            row["hidden_functions"].split(",") if row["hidden_functions"] else []
        )
        audit.sell_tax_percent = row["sell_tax_percent"]
        audit.buy_tax_percent = row["buy_tax_percent"]
        audit.creator_whitelisted = bool(row["creator_whitelisted"])
        audit.risk_score = row["risk_score"]
        audit.decision = row["decision"]
        audit.reason = row["reason"]
        audit.audited_at = datetime.fromisoformat(row["audited_at"])
        return audit

    def list_audits(self, limit: int = 50) -> List[SecurityAudit]:
        """Return the *limit* most recent security audits."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM security_audits ORDER BY audited_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        audits = []
        for row in rows:
            audit = SecurityAudit(token_address=row["token_address"])
            audit.liquidity_bnb = row["liquidity_bnb"]
            audit.lp_burned = bool(row["lp_burned"])
            audit.ownership_renounced = bool(row["ownership_renounced"])
            audit.honeypot_detected = bool(row["honeypot_detected"])
            audit.hidden_functions = (
                row["hidden_functions"].split(",") if row["hidden_functions"] else []
            )
            audit.sell_tax_percent = row["sell_tax_percent"]
            audit.buy_tax_percent = row["buy_tax_percent"]
            audit.creator_whitelisted = bool(row["creator_whitelisted"])
            audit.risk_score = row["risk_score"]
            audit.decision = row["decision"]
            audit.reason = row["reason"]
            audit.audited_at = datetime.fromisoformat(row["audited_at"])
            audits.append(audit)
        return audits

    # ------------------------------------------------------------------
    # TransactionRecord persistence
    # ------------------------------------------------------------------

    def save_transaction(self, tx: TransactionRecord) -> int:
        """Insert a TransactionRecord and return the new row id."""
        conn = self._get_conn()
        cur = conn.execute(
            """
            INSERT INTO transactions
                (tx_type, token_address, token_symbol, amount_bnb, token_amount,
                 gas_price_gwei, gas_used, tx_hash, status, timestamp, profit_loss_bnb)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tx.tx_type,
                tx.token_address,
                tx.token_symbol,
                tx.amount_bnb,
                tx.token_amount,
                tx.gas_price_gwei,
                tx.gas_used,
                tx.tx_hash,
                tx.status,
                tx.timestamp.isoformat(),
                tx.profit_loss_bnb,
            ),
        )
        conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def list_transactions(self, limit: int = 100) -> List[TransactionRecord]:
        """Return the *limit* most recent transactions."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM transactions ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
        txs = []
        for row in rows:
            record = TransactionRecord(
                tx_type=row["tx_type"],
                token_address=row["token_address"],
                token_symbol=row["token_symbol"],
                amount_bnb=row["amount_bnb"],
                token_amount=row["token_amount"],
                gas_price_gwei=row["gas_price_gwei"],
                gas_used=row["gas_used"],
                tx_hash=row["tx_hash"],
                status=row["status"],
                timestamp=datetime.fromisoformat(row["timestamp"]),
                profit_loss_bnb=row["profit_loss_bnb"],
            )
            txs.append(record)
        return txs

    def get_total_profit(self) -> float:
        """
        Calculate the total realised PnL (in BNB) across all SELL transactions.
        """
        conn = self._get_conn()
        row = conn.execute(
            "SELECT SUM(profit_loss_bnb) as total FROM transactions "
            "WHERE tx_type = 'SELL' AND status = 'SUCCESS'"
        ).fetchone()
        return row["total"] or 0.0
