"""Tests for Database layer (SQLite)."""

import os
import tempfile
from datetime import datetime

import pytest

from src.database import Database
from src.models import SecurityAudit, TransactionRecord


@pytest.fixture
def db(tmp_path):
    """Create a fresh in-memory-like database for each test."""
    db_file = str(tmp_path / "test.db")
    database = Database(db_path=db_file)
    yield database
    database.close()


def _make_audit(token_address: str = "0xToken", risk_score: int = 20) -> SecurityAudit:
    audit = SecurityAudit(
        token_address=token_address,
        liquidity_bnb=10.0,
        lp_burned=True,
        ownership_renounced=True,
        honeypot_detected=False,
        hidden_functions=["mint"],
        sell_tax_percent=3.0,
        buy_tax_percent=3.0,
        creator_whitelisted=False,
        risk_score=risk_score,
        decision="BUY",
        reason="Test",
    )
    return audit


def _make_tx(tx_type: str = "BUY", profit: float = None) -> TransactionRecord:
    return TransactionRecord(
        tx_type=tx_type,
        token_address="0xToken",
        token_symbol="TKN",
        amount_bnb=0.05,
        token_amount=1_000_000,
        gas_price_gwei=5.0,
        gas_used=200_000,
        tx_hash="0xhash",
        status="SUCCESS",
        profit_loss_bnb=profit,
    )


class TestAuditPersistence:
    def test_save_and_retrieve_audit(self, db):
        audit = _make_audit()
        row_id = db.save_audit(audit)
        assert row_id > 0

        retrieved = db.get_audit("0xToken")
        assert retrieved is not None
        assert retrieved.token_address == "0xToken"
        assert retrieved.liquidity_bnb == 10.0
        assert retrieved.lp_burned is True
        assert "mint" in retrieved.hidden_functions
        assert retrieved.decision == "BUY"

    def test_get_audit_nonexistent(self, db):
        assert db.get_audit("0xNonExistent") is None

    def test_list_audits_returns_records(self, db):
        db.save_audit(_make_audit("0xA", 10))
        db.save_audit(_make_audit("0xB", 20))
        audits = db.list_audits()
        assert len(audits) == 2

    def test_list_audits_limit(self, db):
        for i in range(5):
            db.save_audit(_make_audit(f"0x{i}"))
        audits = db.list_audits(limit=3)
        assert len(audits) == 3


class TestTransactionPersistence:
    def test_save_and_list_transaction(self, db):
        tx = _make_tx("BUY")
        row_id = db.save_transaction(tx)
        assert row_id > 0

        txs = db.list_transactions()
        assert len(txs) == 1
        assert txs[0].tx_type == "BUY"
        assert txs[0].token_symbol == "TKN"

    def test_total_profit_sell_only(self, db):
        db.save_transaction(_make_tx("SELL", profit=0.1))
        db.save_transaction(_make_tx("SELL", profit=-0.02))
        db.save_transaction(_make_tx("BUY", profit=None))

        total = db.get_total_profit()
        assert abs(total - 0.08) < 1e-9

    def test_total_profit_no_sells(self, db):
        db.save_transaction(_make_tx("BUY"))
        assert db.get_total_profit() == 0.0
