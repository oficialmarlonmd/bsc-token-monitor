"""Tests for data models."""

from datetime import datetime

import pytest

from src.models import (
    MonitoringLog,
    SecurityAudit,
    TokenInfo,
    TransactionRecord,
)


# ---------------------------------------------------------------------------
# TokenInfo
# ---------------------------------------------------------------------------

class TestTokenInfo:
    def test_creation_with_required_fields(self):
        token = TokenInfo(
            contract_address="0xABC",
            symbol="TEST",
            name="Test Token",
            decimals=18,
            total_supply=10**9 * 10**18,
            creator="0xCreator",
        )
        assert token.contract_address == "0xABC"
        assert token.symbol == "TEST"
        assert token.decimals == 18
        assert token.pair_address is None

    def test_discovered_at_defaults_to_now(self):
        token = TokenInfo(
            contract_address="0x1",
            symbol="X",
            name="X Token",
            decimals=18,
            total_supply=1000,
            creator="0x2",
        )
        assert isinstance(token.discovered_at, datetime)

    def test_pair_address_optional(self):
        token = TokenInfo(
            contract_address="0x1",
            symbol="X",
            name="X Token",
            decimals=18,
            total_supply=1000,
            creator="0x2",
            pair_address="0xPair",
        )
        assert token.pair_address == "0xPair"


# ---------------------------------------------------------------------------
# SecurityAudit
# ---------------------------------------------------------------------------

class TestSecurityAudit:
    def test_defaults(self):
        audit = SecurityAudit(token_address="0xToken")
        assert audit.decision == "SKIP"
        assert audit.risk_score == 0
        assert audit.lp_burned is False
        assert audit.hidden_functions == []
        assert audit.liquidity_bnb == 0.0

    def test_audited_at_defaults_to_now(self):
        audit = SecurityAudit(token_address="0x1")
        assert isinstance(audit.audited_at, datetime)

    def test_custom_fields(self):
        audit = SecurityAudit(
            token_address="0xT",
            liquidity_bnb=10.5,
            lp_burned=True,
            ownership_renounced=True,
            honeypot_detected=False,
            hidden_functions=["mint", "setTax"],
            sell_tax_percent=5.0,
            risk_score=30,
            decision="BUY",
            reason="All checks passed",
        )
        assert audit.liquidity_bnb == 10.5
        assert audit.lp_burned is True
        assert "mint" in audit.hidden_functions
        assert audit.decision == "BUY"


# ---------------------------------------------------------------------------
# TransactionRecord
# ---------------------------------------------------------------------------

class TestTransactionRecord:
    def test_defaults(self):
        tx = TransactionRecord(
            tx_type="BUY",
            token_address="0xToken",
            token_symbol="TKN",
            amount_bnb=0.05,
            token_amount=1_000_000,
            gas_price_gwei=5.0,
        )
        assert tx.status == "PENDING"
        assert tx.tx_hash == ""
        assert tx.profit_loss_bnb is None
        assert isinstance(tx.timestamp, datetime)

    def test_sell_with_pnl(self):
        tx = TransactionRecord(
            tx_type="SELL",
            token_address="0xT",
            token_symbol="T",
            amount_bnb=0.1,
            token_amount=500_000,
            gas_price_gwei=5.0,
            status="SUCCESS",
            profit_loss_bnb=0.05,
        )
        assert tx.profit_loss_bnb == 0.05


# ---------------------------------------------------------------------------
# MonitoringLog
# ---------------------------------------------------------------------------

class TestMonitoringLog:
    def test_add_alert(self, capsys):
        log = MonitoringLog(session_id="test-session")
        log.add_alert("Test alert message")
        captured = capsys.readouterr()
        assert "Test alert message" in captured.out
        assert len(log.security_alerts) == 1

    def test_calculate_profit_no_trades(self):
        log = MonitoringLog(session_id="s1")
        assert log.calculate_profit() == 0.0

    def test_calculate_profit_sell_trades(self):
        log = MonitoringLog(session_id="s2")
        for pnl in [0.1, -0.05, 0.2]:
            tx = TransactionRecord(
                tx_type="SELL",
                token_address="0xT",
                token_symbol="T",
                amount_bnb=0.1,
                token_amount=100,
                gas_price_gwei=5.0,
                profit_loss_bnb=pnl,
            )
            log.transactions.append(tx)
        result = log.calculate_profit()
        assert abs(result - 0.25) < 1e-9

    def test_calculate_profit_ignores_buys(self):
        log = MonitoringLog(session_id="s3")
        buy_tx = TransactionRecord(
            tx_type="BUY",
            token_address="0xT",
            token_symbol="T",
            amount_bnb=0.05,
            token_amount=100,
            gas_price_gwei=5.0,
            profit_loss_bnb=None,
        )
        log.transactions.append(buy_tx)
        assert log.calculate_profit() == 0.0
