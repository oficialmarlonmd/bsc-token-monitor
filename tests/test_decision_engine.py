"""Tests for DecisionEngine."""

from datetime import datetime
from unittest.mock import MagicMock

from src.decision_engine import DecisionEngine
from src.models import SecurityAudit


def _make_engine() -> DecisionEngine:
    mock_client = MagicMock()
    mock_client.get_gas_price_gwei.return_value = 5.0
    return DecisionEngine(web3_client=mock_client)


def _make_audit(decision: str, risk_score: int) -> SecurityAudit:
    audit = SecurityAudit(
        token_address="0xToken",
        lp_burned=True,
        ownership_renounced=True,
        honeypot_detected=False,
        hidden_functions=[],
        sell_tax_percent=0.0,
        buy_tax_percent=0.0,
        liquidity_bnb=10.0,
        creator_whitelisted=True,
        risk_score=risk_score,
        decision=decision,
        reason="Test reason",
    )
    return audit


class TestMakeDecision:
    def test_buy_decision_structure(self):
        engine = _make_engine()
        audit = _make_audit("BUY", risk_score=10)
        result = engine.make_decision(audit)

        assert result["decision"] == "BUY"
        assert result["confidence_score"] == 90  # 100 - 10
        assert result["reason"] == "Test reason"
        assert "Gwei" in result["suggested_gas_price"]
        assert result["risk_score"] == 10
        assert result["token_address"] == "0xToken"

    def test_skip_decision_structure(self):
        engine = _make_engine()
        audit = _make_audit("SKIP", risk_score=75)
        result = engine.make_decision(audit)

        assert result["decision"] == "SKIP"
        assert result["confidence_score"] == 75  # risk_score itself

    def test_confidence_never_below_zero(self):
        engine = _make_engine()
        audit = _make_audit("BUY", risk_score=110)  # edge case
        result = engine.make_decision(audit)
        assert result["confidence_score"] >= 0

    def test_checks_block_present(self):
        engine = _make_engine()
        audit = _make_audit("BUY", risk_score=0)
        result = engine.make_decision(audit)
        checks = result["checks"]

        assert "lp_burned" in checks
        assert "ownership_renounced" in checks
        assert "honeypot_detected" in checks
        assert "hidden_functions" in checks
        assert "sell_tax_percent" in checks
        assert "buy_tax_percent" in checks
        assert "liquidity_bnb" in checks
        assert "creator_whitelisted" in checks

    def test_audited_at_format(self):
        engine = _make_engine()
        audit = _make_audit("BUY", risk_score=0)
        result = engine.make_decision(audit)
        # Should end with 'Z' (UTC marker)
        assert result["audited_at"].endswith("Z")

    def test_make_decision_json_is_valid_json(self):
        import json
        engine = _make_engine()
        audit = _make_audit("SKIP", risk_score=60)
        json_str = engine.make_decision_json(audit)
        parsed = json.loads(json_str)
        assert parsed["decision"] == "SKIP"


class TestClaudePrompt:
    def test_prompt_contains_required_sections(self):
        engine = _make_engine()
        audit = _make_audit("SKIP", risk_score=50)
        prompt = engine.claude_prompt(audit)

        assert "### ROLE" in prompt
        assert "### CONTEXT" in prompt
        assert "### INPUT DATA" in prompt
        assert "### TASK" in prompt
        assert "### OUTPUT (JSON ONLY)" in prompt
        assert '"decision"' in prompt
