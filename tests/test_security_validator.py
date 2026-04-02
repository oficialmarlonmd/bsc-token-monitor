"""Tests for SecurityValidator risk scoring logic.

These tests use mocked Web3Client and ContractAnalyzer so they run
without a real BSC connection.
"""

from unittest.mock import MagicMock, patch

import pytest

from src.models import SecurityAudit
from src.security_validator import (
    PENALTY_CREATOR_UNKNOWN,
    PENALTY_HIDDEN_FUNCTIONS,
    PENALTY_HONEYPOT,
    PENALTY_LIQUIDITY_LOW,
    PENALTY_LP_NOT_BURNED,
    PENALTY_OWNERSHIP_NOT_RENOUNCED,
    PENALTY_SELL_TAX_HIGH,
    SecurityValidator,
)


def _make_validator(
    *,
    owner="0x0000000000000000000000000000000000000000",
    pair_address="0xPair",
    lp_burned=True,
    liquidity_bnb=10.0,
    sell_simulate_success=True,
    hidden_functions=None,
    sell_tax=0.0,
    buy_tax=0.0,
    creator="0xCreator",
    whitelisted_creators=None,
) -> SecurityValidator:
    """
    Build a SecurityValidator with fully mocked dependencies.
    """
    mock_client = MagicMock()
    mock_client.wallet_address = "0xWallet"
    mock_client.get_owner.return_value = owner
    mock_client.get_pair_address.return_value = pair_address
    mock_client.is_lp_burned.return_value = lp_burned
    mock_client.get_liquidity_bnb.return_value = liquidity_bnb
    mock_client.simulate_sell.return_value = (
        sell_simulate_success,
        "ok" if sell_simulate_success else "reverted",
    )
    mock_client.get_gas_price_gwei.return_value = 5.0

    mock_analyzer = MagicMock()
    mock_analyzer.full_analysis.return_value = {
        "creator": creator,
        "abi_available": True,
        "source_available": True,
        "hidden_functions": hidden_functions or [],
        "taxes": {"sell_tax": sell_tax, "buy_tax": buy_tax},
    }

    return SecurityValidator(
        web3_client=mock_client,
        contract_analyzer=mock_analyzer,
        whitelisted_creators=whitelisted_creators or [],
    )


# ---------------------------------------------------------------------------
# Individual check methods
# ---------------------------------------------------------------------------

class TestCheckOwnership:
    def test_renounced_when_zero_address(self):
        v = _make_validator(owner="0x0000000000000000000000000000000000000000")
        assert v.check_ownership("0xToken") is True

    def test_not_renounced_when_real_owner(self):
        v = _make_validator(owner="0xRealOwner")
        assert v.check_ownership("0xToken") is False

    def test_renounced_when_no_owner_function(self):
        mock_client = MagicMock()
        mock_client.get_owner.return_value = None
        v = SecurityValidator(web3_client=mock_client, contract_analyzer=MagicMock())
        assert v.check_ownership("0xToken") is True


class TestCheckLpBurned:
    def test_burned(self):
        v = _make_validator(lp_burned=True)
        burned, pair = v.check_lp_burned("0xToken")
        assert burned is True
        assert pair == "0xPair"

    def test_not_burned(self):
        v = _make_validator(lp_burned=False)
        burned, _ = v.check_lp_burned("0xToken")
        assert burned is False

    def test_no_pair_returns_false(self):
        v = _make_validator(pair_address=None)
        burned, pair = v.check_lp_burned("0xToken")
        assert burned is False
        assert pair is None


class TestCheckHoneypot:
    def test_not_honeypot(self):
        v = _make_validator(sell_simulate_success=True)
        assert v.check_honeypot("0xToken", "0xWallet") is False

    def test_is_honeypot(self):
        v = _make_validator(sell_simulate_success=False)
        assert v.check_honeypot("0xToken", "0xWallet") is True


class TestCheckCreatorWhitelist:
    def test_creator_whitelisted(self):
        v = _make_validator(whitelisted_creators=["0xgoodcreator"])
        assert v.check_creator_whitelist("0xGoodCreator") is True

    def test_creator_not_whitelisted(self):
        v = _make_validator(whitelisted_creators=["0xgoodcreator"])
        assert v.check_creator_whitelist("0xBadCreator") is False

    def test_none_creator(self):
        v = _make_validator()
        assert v.check_creator_whitelist(None) is False


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

class TestRiskScoring:
    def _empty_audit(self) -> SecurityAudit:
        return SecurityAudit(
            token_address="0xT",
            lp_burned=True,
            ownership_renounced=True,
            honeypot_detected=False,
            hidden_functions=[],
            sell_tax_percent=0.0,
            liquidity_bnb=10.0,
            creator_whitelisted=True,
        )

    def test_all_clear_gives_zero_score(self):
        v = _make_validator()
        audit = self._empty_audit()
        v.calculate_risk_score(audit)
        assert audit.risk_score == 0
        assert audit.decision == "BUY"

    def test_honeypot_adds_penalty(self):
        v = _make_validator()
        audit = self._empty_audit()
        audit.honeypot_detected = True
        v.calculate_risk_score(audit)
        assert audit.risk_score >= PENALTY_HONEYPOT

    def test_hidden_functions_adds_penalty(self):
        v = _make_validator()
        audit = self._empty_audit()
        audit.hidden_functions = ["mint", "setTax"]
        v.calculate_risk_score(audit)
        assert audit.risk_score >= PENALTY_HIDDEN_FUNCTIONS

    def test_high_sell_tax_adds_penalty(self):
        v = _make_validator()
        audit = self._empty_audit()
        audit.sell_tax_percent = 15.0  # above default 10%
        v.calculate_risk_score(audit)
        assert audit.risk_score >= PENALTY_SELL_TAX_HIGH

    def test_low_liquidity_adds_penalty(self):
        v = _make_validator()
        audit = self._empty_audit()
        audit.liquidity_bnb = 2.0  # below default 5 BNB
        v.calculate_risk_score(audit)
        assert audit.risk_score >= PENALTY_LIQUIDITY_LOW

    def test_lp_not_burned_adds_penalty(self):
        v = _make_validator()
        audit = self._empty_audit()
        audit.lp_burned = False
        v.calculate_risk_score(audit)
        assert audit.risk_score >= PENALTY_LP_NOT_BURNED

    def test_ownership_not_renounced_adds_penalty(self):
        v = _make_validator()
        audit = self._empty_audit()
        audit.ownership_renounced = False
        v.calculate_risk_score(audit)
        assert audit.risk_score >= PENALTY_OWNERSHIP_NOT_RENOUNCED

    def test_unknown_creator_adds_penalty(self):
        v = _make_validator()
        audit = self._empty_audit()
        audit.creator_whitelisted = False
        v.calculate_risk_score(audit)
        assert audit.risk_score >= PENALTY_CREATOR_UNKNOWN

    def test_score_capped_at_100(self):
        v = _make_validator()
        audit = self._empty_audit()
        audit.honeypot_detected = True
        audit.hidden_functions = ["mint"]
        audit.sell_tax_percent = 99.0
        audit.lp_burned = False
        audit.liquidity_bnb = 0.1
        audit.ownership_renounced = False
        audit.creator_whitelisted = False
        v.calculate_risk_score(audit)
        assert audit.risk_score <= 100

    def test_buy_decision_below_threshold(self):
        v = _make_validator()
        audit = self._empty_audit()
        v.calculate_risk_score(audit)
        assert audit.decision == "BUY"

    def test_skip_decision_above_threshold(self):
        v = _make_validator()
        audit = self._empty_audit()
        audit.honeypot_detected = True
        v.calculate_risk_score(audit)
        assert audit.decision == "SKIP"


# ---------------------------------------------------------------------------
# Full validation pipeline (integration-style with mocks)
# ---------------------------------------------------------------------------

class TestValidatePipeline:
    def test_safe_token_gets_buy(self):
        v = _make_validator(
            owner="0x0000000000000000000000000000000000000000",
            lp_burned=True,
            liquidity_bnb=20.0,
            sell_simulate_success=True,
            sell_tax=0.0,
            whitelisted_creators=["0xcreator"],
            creator="0xCreator",
        )
        audit = v.validate("0xToken")
        assert audit.decision == "BUY"
        assert audit.risk_score <= 25

    def test_honeypot_token_gets_skip(self):
        v = _make_validator(sell_simulate_success=False)
        audit = v.validate("0xToken")
        assert audit.decision == "SKIP"
        assert audit.honeypot_detected is True

    def test_high_tax_gets_skip(self):
        v = _make_validator(sell_tax=50.0)
        audit = v.validate("0xToken")
        assert audit.decision == "SKIP"
