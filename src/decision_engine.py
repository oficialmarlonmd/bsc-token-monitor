"""
Decision Engine.

Converts a SecurityAudit into a structured JSON decision object that is
ready for external consumption (e.g. by a Claude integration or a trading
dashboard).

Output format
-------------
{
    "decision":            "BUY" | "SKIP",
    "confidence_score":    0-100,
    "reason":              "<brief explanation>",
    "suggested_gas_price": "<value> Gwei",
    "risk_score":          0-100,
    "token_address":       "0x...",
    "checks": {
        "lp_burned":            true | false,
        "ownership_renounced":  true | false,
        "honeypot_detected":    true | false,
        "hidden_functions":     [...],
        "sell_tax_percent":     0.0,
        "buy_tax_percent":      0.0,
        "liquidity_bnb":        0.0,
        "creator_whitelisted":  true | false
    },
    "audited_at": "ISO-8601 timestamp"
}
"""

import json
import logging
from typing import Optional

from .models import SecurityAudit
from .web3_client import BSCWeb3Client

logger = logging.getLogger(__name__)


class DecisionEngine:
    """
    Produces a JSON decision object from a SecurityAudit.

    This class is designed to be the final stage of the pipeline before
    a human operator or an AI agent (e.g. Claude) acts on the data.

    Parameters
    ----------
    web3_client : BSCWeb3Client, optional
        Used to fetch the current network gas price.  If not provided a new
        client is created.
    """

    def __init__(self, web3_client: Optional[BSCWeb3Client] = None):
        self.client = web3_client or BSCWeb3Client()

    def make_decision(self, audit: SecurityAudit) -> dict:
        """
        Convert *audit* into a structured decision dictionary.

        The ``confidence_score`` is defined as:

        - BUY  decision: ``100 - risk_score``  (lower risk = higher confidence)
        - SKIP decision: ``risk_score``         (higher risk = more confident to skip)

        Returns a plain Python dict (JSON-serialisable).
        """
        if audit.decision == "BUY":
            confidence = max(0, 100 - audit.risk_score)
        else:
            confidence = audit.risk_score

        gas_price_gwei = self.client.get_gas_price_gwei()

        return {
            "decision": audit.decision,
            "confidence_score": confidence,
            "reason": audit.reason,
            "suggested_gas_price": f"{gas_price_gwei} Gwei",
            "risk_score": audit.risk_score,
            "token_address": audit.token_address,
            "checks": {
                "lp_burned": audit.lp_burned,
                "ownership_renounced": audit.ownership_renounced,
                "honeypot_detected": audit.honeypot_detected,
                "hidden_functions": audit.hidden_functions,
                "sell_tax_percent": audit.sell_tax_percent,
                "buy_tax_percent": audit.buy_tax_percent,
                "liquidity_bnb": audit.liquidity_bnb,
                "creator_whitelisted": audit.creator_whitelisted,
            },
            "audited_at": audit.audited_at.isoformat() + "Z",
        }

    def make_decision_json(self, audit: SecurityAudit) -> str:
        """
        Same as :meth:`make_decision` but returns a formatted JSON string.
        """
        return json.dumps(self.make_decision(audit), indent=2)

    def claude_prompt(self, audit: SecurityAudit) -> str:
        """
        Build a structured prompt string ready to send to Claude (or another
        LLM) for a second-opinion analysis.

        The prompt follows the role / context / task / output pattern described
        in the problem statement.
        """
        data = self.make_decision(audit)
        return (
            "### ROLE\n"
            "You are an expert Smart Contract security analyst and memecoin "
            "auditor on BNB Chain.\n\n"
            "### CONTEXT\n"
            "I am monitoring the BSC mempool. I received data about a new "
            "token contract. Analyse the data below to identify rug-pull or "
            "honeypot risks.\n\n"
            "### INPUT DATA\n"
            f"{json.dumps(data, indent=2)}\n\n"
            "### TASK\n"
            "1. Review the risk checks above.\n"
            "2. Flag any additional concerns not captured by the automated checks.\n"
            "3. Confirm or override the decision.\n\n"
            "### OUTPUT (JSON ONLY)\n"
            "Return exactly one JSON object:\n"
            "{\n"
            '  "decision": "BUY" | "SKIP",\n'
            '  "confidence_score": 0-100,\n'
            '  "reason": "<brief explanation>",\n'
            '  "suggested_gas_price": "<value> Gwei"\n'
            "}"
        )
