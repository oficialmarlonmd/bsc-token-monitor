"""
Token Security Validator Module.

Orchestrates all individual security checks and produces a SecurityAudit
with a computed risk score and a BUY / SKIP decision.

Risk scoring rules
------------------
Each flag adds penalty points to the risk score (0 = safe, 100 = certain scam).

Flag                              | Penalty | Level
------------------------------------|---------|----------
Honeypot detected                 |   50    | CRITICAL
Hidden dangerous functions        |   30    | BLOCK
Sell tax > 10%                    |   25    | SCAM
LP not burned / locked            |   20    | HIGH RISK
Ownership not renounced           |   10    | CAUTION
Liquidity < 5 BNB                 |   15    | HIGH RISK
Creator not in whitelist          |    5    | CAUTION
No source code available          |    5    | CAUTION

Decision thresholds
-------------------
risk_score <= 25  → BUY   (confidence = 100 - risk_score)
risk_score >  25  → SKIP  (confidence = risk_score)
"""

import logging
import os
from typing import List, Optional, Tuple

from dotenv import load_dotenv

from .models import SecurityAudit, TokenInfo
from .web3_client import BSCWeb3Client
from .contract_analyzer import ContractAnalyzer

load_dotenv()

logger = logging.getLogger(__name__)

# Penalty values per risk flag
PENALTY_HONEYPOT = 50
PENALTY_HIDDEN_FUNCTIONS = 30
PENALTY_SELL_TAX_HIGH = 25
PENALTY_LP_NOT_BURNED = 20
PENALTY_LIQUIDITY_LOW = 15
PENALTY_OWNERSHIP_NOT_RENOUNCED = 10
PENALTY_NO_SOURCE = 5
PENALTY_CREATOR_UNKNOWN = 5


class SecurityValidator:
    """
    End-to-end security validator for BSC tokens.

    Usage
    -----
    >>> validator = SecurityValidator()
    >>> audit = validator.validate("0xTokenAddress...")
    >>> print(audit.decision, audit.risk_score)
    """

    def __init__(
        self,
        web3_client: Optional[BSCWeb3Client] = None,
        contract_analyzer: Optional[ContractAnalyzer] = None,
        min_liquidity_bnb: Optional[float] = None,
        max_sell_tax_percent: Optional[float] = None,
        whitelisted_creators: Optional[List[str]] = None,
    ):
        self.client = web3_client or BSCWeb3Client()
        self.analyzer = contract_analyzer or ContractAnalyzer()

        self.min_liquidity_bnb = min_liquidity_bnb or float(
            os.getenv("MIN_LIQUIDITY_BNB", "5")
        )
        self.max_sell_tax_percent = max_sell_tax_percent or float(
            os.getenv("MAX_SELL_TAX_PERCENT", "10")
        )

        raw_whitelist = whitelisted_creators or os.getenv("WHITELISTED_CREATORS", "")
        if isinstance(raw_whitelist, str):
            self.whitelisted_creators = [
                addr.strip().lower()
                for addr in raw_whitelist.split(",")
                if addr.strip()
            ]
        else:
            self.whitelisted_creators = [a.lower() for a in raw_whitelist]

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def check_ownership(self, token_address: str) -> bool:
        """
        Return True if the token contract's ownership has been renounced.

        Ownership is considered renounced when owner() returns the zero address
        (0x0000...0000).
        """
        owner = self.client.get_owner(token_address)
        if owner is None:
            # Contract has no owner() function – treat as renounced
            return True
        return owner.lower() == "0x0000000000000000000000000000000000000000"

    def check_lp_burned(self, token_address: str) -> Tuple[bool, Optional[str]]:
        """
        Return (is_burned, pair_address).

        Looks up the PancakeSwap V2 WBNB/Token pair and checks whether LP
        tokens have been sent to the burn address.
        """
        pair_address = self.client.get_pair_address(token_address)
        if not pair_address:
            return False, None
        return self.client.is_lp_burned(pair_address), pair_address

    def check_liquidity(self, pair_address: str, token_address: str) -> float:
        """Return the BNB liquidity for the LP pair."""
        return self.client.get_liquidity_bnb(pair_address, token_address)

    def check_honeypot(
        self,
        token_address: str,
        wallet_address: Optional[str] = None,
    ) -> bool:
        """
        Simulate selling 1 raw token unit to detect honeypots.

        Returns True if the contract appears to be a honeypot (sell fails).
        """
        from_addr = wallet_address or self.client.wallet_address
        if not from_addr:
            logger.warning("No wallet address for honeypot simulation – skipping")
            return False

        success, message = self.client.simulate_sell(
            token_address=token_address,
            amount_tokens=1,   # Sell 1 raw unit (smallest possible amount)
            from_address=from_addr,
        )
        if not success:
            logger.warning("Honeypot detected for %s: %s", token_address, message)
        return not success

    def check_creator_whitelist(self, creator_address: Optional[str]) -> bool:
        """Return True if the creator is in the trusted whitelist."""
        if not creator_address:
            return False
        return creator_address.lower() in self.whitelisted_creators

    # ------------------------------------------------------------------
    # Score calculation
    # ------------------------------------------------------------------

    def calculate_risk_score(self, audit: SecurityAudit) -> SecurityAudit:
        """
        Compute the integer risk score (0–100) for *audit* and set
        ``audit.decision`` and ``audit.reason`` accordingly.

        This method mutates and returns the audit object.
        """
        score = 0
        reasons: List[str] = []

        if audit.honeypot_detected:
            score += PENALTY_HONEYPOT
            reasons.append("Honeypot detected (sell simulation failed)")

        if audit.hidden_functions:
            score += PENALTY_HIDDEN_FUNCTIONS
            reasons.append(
                f"Hidden/dangerous functions: {', '.join(audit.hidden_functions)}"
            )

        if audit.sell_tax_percent > self.max_sell_tax_percent:
            score += PENALTY_SELL_TAX_HIGH
            reasons.append(
                f"Sell tax {audit.sell_tax_percent:.1f}% exceeds limit "
                f"{self.max_sell_tax_percent:.0f}%"
            )

        if not audit.lp_burned:
            score += PENALTY_LP_NOT_BURNED
            reasons.append("LP tokens are NOT burned/locked")

        if audit.liquidity_bnb < self.min_liquidity_bnb:
            score += PENALTY_LIQUIDITY_LOW
            reasons.append(
                f"Liquidity {audit.liquidity_bnb:.2f} BNB below minimum "
                f"{self.min_liquidity_bnb:.0f} BNB"
            )

        if not audit.ownership_renounced:
            score += PENALTY_OWNERSHIP_NOT_RENOUNCED
            reasons.append("Ownership has NOT been renounced")

        if not audit.creator_whitelisted:
            score += PENALTY_CREATOR_UNKNOWN
            reasons.append("Creator is not in the trusted whitelist")

        # Cap at 100
        audit.risk_score = min(score, 100)
        audit.decision = "BUY" if audit.risk_score <= 25 else "SKIP"
        audit.reason = "; ".join(reasons) if reasons else "All checks passed"
        return audit

    # ------------------------------------------------------------------
    # Full validation pipeline
    # ------------------------------------------------------------------

    def validate(self, token_address: str) -> SecurityAudit:
        """
        Run the complete security pipeline for *token_address*.

        Steps
        -----
        1. Fetch contract analysis (ABI + source + creator) from BSCScan.
        2. Check LP burn status.
        3. Check liquidity level.
        4. Check ownership renouncement.
        5. Check for honeypot via sell simulation.
        6. Score and decide.

        Returns a fully populated :class:`SecurityAudit`.
        """
        logger.info("Starting security validation for %s", token_address)
        audit = SecurityAudit(token_address=token_address)

        # ---- 1. Contract analysis ----------------------------------------
        analysis = self.analyzer.full_analysis(token_address)
        audit.hidden_functions = analysis.get("hidden_functions", [])
        audit.sell_tax_percent = analysis["taxes"].get("sell_tax", 0.0)
        audit.buy_tax_percent = analysis["taxes"].get("buy_tax", 0.0)
        creator = analysis.get("creator")

        if not analysis.get("source_available"):
            logger.warning("Source code not available for %s", token_address)

        # ---- 2. LP burn check --------------------------------------------
        lp_burned, pair_address = self.check_lp_burned(token_address)
        audit.lp_burned = lp_burned

        # ---- 3. Liquidity check ------------------------------------------
        if pair_address:
            audit.liquidity_bnb = self.check_liquidity(pair_address, token_address)

        # ---- 4. Ownership check ------------------------------------------
        audit.ownership_renounced = self.check_ownership(token_address)

        # ---- 5. Honeypot detection ----------------------------------------
        audit.honeypot_detected = self.check_honeypot(token_address)

        # ---- 6. Creator whitelist ----------------------------------------
        audit.creator_whitelisted = self.check_creator_whitelist(creator)

        # ---- 7. Score & decide -------------------------------------------
        self.calculate_risk_score(audit)

        logger.info(
            "Audit complete for %s: decision=%s score=%d reason=%s",
            token_address,
            audit.decision,
            audit.risk_score,
            audit.reason,
        )
        return audit
