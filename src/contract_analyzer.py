"""
Smart Contract Analysis Engine.

This module fetches contract source code and ABI from BSCScan and analyses
them for:
- Suspicious / hidden functions (mint, setTax, blacklistAddress, etc.)
- Tax/fee variable extraction
- General contract metadata
"""

import os
import re
import logging
from typing import Dict, List, Optional, Set, Tuple

import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BSCSCAN_API_BASE = "https://api.bscscan.com/api"

# Function signatures that are red flags in a memecoin / BEP-20 contract.
# Their presence doesn't automatically mean the token is malicious, but each
# one raises the risk level.
SUSPICIOUS_FUNCTIONS = [
    # Supply manipulation
    "mint",
    "burn",
    "burnFrom",
    # Tax / fee manipulation
    "setTax",
    "setFee",
    "setBuyFee",
    "setSellFee",
    "setMaxTx",
    "setMaxWallet",
    "updateFee",
    "updateTax",
    # Access control abuse
    "blacklist",
    "blacklistAddress",
    "addBlacklist",
    "removeBlacklist",
    "pause",
    "unpause",
    # Ownership / upgrade abuse
    "setOwner",
    "transferOwnership",   # not inherently bad, but notable
    "renounceOwnership",   # also not bad, but track it
    "upgradeTo",
    "upgradeToAndCall",
]

# Regex patterns to extract numeric tax/fee values from Solidity source
TAX_PATTERNS = [
    r"(?:sellFee|sellTax|_sellTax|_sellFee)\s*=\s*(\d+)",
    r"(?:buyFee|buyTax|_buyTax|_buyFee)\s*=\s*(\d+)",
    r"(?:taxFee|_taxFee|marketingFee|_marketingFee)\s*=\s*(\d+)",
    r"(?:totalFee|_totalFee)\s*=\s*(\d+)",
]

# Pre-compiled regex objects for performance (avoids recompilation per-call)
_COMPILED_TAX_PATTERNS = [re.compile(p) for p in TAX_PATTERNS]
_COMPILED_FUNCTION_PATTERNS = {
    s: re.compile(rf"\bfunction\s+{re.escape(s)}\s*\(", re.IGNORECASE)
    for s in SUSPICIOUS_FUNCTIONS
}


# ---------------------------------------------------------------------------
# ContractAnalyzer
# ---------------------------------------------------------------------------

class ContractAnalyzer:
    """
    Analyse a BEP-20 smart contract by fetching its verified source/ABI from
    BSCScan and inspecting the code for risk indicators.

    Parameters
    ----------
    api_key : str, optional
        BSCScan API key.  Falls back to the ``BSCSCAN_API_KEY`` env variable.
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("BSCSCAN_API_KEY", "")
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "BSCTokenMonitor/1.0"})

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_contract_abi(self, contract_address: str) -> Optional[list]:
        """
        Fetch the verified ABI for *contract_address* from BSCScan.

        Returns the parsed ABI list or None if not available.
        """
        params = {
            "module": "contract",
            "action": "getabi",
            "address": contract_address,
            "apikey": self.api_key,
        }
        try:
            resp = self.session.get(BSCSCAN_API_BASE, params=params, timeout=10)
            data = resp.json()
            if data.get("status") == "1":
                import json
                return json.loads(data["result"])
            logger.warning("ABI not verified for %s: %s", contract_address, data.get("result"))
            return None
        except Exception as exc:
            logger.error("get_contract_abi failed for %s: %s", contract_address, exc)
            return None

    def get_contract_source(self, contract_address: str) -> Optional[str]:
        """
        Fetch the verified Solidity source code for *contract_address*.

        Returns the concatenated source string or None.
        """
        params = {
            "module": "contract",
            "action": "getsourcecode",
            "address": contract_address,
            "apikey": self.api_key,
        }
        try:
            resp = self.session.get(BSCSCAN_API_BASE, params=params, timeout=10)
            data = resp.json()
            if data.get("status") == "1" and data.get("result"):
                return data["result"][0].get("SourceCode", "")
            return None
        except Exception as exc:
            logger.error("get_contract_source failed for %s: %s", contract_address, exc)
            return None

    def get_contract_creator(self, contract_address: str) -> Optional[str]:
        """
        Return the wallet address that deployed *contract_address*.

        Uses BSCScan's ``getcontractcreation`` endpoint.
        """
        params = {
            "module": "contract",
            "action": "getcontractcreation",
            "contractaddresses": contract_address,
            "apikey": self.api_key,
        }
        try:
            resp = self.session.get(BSCSCAN_API_BASE, params=params, timeout=10)
            data = resp.json()
            if data.get("status") == "1" and data.get("result"):
                return data["result"][0].get("contractCreator")
            return None
        except Exception as exc:
            logger.error("get_contract_creator failed: %s", exc)
            return None

    def find_hidden_functions(
        self,
        abi: Optional[list] = None,
        source_code: Optional[str] = None,
    ) -> List[str]:
        """
        Identify suspicious function names present in the contract.

        Checks both the ABI (if provided) and the raw source code.

        Returns a deduplicated list of suspicious function names found.
        """
        found: Set[str] = set()

        # Check ABI entries
        if abi:
            for entry in abi:
                if entry.get("type") == "function":
                    fn_name = entry.get("name", "")
                    if any(s.lower() in fn_name.lower() for s in SUSPICIOUS_FUNCTIONS):
                        found.add(fn_name)

        # Check source code with pre-compiled regex patterns
        if source_code:
            for suspicious, pattern in _COMPILED_FUNCTION_PATTERNS.items():
                if pattern.search(source_code):
                    found.add(suspicious)

        return sorted(found)

    def extract_tax_info(self, source_code: str) -> Dict[str, float]:
        """
        Attempt to parse buy/sell tax percentages from the Solidity source.

        Returns a dict such as::

            {"sell_tax": 5.0, "buy_tax": 3.0}

        Values default to 0.0 when not found.
        """
        taxes: Dict[str, float] = {"sell_tax": 0.0, "buy_tax": 0.0}
        if not source_code:
            return taxes

        for compiled_pattern, raw_pattern in zip(_COMPILED_TAX_PATTERNS, TAX_PATTERNS):
            match = compiled_pattern.search(source_code)
            if match:
                value = float(match.group(1))
                name = raw_pattern.split("(")[0].lower()
                if "sell" in name:
                    taxes["sell_tax"] = value
                elif "buy" in name:
                    taxes["buy_tax"] = value
                else:
                    # Generic fee – assign to both if not yet set
                    if taxes["sell_tax"] == 0.0:
                        taxes["sell_tax"] = value
                    if taxes["buy_tax"] == 0.0:
                        taxes["buy_tax"] = value

        return taxes

    def full_analysis(self, contract_address: str) -> Dict:
        """
        Run a complete analysis for *contract_address*.

        Fetches ABI + source from BSCScan, then returns::

            {
                "creator":           str | None,
                "abi_available":     bool,
                "source_available":  bool,
                "hidden_functions":  List[str],
                "taxes":             {"sell_tax": float, "buy_tax": float},
            }
        """
        logger.info("Analysing contract %s", contract_address)

        abi = self.get_contract_abi(contract_address)
        source = self.get_contract_source(contract_address)
        creator = self.get_contract_creator(contract_address)

        hidden_functions = self.find_hidden_functions(abi=abi, source_code=source)
        taxes = self.extract_tax_info(source or "")

        return {
            "creator": creator,
            "abi_available": abi is not None,
            "source_available": bool(source),
            "hidden_functions": hidden_functions,
            "taxes": taxes,
        }
