"""
Real-time block monitoring and alerting system.

Monitors new BSC blocks for newly deployed token contracts and
PancakeSwap liquidity-add events, then runs the security pipeline
on each discovered token.

Architecture
------------
- ``BlockMonitor.run()`` – synchronous polling loop (HTTP RPC).
- ``WebSocketMonitor.run()`` – async WebSocket subscription (wss:// RPC).
  Use ``WebSocketMonitor`` when you have a private RPC with WSS support.
"""

import asyncio
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

from web3 import Web3
from dotenv import load_dotenv

from .models import MonitoringLog, TokenInfo, TransactionRecord
from .web3_client import BSCWeb3Client
from .security_validator import SecurityValidator
from .decision_engine import DecisionEngine
from .database import Database

load_dotenv()

logger = logging.getLogger(__name__)

# PancakeSwap V2 Factory – we watch for PairCreated events to detect new tokens
PANCAKESWAP_FACTORY_ADDRESS = Web3.to_checksum_address(
    "0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73"
)

PAIR_CREATED_ABI = [
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "token0", "type": "address"},
            {"indexed": True, "name": "token1", "type": "address"},
            {"indexed": False, "name": "pair", "type": "address"},
            {"indexed": False, "name": "allPairsLength", "type": "uint256"},
        ],
        "name": "PairCreated",
        "type": "event",
    }
]


class BlockMonitor:
    """
    Synchronous (HTTP polling) block monitor.

    Polls for new blocks every *poll_interval* seconds and scans each block
    for PairCreated events from the PancakeSwap Factory.  Each new pair
    triggers a full security audit.

    Parameters
    ----------
    poll_interval : int
        Seconds between block polls (default: 3 – roughly one BSC block).
    auto_buy : bool
        If True, execute a buy when the decision engine returns "BUY".
    buy_amount_bnb : float
        BNB amount to spend on each automated buy.
    """

    def __init__(
        self,
        poll_interval: int = 3,
        auto_buy: bool = False,
        buy_amount_bnb: Optional[float] = None,
        web3_client: Optional[BSCWeb3Client] = None,
        validator: Optional[SecurityValidator] = None,
        decision_engine: Optional[DecisionEngine] = None,
        database: Optional[Database] = None,
    ):
        self.poll_interval = poll_interval
        self.auto_buy = auto_buy
        self.buy_amount_bnb = buy_amount_bnb or float(
            os.getenv("BUY_AMOUNT_BNB", "0.05")
        )

        self.client = web3_client or BSCWeb3Client()
        self.validator = validator or SecurityValidator(web3_client=self.client)
        self.decision_engine = decision_engine or DecisionEngine(web3_client=self.client)
        self.db = database or Database()
        self.log = MonitoringLog(session_id=str(uuid.uuid4()))

        self._factory_contract = self.client.w3.eth.contract(
            address=PANCAKESWAP_FACTORY_ADDRESS,
            abi=PAIR_CREATED_ABI,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _scan_block(self, block_number: int) -> None:
        """Scan a single block for PairCreated events."""
        try:
            events = self.client.w3.eth.get_logs({
                "fromBlock": block_number,
                "toBlock": block_number,
                "address": PANCAKESWAP_FACTORY_ADDRESS,
            })
            for raw_log in events:
                try:
                    event = self._factory_contract.events.PairCreated().process_log(raw_log)
                    self._handle_new_pair(event)
                except Exception as exc:
                    logger.debug("Could not decode log: %s", exc)
        except Exception as exc:
            logger.error("Error scanning block %d: %s", block_number, exc)

    def _handle_new_pair(self, event) -> None:
        """
        Called for every PairCreated event.

        Identifies which token in the pair is NOT WBNB, fetches its metadata,
        runs the security audit, and optionally executes a buy.
        """
        from .web3_client import WBNB_ADDRESS

        token0 = event["args"]["token0"]
        token1 = event["args"]["token1"]
        pair_address = event["args"]["pair"]

        # Identify the non-WBNB token
        if token0.lower() == WBNB_ADDRESS.lower():
            token_address = token1
        elif token1.lower() == WBNB_ADDRESS.lower():
            token_address = token0
        else:
            # Neither token is WBNB – skip (e.g. stablecoin pairs)
            return

        logger.info("New token detected: %s (pair: %s)", token_address, pair_address)
        self.log.add_alert(f"New token: {token_address} | pair: {pair_address}")

        # Fetch on-chain metadata
        info = self.client.get_token_info(token_address)
        token_info = TokenInfo(
            contract_address=token_address,
            symbol=info.get("symbol", "UNKNOWN"),
            name=info.get("name", "Unknown Token"),
            decimals=info.get("decimals", 18),
            total_supply=info.get("total_supply", 0),
            creator="",
            pair_address=pair_address,
        )
        self.log.tokens_discovered.append(token_info)

        # Security audit
        audit = self.validator.validate(token_address)
        self.db.save_audit(audit)

        # Decision
        decision_obj = self.decision_engine.make_decision(audit)
        logger.info(
            "Decision for %s: %s (score=%d, confidence=%d)",
            token_address,
            decision_obj["decision"],
            decision_obj["risk_score"],
            decision_obj["confidence_score"],
        )

        if audit.decision == "SKIP":
            self.log.add_alert(
                f"SKIP {token_address}: {audit.reason}"
            )
            return

        # Opportunity alert
        self.log.add_alert(
            f"BUY OPPORTUNITY: {token_info.symbol} ({token_address}) "
            f"– confidence {decision_obj['confidence_score']}"
        )

        # Auto-buy (disabled by default for safety)
        if self.auto_buy:
            success, tx_hash = self.client.buy_token(token_address, self.buy_amount_bnb)
            status = "SUCCESS" if success else "FAILED"
            tx_record = TransactionRecord(
                tx_type="BUY",
                token_address=token_address,
                token_symbol=token_info.symbol,
                amount_bnb=self.buy_amount_bnb,
                token_amount=0,  # updated after confirmation
                gas_price_gwei=self.client.get_gas_price_gwei(),
                tx_hash=tx_hash if success else "",
                status=status,
            )
            self.db.save_transaction(tx_record)
            self.log.transactions.append(tx_record)
            if success:
                logger.info("Buy TX sent: %s", tx_hash)
            else:
                logger.error("Buy TX failed: %s", tx_hash)

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def run(self, max_blocks: Optional[int] = None) -> MonitoringLog:
        """
        Start the polling monitor.

        Parameters
        ----------
        max_blocks : int, optional
            Stop after scanning this many blocks (useful for testing).
            Pass None to run indefinitely.

        Returns
        -------
        MonitoringLog
            The log accumulated during the session.
        """
        logger.info(
            "BlockMonitor starting | session=%s | auto_buy=%s",
            self.log.session_id,
            self.auto_buy,
        )
        last_block = self.client.w3.eth.block_number
        blocks_scanned = 0

        try:
            while True:
                current_block = self.client.w3.eth.block_number
                if current_block > last_block:
                    for block_num in range(last_block + 1, current_block + 1):
                        self._scan_block(block_num)
                        blocks_scanned += 1
                        self.log.blocks_scanned = blocks_scanned

                        if max_blocks is not None and blocks_scanned >= max_blocks:
                            raise KeyboardInterrupt("max_blocks reached")
                    last_block = current_block
                time.sleep(self.poll_interval)
        except KeyboardInterrupt:
            logger.info("Monitor stopped by user / limit reached.")

        self.log.ended_at = datetime.now(timezone.utc)
        self.log.calculate_profit()
        logger.info(
            "Session ended. Blocks: %d | Tokens found: %d | PnL: %.4f BNB",
            self.log.blocks_scanned,
            len(self.log.tokens_discovered),
            self.log.total_profit_bnb,
        )
        return self.log


# ---------------------------------------------------------------------------
# WebSocket (async) monitor
# ---------------------------------------------------------------------------

class WebSocketMonitor:
    """
    Async WebSocket monitor for real-time new-block subscriptions.

    Requires a ``WSS_URL`` in the environment pointing to a WebSocket-capable
    RPC endpoint (e.g. QuickNode or Alchemy).

    Usage
    -----
    >>> monitor = WebSocketMonitor()
    >>> asyncio.run(monitor.run())
    """

    def __init__(
        self,
        wss_url: Optional[str] = None,
        validator: Optional[SecurityValidator] = None,
        database: Optional[Database] = None,
    ):
        self.wss_url = wss_url or os.getenv("WSS_URL", "")
        self.validator = validator or SecurityValidator()
        self.db = database or Database()
        self.log = MonitoringLog(session_id=str(uuid.uuid4()))

    async def run(self) -> MonitoringLog:
        """
        Subscribe to new block headers via WebSocket and scan each block.

        Falls back gracefully if the wss_url is not configured.
        """
        if not self.wss_url:
            logger.error("WSS_URL not configured. Cannot start WebSocket monitor.")
            return self.log

        try:
            from web3 import AsyncWeb3
            from web3.providers import WebSocketProvider

            async with AsyncWeb3(WebSocketProvider(self.wss_url)) as w3:
                logger.info("WebSocket connected to %s", self.wss_url)
                subscription_id = await w3.eth.subscribe("newHeads")
                async for response in w3.socket.process_subscriptions():
                    block_number = int(response["result"]["number"], 16)
                    logger.debug("New block via WS: %d", block_number)
                    self.log.blocks_scanned += 1
        except Exception as exc:
            logger.error("WebSocket monitor error: %s", exc)
        finally:
            self.log.ended_at = datetime.now(timezone.utc)

        return self.log
