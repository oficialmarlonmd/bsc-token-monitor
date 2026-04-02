"""
Web3 client module for BSC (Binance Smart Chain) interaction.

Responsibilities
----------------
- Establish an HTTP/WebSocket connection to a BSC RPC endpoint.
- Provide helper methods for reading blockchain state (balance, token info, LP data).
- Execute transaction simulation via eth_call (honeypot detection).
- Sign and broadcast buy/sell swap transactions via PancakeSwap V2 Router.
- Manage nonce, gas price, and gas limit.
"""

import os
import json
import logging
from typing import Optional, Tuple

from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# PancakeSwap V2 Router on BSC mainnet
PANCAKESWAP_ROUTER_ADDRESS = Web3.to_checksum_address(
    "0x10ED43C718714eb63d5aA57B78B54704E256024E"
)

# Wrapped BNB (WBNB) contract address on BSC
WBNB_ADDRESS = Web3.to_checksum_address(
    "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c"
)

# PancakeSwap V2 Factory – used to look up LP pair addresses
PANCAKESWAP_FACTORY_ADDRESS = Web3.to_checksum_address(
    "0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73"
)

# Address considered "burned" – LP tokens sent here are permanently locked
DEAD_ADDRESS = "0x000000000000000000000000000000000000dEaD"
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

# Minimal ABIs needed for common on-chain calls

# Minimum fraction of total LP supply that must be at burn/zero addresses
# for the LP to be considered burned (95%).
LP_BURN_THRESHOLD = 0.95

ERC20_MINIMAL_ABI = json.loads("""[
  {"constant":true,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"type":"function"},
  {"constant":true,"inputs":[],"name":"name","outputs":[{"name":"","type":"string"}],"type":"function"},
  {"constant":true,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"type":"function"},
  {"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"name":"","type":"uint256"}],"type":"function"},
  {"constant":true,"inputs":[{"name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"type":"function"},
  {"constant":false,"inputs":[{"name":"_spender","type":"address"},{"name":"_value","type":"uint256"}],"name":"approve","outputs":[{"name":"","type":"bool"}],"type":"function"}
]""")

PANCAKE_FACTORY_ABI = json.loads("""[
  {"constant":true,"inputs":[{"internalType":"address","name":"tokenA","type":"address"},{"internalType":"address","name":"tokenB","type":"address"}],"name":"getPair","outputs":[{"internalType":"address","name":"pair","type":"address"}],"stateMutability":"view","type":"function"}
]""")

PANCAKE_PAIR_ABI = json.loads("""[
  {"constant":true,"inputs":[],"name":"getReserves","outputs":[{"internalType":"uint112","name":"_reserve0","type":"uint112"},{"internalType":"uint112","name":"_reserve1","type":"uint112"},{"internalType":"uint32","name":"_blockTimestampLast","type":"uint32"}],"stateMutability":"view","type":"function"},
  {"constant":true,"inputs":[],"name":"token0","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},
  {"constant":true,"inputs":[],"name":"token1","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},
  {"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},
  {"constant":true,"inputs":[{"name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"type":"function"}
]""")

PANCAKE_ROUTER_ABI = json.loads("""[
  {"inputs":[{"internalType":"uint256","name":"amountOutMin","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapExactETHForTokensSupportingFeeOnTransferTokens","outputs":[],"stateMutability":"payable","type":"function"},
  {"inputs":[{"internalType":"uint256","name":"amountIn","type":"uint256"},{"internalType":"uint256","name":"amountOutMin","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapExactTokensForETHSupportingFeeOnTransferTokens","outputs":[],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[{"internalType":"uint256","name":"amountIn","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"}],"name":"getAmountsOut","outputs":[{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"stateMutability":"view","type":"function"}
]""")

OWNABLE_ABI = json.loads("""[
  {"constant":true,"inputs":[],"name":"owner","outputs":[{"name":"","type":"address"}],"type":"function"}
]""")


# ---------------------------------------------------------------------------
# BSCWeb3Client
# ---------------------------------------------------------------------------

class BSCWeb3Client:
    """
    High-level client for interacting with the Binance Smart Chain.

    Usage
    -----
    >>> client = BSCWeb3Client()
    >>> if client.is_connected():
    ...     info = client.get_token_info("0x...")
    """

    def __init__(
        self,
        rpc_url: Optional[str] = None,
        private_key: Optional[str] = None,
        wallet_address: Optional[str] = None,
    ):
        self.rpc_url = rpc_url or os.getenv("RPC_URL", "https://bsc-dataseed1.binance.org/")
        self.private_key = private_key or os.getenv("PRIVATE_KEY")
        self.wallet_address = wallet_address or os.getenv("WALLET_ADDRESS")
        self.gas_price_multiplier = float(os.getenv("GAS_PRICE_MULTIPLIER", "1.2"))

        # Connect and inject POA (Proof-of-Authority) middleware required by BSC
        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        self.w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

        if not self.is_connected():
            logger.warning("Could not connect to BSC RPC at %s", self.rpc_url)
        else:
            logger.info("Connected to BSC RPC. Latest block: %d", self.w3.eth.block_number)

    # ------------------------------------------------------------------
    # Connection helpers
    # ------------------------------------------------------------------

    def is_connected(self) -> bool:
        """Return True if the Web3 instance can reach the BSC node."""
        try:
            return self.w3.is_connected()
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Token information
    # ------------------------------------------------------------------

    def get_token_info(self, token_address: str) -> dict:
        """
        Fetch basic BEP-20 token metadata from the chain.

        Returns a dict with keys: symbol, name, decimals, total_supply.
        Returns an empty dict on failure.
        """
        try:
            address = Web3.to_checksum_address(token_address)
            contract = self.w3.eth.contract(address=address, abi=ERC20_MINIMAL_ABI)
            return {
                "symbol": contract.functions.symbol().call(),
                "name": contract.functions.name().call(),
                "decimals": contract.functions.decimals().call(),
                "total_supply": contract.functions.totalSupply().call(),
            }
        except Exception as exc:
            logger.error("get_token_info failed for %s: %s", token_address, exc)
            return {}

    def get_token_balance(self, token_address: str, wallet: str) -> int:
        """Return the raw token balance (integer) for *wallet*."""
        try:
            token = self.w3.eth.contract(
                address=Web3.to_checksum_address(token_address),
                abi=ERC20_MINIMAL_ABI,
            )
            return token.functions.balanceOf(Web3.to_checksum_address(wallet)).call()
        except Exception as exc:
            logger.error("get_token_balance failed: %s", exc)
            return 0

    def get_owner(self, token_address: str) -> Optional[str]:
        """
        Call owner() on the token contract.

        Returns None if the function does not exist (contract may not be Ownable).
        Returns ZERO_ADDRESS string if ownership has been renounced.
        """
        try:
            contract = self.w3.eth.contract(
                address=Web3.to_checksum_address(token_address),
                abi=OWNABLE_ABI,
            )
            return contract.functions.owner().call()
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Liquidity / LP helpers
    # ------------------------------------------------------------------

    def get_pair_address(self, token_address: str) -> Optional[str]:
        """
        Look up the PancakeSwap V2 LP pair address for TOKEN/WBNB.

        Returns None if no pair exists.
        """
        try:
            factory = self.w3.eth.contract(
                address=PANCAKESWAP_FACTORY_ADDRESS,
                abi=PANCAKE_FACTORY_ABI,
            )
            pair = factory.functions.getPair(
                Web3.to_checksum_address(token_address),
                WBNB_ADDRESS,
            ).call()
            return pair if pair != ZERO_ADDRESS else None
        except Exception as exc:
            logger.error("get_pair_address failed: %s", exc)
            return None

    def get_liquidity_bnb(self, pair_address: str, token_address: str) -> float:
        """
        Return the BNB reserve in the LP pair (in BNB, not Wei).

        The pair holds two tokens; we identify which slot is WBNB by
        comparing token0/token1 to the WBNB address.
        """
        try:
            pair = self.w3.eth.contract(
                address=Web3.to_checksum_address(pair_address),
                abi=PANCAKE_PAIR_ABI,
            )
            token0 = pair.functions.token0().call()
            reserves = pair.functions.getReserves().call()  # (reserve0, reserve1, ts)

            # Determine which reserve slot holds WBNB
            if token0.lower() == WBNB_ADDRESS.lower():
                bnb_reserve_wei = reserves[0]
            else:
                bnb_reserve_wei = reserves[1]

            return float(self.w3.from_wei(bnb_reserve_wei, "ether"))
        except Exception as exc:
            logger.error("get_liquidity_bnb failed: %s", exc)
            return 0.0

    def is_lp_burned(self, pair_address: str) -> bool:
        """
        Check whether LP tokens have been burned.

        "Burned" means LP tokens were sent to the DEAD address (0x...dEaD)
        OR the zero address (0x0000...0000).  This prevents the creator from
        removing liquidity and running a rug-pull.
        """
        try:
            pair = self.w3.eth.contract(
                address=Web3.to_checksum_address(pair_address),
                abi=PANCAKE_PAIR_ABI,
            )
            total_lp = pair.functions.totalSupply().call()
            if total_lp == 0:
                return False

            dead_balance = pair.functions.balanceOf(
                Web3.to_checksum_address(DEAD_ADDRESS)
            ).call()
            zero_balance = pair.functions.balanceOf(
                Web3.to_checksum_address(ZERO_ADDRESS)
            ).call()

            burned = dead_balance + zero_balance
            # Consider burned if ≥ LP_BURN_THRESHOLD of total LP supply is at burn addresses
            return (burned / total_lp) >= LP_BURN_THRESHOLD
        except Exception as exc:
            logger.error("is_lp_burned failed: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Transaction simulation (honeypot detection)
    # ------------------------------------------------------------------

    def simulate_sell(
        self,
        token_address: str,
        amount_tokens: int,
        from_address: str,
    ) -> Tuple[bool, str]:
        """
        Simulate a sell transaction using eth_call (read-only, no gas cost).

        This detects honeypots: tokens you can buy but CANNOT sell.

        Parameters
        ----------
        token_address : str
            Contract address of the token.
        amount_tokens : int
            Raw token amount to attempt selling (e.g. 1 * 10**18).
        from_address : str
            The wallet address used as the caller in the simulation.

        Returns
        -------
        (success: bool, message: str)
        """
        try:
            router = self.w3.eth.contract(
                address=PANCAKESWAP_ROUTER_ADDRESS,
                abi=PANCAKE_ROUTER_ABI,
            )
            path = [Web3.to_checksum_address(token_address), WBNB_ADDRESS]
            deadline = self.w3.eth.get_block("latest")["timestamp"] + 60

            # eth_call is read-only; it reverts if the sell would fail
            router.functions.swapExactTokensForETHSupportingFeeOnTransferTokens(
                amount_tokens,
                0,          # accept any amount of BNB out
                path,
                Web3.to_checksum_address(from_address),
                deadline,
            ).call({"from": Web3.to_checksum_address(from_address)})

            return True, "Sell simulation succeeded – not a honeypot"
        except Exception as exc:
            return False, f"Sell simulation FAILED (honeypot?): {exc}"

    # ------------------------------------------------------------------
    # Gas helpers
    # ------------------------------------------------------------------

    def get_gas_price_gwei(self) -> float:
        """Return the current network gas price in Gwei, scaled by the multiplier."""
        try:
            base_gwei = float(self.w3.from_wei(self.w3.eth.gas_price, "gwei"))
            return round(base_gwei * self.gas_price_multiplier, 2)
        except Exception:
            return 5.0  # fallback

    def estimate_gas(self, tx_params: dict) -> int:
        """Estimate gas for a transaction dict; return a safe default on error."""
        try:
            return self.w3.eth.estimate_gas(tx_params)
        except Exception:
            return 300_000  # safe upper bound for swap transactions

    # ------------------------------------------------------------------
    # Buy / Sell execution
    # ------------------------------------------------------------------

    def buy_token(
        self,
        token_address: str,
        amount_bnb: float,
        slippage_percent: float = 10.0,
    ) -> Tuple[bool, str]:
        """
        Execute a buy swap: BNB → Token via PancakeSwap V2.

        Parameters
        ----------
        token_address   : Target token contract address.
        amount_bnb      : Amount of BNB to spend.
        slippage_percent: Maximum acceptable slippage (default 10%).

        Returns (success, tx_hash_or_error_message).
        """
        if not self.private_key or not self.wallet_address:
            return False, "PRIVATE_KEY / WALLET_ADDRESS not configured"
        try:
            router = self.w3.eth.contract(
                address=PANCAKESWAP_ROUTER_ADDRESS,
                abi=PANCAKE_ROUTER_ABI,
            )
            path = [WBNB_ADDRESS, Web3.to_checksum_address(token_address)]
            amount_in_wei = self.w3.to_wei(amount_bnb, "ether")
            deadline = self.w3.eth.get_block("latest")["timestamp"] + 60

            # Calculate minimum tokens out (accounting for slippage)
            amounts_out = router.functions.getAmountsOut(amount_in_wei, path).call()
            min_out = int(amounts_out[-1] * (1 - slippage_percent / 100))

            gas_price_wei = self.w3.to_wei(self.get_gas_price_gwei(), "gwei")
            nonce = self.w3.eth.get_transaction_count(
                Web3.to_checksum_address(self.wallet_address)
            )

            tx = router.functions.swapExactETHForTokensSupportingFeeOnTransferTokens(
                min_out, path,
                Web3.to_checksum_address(self.wallet_address),
                deadline,
            ).build_transaction({
                "from": Web3.to_checksum_address(self.wallet_address),
                "value": amount_in_wei,
                "gasPrice": gas_price_wei,
                "nonce": nonce,
                "gas": 300_000,
            })

            signed = self.w3.eth.account.sign_transaction(tx, self.private_key)
            tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
            return True, tx_hash.hex()
        except Exception as exc:
            return False, str(exc)

    def sell_token(
        self,
        token_address: str,
        token_amount: int,
        slippage_percent: float = 10.0,
    ) -> Tuple[bool, str]:
        """
        Execute a sell swap: Token → BNB via PancakeSwap V2.

        Parameters
        ----------
        token_address : Token contract address.
        token_amount  : Raw token amount to sell (integer, not divided by decimals).
        slippage_percent: Maximum acceptable slippage (default 10%).

        Returns (success, tx_hash_or_error_message).
        """
        if not self.private_key or not self.wallet_address:
            return False, "PRIVATE_KEY / WALLET_ADDRESS not configured"
        try:
            wallet = Web3.to_checksum_address(self.wallet_address)
            token_addr = Web3.to_checksum_address(token_address)
            gas_price_wei = self.w3.to_wei(self.get_gas_price_gwei(), "gwei")
            nonce = self.w3.eth.get_transaction_count(wallet)

            # Step 1: Approve the router to spend tokens
            token_contract = self.w3.eth.contract(address=token_addr, abi=ERC20_MINIMAL_ABI)
            approve_tx = token_contract.functions.approve(
                PANCAKESWAP_ROUTER_ADDRESS, token_amount
            ).build_transaction({
                "from": wallet,
                "gasPrice": gas_price_wei,
                "nonce": nonce,
                "gas": 100_000,
            })
            signed_approve = self.w3.eth.account.sign_transaction(approve_tx, self.private_key)
            self.w3.eth.send_raw_transaction(signed_approve.raw_transaction)

            # Step 2: Execute the swap
            router = self.w3.eth.contract(
                address=PANCAKESWAP_ROUTER_ADDRESS,
                abi=PANCAKE_ROUTER_ABI,
            )
            path = [token_addr, WBNB_ADDRESS]
            amounts_out = router.functions.getAmountsOut(token_amount, path).call()
            min_bnb_out = int(amounts_out[-1] * (1 - slippage_percent / 100))
            deadline = self.w3.eth.get_block("latest")["timestamp"] + 60

            sell_tx = router.functions.swapExactTokensForETHSupportingFeeOnTransferTokens(
                token_amount,
                min_bnb_out,
                path,
                wallet,
                deadline,
            ).build_transaction({
                "from": wallet,
                "gasPrice": gas_price_wei,
                "nonce": nonce + 1,
                "gas": 300_000,
            })
            signed_sell = self.w3.eth.account.sign_transaction(sell_tx, self.private_key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_sell.raw_transaction)
            return True, tx_hash.hex()
        except Exception as exc:
            return False, str(exc)
