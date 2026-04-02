"""
BSC Token Monitor – entry point.

Usage
-----
Run the HTTP polling monitor:
    python main.py

Run a one-off security audit for a specific token:
    python main.py --audit 0xTokenAddress

Print the decision JSON for a token (no real transactions):
    python main.py --decision 0xTokenAddress
"""

import argparse
import json
import logging
import os
import sys

from dotenv import load_dotenv

load_dotenv()

# Configure logging before importing any project modules
log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, log_level, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

logger = logging.getLogger(__name__)


def run_monitor(auto_buy: bool = False) -> None:
    """Start the real-time block monitor."""
    from src.monitor import BlockMonitor

    monitor = BlockMonitor(auto_buy=auto_buy)
    print("=" * 60)
    print("  BSC Token Monitor – Block Scanner")
    print(f"  Session: {monitor.log.session_id}")
    print(f"  Auto-buy: {auto_buy}")
    print("=" * 60)
    print("Press Ctrl+C to stop.\n")

    session_log = monitor.run()
    print("\n--- Session Summary ---")
    print(f"Blocks scanned  : {session_log.blocks_scanned}")
    print(f"Tokens found    : {len(session_log.tokens_discovered)}")
    print(f"Total PnL       : {session_log.total_profit_bnb:.4f} BNB")
    print(f"Alerts raised   : {len(session_log.security_alerts)}")


def run_audit(token_address: str) -> None:
    """Perform a security audit and print the result."""
    from src.security_validator import SecurityValidator
    from src.decision_engine import DecisionEngine

    validator = SecurityValidator()
    engine = DecisionEngine()

    print(f"\nAuditing token: {token_address}\n")
    audit = validator.validate(token_address)
    decision = engine.make_decision(audit)

    print(json.dumps(decision, indent=2))


def run_decision(token_address: str) -> None:
    """Print a JSON decision for *token_address* (alias for audit)."""
    run_audit(token_address)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="BSC Token Security Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--audit",
        metavar="TOKEN_ADDRESS",
        help="Run a one-off security audit for a token and print JSON output.",
    )
    parser.add_argument(
        "--decision",
        metavar="TOKEN_ADDRESS",
        help="Alias for --audit.",
    )
    parser.add_argument(
        "--auto-buy",
        action="store_true",
        default=False,
        help="Enable automatic buying (USE WITH EXTREME CAUTION – real funds!)",
    )

    args = parser.parse_args()

    if args.audit:
        run_audit(args.audit)
    elif args.decision:
        run_decision(args.decision)
    else:
        run_monitor(auto_buy=args.auto_buy)


if __name__ == "__main__":
    main()
