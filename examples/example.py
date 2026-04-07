# Copyright (c) 2026 CaviarNine
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
Cantex SDK -- Example Usage

Set the following environment variables before running:

    export CANTEX_BASE_URL="https://api.cantex.io"
    export CANTEX_OPERATOR_KEY="<operator Ed25519 private key hex>"
    export CANTEX_TRADING_KEY="<intent secp256k1 private key hex>"

Then:

    python example.py
"""

import asyncio
import logging
import os
import sys
from decimal import Decimal

from cantex_sdk import (
    CantexAPIError,
    CantexAuthError,
    CantexSDK,
    CantexTimeoutError,
    FundingEvent,
    InstrumentId,
    IntentTradingKeySigner,
    OperatorKeySigner,
    SwapExecutedEvent,
    SwapFailedEvent,
    SwapPendingEvent,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
log = logging.getLogger("example")


async def main() -> None:
    # ── 1. Configuration from environment ──────────────────────────────
    base_url = os.environ.get("CANTEX_BASE_URL", "https://api.cantex.io")

    operator_hex = os.environ.get("CANTEX_OPERATOR_KEY")
    if not operator_hex:
        sys.exit("CANTEX_OPERATOR_KEY environment variable is required")

    intent_hex = os.environ.get("CANTEX_TRADING_KEY")
    if not intent_hex:
        sys.exit("CANTEX_TRADING_KEY environment variable is required")

    # ── 2. Build signers ───────────────────────────────────────────────
    operator = OperatorKeySigner.from_hex(operator_hex)
    intent = IntentTradingKeySigner.from_hex(intent_hex)

    # ── 3. Initialise SDK and authenticate ─────────────────────────────
    async with CantexSDK(operator, intent, base_url=base_url) as sdk:
        api_key = await sdk.authenticate()
        log.info("Authenticated (API key: %s...)", api_key[:8])

        # ── 4. Read account admin ──────────────────────────────────────
        admin = await sdk.get_account_admin()
        log.info("Party address: %s", admin.address)
        log.info("User ID: %s", admin.user_id)
        log.info("Trading account exists: %s", admin.has_trading_account)
        log.info("Intent account exists: %s", admin.has_intent_account)

        for inst in admin.instruments:
            log.info("  Instrument: %s [%s]", inst.instrument_name, inst.instrument)

        # ── 5. Read account balances ───────────────────────────────────
        info = await sdk.get_account_info()
        log.info("Account address: %s", info.address)

        for token in info.tokens:
            log.info(
                "  %s (%s): unlocked=%s  locked=%s",
                token.instrument_name,
                token.instrument_symbol,
                token.unlocked_amount,
                token.locked_amount,
            )

        # ── 6. List pools ─────────────────────────────────────────────
        pools = await sdk.get_pool_info()
        log.info("Available pools: %d", len(pools.pools))

        for pool in pools.pools:
            log.info(
                "  Pool %s...: %s <-> %s",
                pool.contract_id[:16],
                pool.token_a.id,
                pool.token_b.id,
            )

        # ── 7. Get a swap quote ────────────────────────────────────────
        if pools.pools:
            pool = pools.pools[0]
            quote = await sdk.get_swap_quote(
                sell_amount=Decimal("1"),
                sell_instrument=pool.token_a,
                buy_instrument=pool.token_b,
            )
            log.info("Quote: trade_price=%s", quote.prices.trade)
            log.info("  Returned: %s %s", quote.returned_amount, quote.returned.instrument.id)
            log.info("  Slippage: %s", quote.prices.slippage)
            log.info("  Trade (no fees): %s", quote.prices.trade_no_fees)
            log.info("  Fees: %s%%  (admin=%s, liquidity=%s, network=%s)",
                     quote.fees.fee_percentage,
                     quote.fees.amount_admin,
                     quote.fees.amount_liquidity,
                     quote.fees.network_fee.amount)
            log.info("  Pool price: %s -> %s",
                     quote.prices.pool_before,
                     quote.prices.pool_after)
            log.info("  Estimated time: %ss", quote.estimated_time_seconds)

        # ── 8. Execute a swap ────────────────────────────
        # Uncomment to actually execute -- requires intent signer and
        # sufficient balance:
        #
        # result = await sdk.swap(
        #     sell_amount=Decimal("10"),
        #     sell_instrument=pool.token_a,
        #     buy_instrument=pool.token_b,
        # )
        # log.info("Swap result: %s", result)

        # ── 8b. Swap with confirmation ────────────────────────────────
        # Like swap(), but waits for on-ledger confirmation via WebSocket.
        # Returns a SwapExecutedEvent or raises on failure/timeout.
        
        confirmed = await sdk.swap_and_confirm(
            sell_amount=Decimal("10"),
            sell_instrument=pool.token_a,
            buy_instrument=pool.token_b,
            timeout=60.0,
        )
        log.info("Confirmed: %s %s -> %s %s (price=%s)",
                 confirmed.input_amount, confirmed.input_instrument.id,
                 confirmed.output_amount, confirmed.output_instrument.id,
                 confirmed.price)

        # ── 9. Transfer tokens ─────────────────────────────────────────
        # Uncomment to actually transfer:
        #
        # result = await sdk.transfer(
        #     amount=Decimal("1.0"),
        #     instrument=InstrumentId(admin="DSO::1220...", id="Amulet"),
        #     receiver="Cantex::1220...",
        #     memo="test transfer",
        # )
        # log.info("Transfer result: %s", result)

        # ── 10. Error handling ─────────────────────────────────────────
        # try:
        #     await sdk.get_swap_quote(
        #         sell_amount=Decimal("0"),
        #         sell_instrument=InstrumentId(admin="INVALID", id="INVALID"),
        #         buy_instrument=InstrumentId(admin="INVALID", id="INVALID"),
        #     )
        # except CantexAuthError as exc:
        #     log.error("Auth error (HTTP %d): %s", exc.status, exc.body[:100])
        # except CantexAPIError as exc:
        #     log.warning("API error (HTTP %d): %s", exc.status, exc.body[:100])
        # except CantexTimeoutError:
        #     log.warning("Request timed out")

        # ── 11. Stream WebSocket events ────────────────────────────────
        # log.info("Connecting to private WebSocket...")
        # async with sdk.connect_private_ws() as ws:
        #     log.info("Listening for events (Ctrl+C to stop)...")
        #     async for event in ws:
        #         if isinstance(event, SwapExecutedEvent):
        #             log.info(
        #                 "Swap confirmed: %s %s -> %s %s (price=%s)",
        #                 event.input_amount, event.input_instrument.id,
        #                 event.output_amount, event.output_instrument.id,
        #                 event.price,
        #             )
        #         elif isinstance(event, SwapPendingEvent):
        #             log.info(
        #                 "Swap pending: %s -> %s (id=%s)",
        #                 event.input_instrument.id,
        #                 event.output_instrument.id,
        #                 event.swap_id,
        #             )
        #         elif isinstance(event, SwapFailedEvent):
        #             log.warning(
        #                 "Swap failed: %s -> %s: %s",
        #                 event.input_instrument.id,
        #                 event.output_instrument.id,
        #                 event.error,
        #             )
        #         elif isinstance(event, FundingEvent):
        #             log.info(
        #                 "%s: %s %s (%s -> %s)",
        #                 event.event_type,
        #                 event.amount,
        #                 event.instrument.id,
        #                 event.sender[:20],
        #                 event.receiver[:20],
        #             )
        #         else:
        #             log.info("Event [%s]: %s", event.event_type, event.data)

    log.info("Done -- session closed")


if __name__ == "__main__":
    asyncio.run(main())
