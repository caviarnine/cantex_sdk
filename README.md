# Cantex SDK

An async Python SDK for the [Cantex](https://cantex.io) decentralised exchange API. It handles authentication, transaction signing, and provides typed response models for all API endpoints.

## License

MIT OR Apache-2.0 at your option. See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).

## Installation

```bash
pip install .            # runtime only
pip install -e ".[dev]"  # includes test dependencies
```

Requires Python 3.11+.

## Quick Start

```python
import asyncio
import os
from decimal import Decimal
from cantex_sdk import CantexSDK, OperatorKeySigner, IntentTradingKeySigner

async def main():
    operator = OperatorKeySigner.from_hex(os.environ["CANTEX_OPERATOR_KEY"])
    intent = IntentTradingKeySigner.from_hex(os.environ["CANTEX_TRADING_KEY"])

    async with CantexSDK(operator, intent) as sdk:
        await sdk.authenticate()

        info = await sdk.get_account_info()
        for token in info.tokens:
            print(f"{token.instrument_symbol}: {token.unlocked_amount}")

asyncio.run(main())
```

See [`examples/example.py`](examples/example.py) for a full walkthrough including swaps, WebSocket streaming, and error handling.

## Environment Variables

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `CANTEX_OPERATOR_KEY` | Yes | — | Operator Ed25519 private key (hex) |
| `CANTEX_TRADING_KEY` | No | — | Intent trading secp256k1 private key (hex). Required for swaps. |
| `CANTEX_BASE_URL` | No | `https://api.testnet.cantex.io` | API base URL (mainnet: `https://api.cantex.io`) |

## SDK Reference

### Signers

Both signers extend `BaseSigner` and support the same constructors: `from_hex`, `from_env`, `from_hex_file`, `from_pem_file`, `from_raw_file`, and `from_file`.

- **`OperatorKeySigner`** — Signs authentication challenges (Ed25519).
- **`IntentTradingKeySigner`** — Signs intent transactions (secp256k1). Required for swaps.

### `CantexSDK`

```python
CantexSDK(
    operator_signer: OperatorKeySigner,
    intent_signer: IntentTradingKeySigner | None = None,
    *,
    base_url: str = "https://api.testnet.cantex.io",
    api_key_path: str | None = "secrets/api_key.txt",
    timeout: aiohttp.ClientTimeout | None = None,
    max_retries: int = 3,
    retry_base_delay: float = 1.0,
)
```

Use as an async context manager (`async with CantexSDK(...) as sdk`) or call `await sdk.close()` manually.

### Read Operations

| Method | Returns | Description |
| --- | --- | --- |
| `authenticate(*, force=False)` | `str` | Challenge-response auth; caches the API key to disk |
| `get_account_info()` | `AccountInfo` | Balances, pending transfers, expired allocations |
| `get_account_admin()` | `AccountAdmin` | Party address, instruments, account contract IDs |
| `get_pool_info()` | `PoolsInfo` | All available liquidity pools |
| `get_swap_quote(...)` | `SwapQuote` | Quote with prices, per-pool breakdown, and fees |

### Write Operations

| Method | Returns | Description |
| --- | --- | --- |
| `transfer(amount, instrument_id, instrument_admin, receiver, memo="")` | `dict` | Transfer tokens to another account |
| `batch_transfer(transfers, instrument_id, instrument_admin, memo="")` | `dict` | Transfer to multiple receivers in one transaction |
| `create_intent_trading_account()` | `dict` | Create an intent trading account |
| `swap(sell_amount, sell_instrument_id, sell_instrument_admin, buy_instrument_id, buy_instrument_admin)` | `dict` | Execute a swap via the intent-based trading flow |
| `swap_and_confirm(sell_amount, sell_instrument, buy_instrument, *, timeout=60.0)` | `SwapExecutedEvent` | Swap and wait for on-ledger confirmation via WebSocket |

`swap_and_confirm` connects to the private WebSocket *before* submitting, so the confirmation event is never missed. Raises `CantexError` on swap failure or `CantexTimeoutError` on timeout.

### WebSocket Streaming

| Method | Auth | Description |
| --- | --- | --- |
| `connect_public_ws()` | No | Public event stream |
| `connect_private_ws()` | Yes | Private event stream |

Both return an awaitable async-context-manager:

```python
async with sdk.connect_private_ws() as ws:
    async for event in ws:
        print(event.event_type, event.data)
```

`CantexWebSocket` handles ping/pong keep-alive and reconnects with exponential backoff on unexpected drops.

## Response Models

All models are frozen dataclasses (immutable). Fields are discoverable via IDE autocomplete.

### `AccountInfo`

| Field | Type | Description |
| --- | --- | --- |
| `address` | `str` | Canton party address |
| `user_id` | `str` | API user identity |
| `tokens` | `list[TokenBalance]` | Per-token balances and pending operations |

Helper: `get_balance(instrument_id, instrument_admin) -> Decimal`

### `AccountAdmin`

| Field | Type | Description |
| --- | --- | --- |
| `address` | `str` | Canton party address |
| `user_id` | `str` | API user identity |
| `instruments` | `list[InstrumentInfo]` | Registered instrument metadata |
| `has_intent_account` | `bool` | Whether an intent account exists |
| `has_trading_account` | `bool` | Whether a trading account exists |

### `SwapQuote`

| Field | Type | Description |
| --- | --- | --- |
| `sell_amount` / `sell_instrument` | `Decimal` / `InstrumentId` | Sell side |
| `returned_amount` | `Decimal` | Amount received after fees |
| `prices` | `QuotePrices` | Trade price, slippage, pool prices before/after |
| `fees` | `QuoteFees` | Admin, liquidity, and network fees |
| `pools` | `list[QuotePoolDetail]` | Per-pool breakdown |
| `estimated_time_seconds` | `Decimal` | Estimated execution time |

## WebSocket Events

All events are frozen dataclasses. Unknown types are returned as plain `WsEvent` instances.

### `WsEvent` (base)

Every event carries: `event_type`, `category`, `event_id`, `severity`, `source`, `user_id`, `wallet_address`, `created_at`, `data` (raw payload), and `raw` (original JSON dict).

### Trading Events

| Event | Key Fields |
| --- | --- |
| `SwapPendingEvent` | `swap_id`, `input_instrument`, `output_instrument`, `sender` |
| `SwapExecutedEvent` | `input_amount`, `input_instrument`, `output_amount`, `output_instrument`, `admin_fee_amount`, `liquidity_fee_amount`, `market`, `price` |
| `SwapFailedEvent` | `swap_id`, `input_instrument`, `output_instrument`, `sender`, `error` |

### Funding Events

All extend `FundingEvent` which adds: `amount`, `instrument`, `sender`, `receiver`, `ledger_created_at`.

| Event | Extra Fields |
| --- | --- |
| `DepositPendingEvent` | `execute_before`, `requested_at` |
| `DepositConfirmedEvent` | — |
| `DepositRejectedEvent` | — |
| `WithdrawalRequestedEvent` | `execute_before`, `requested_at` |
| `WithdrawalCompletedEvent` | — |
| `WithdrawalFailedEvent` | — |

## Error Handling

```text
CantexError
├── CantexAPIError          # Non-success HTTP status (has .status and .body)
│   └── CantexAuthError     # 401 / 403
└── CantexTimeoutError      # Request timed out
```

Transient errors (429, 502–504) and network failures are retried automatically with exponential backoff.

## Testing

```bash
pip install -e ".[dev]"
python -m pytest tests/ -v
```
