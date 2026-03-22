# Cantex SDK

An async Python SDK for the [Cantex](https://cantex.io) decentralised exchange API. It handles authentication, transaction signing, and provides typed response models for all API endpoints.

## License

MIT OR Apache-2.0  
See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).

at your option.

## Installation

The SDK requires Python 3.11+:

```bash
pip install .
```

For development (includes test dependencies):

```bash
pip install -e ".[dev]"
```

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

See [`examples/example.py`](examples/example.py) for a more complete walkthrough.

## Environment Variables

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `CANTEX_BASE_URL` | No | `https://api.testnet.cantex.io` | API base URL (mainnet: `https://api.cantex.io`) |
| `CANTEX_OPERATOR_KEY` | Yes | -- | Operator Ed25519 private key (hex) |
| `CANTEX_TRADING_KEY` | No | -- | Intent trading secp256k1 private key (hex). Required for swaps and intent operations. |

## SDK Reference

### Signers

Signers handle cryptographic key management and transaction signing. Both extend `BaseSigner`.

#### `OperatorKeySigner`

Signs authentication challenges using an Ed25519 private key.

| Constructor | Description |
| --- | --- |
| `from_hex(hex_string)` | From a hex-encoded private key string |
| `from_env(var_name)` | From an environment variable containing hex |
| `from_hex_file(path)` | From a file containing the key as hex |
| `from_pem_file(path)` | From a PEM file (validates Ed25519 key type) |
| `from_raw_file(path)` | From a file containing raw 32-byte key |
| `from_file(path, key_type="hex", *, prompt_if_missing=False)` | Unified loader (`key_type`: `"hex"`, `"pem"`, or `"raw"`) |

#### `IntentTradingKeySigner`

Signs intent transactions using a secp256k1 private key.

Supports the same constructors as `OperatorKeySigner`. The `from_pem_file` method validates that the PEM contains a secp256k1 key.

### Client

#### `CantexSDK`

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

| Parameter | Description |
| --- | --- |
| `operator_signer` | Required. Handles authentication signing. |
| `intent_signer` | Optional. Required for `swap()` and `create_intent_trading_account()`. |
| `base_url` | API endpoint. Trailing slashes are stripped automatically. |
| `api_key_path` | Path to cache the API key on disk. Set to `None` to disable caching. |
| `timeout` | Custom `aiohttp.ClientTimeout`. Defaults to 30s total, 10s connect, 30s read. |
| `max_retries` | Number of retries for transient errors (429, 502, 503, 504) and network failures. |
| `retry_base_delay` | Base delay in seconds for exponential backoff between retries. |

Use as an async context manager to ensure the HTTP session is closed:

```python
async with CantexSDK(operator) as sdk:
    await sdk.authenticate()
    # ... use the sdk ...
```

Or manage the lifecycle manually:

```python
sdk = CantexSDK(operator)
try:
    await sdk.authenticate()
    # ...
finally:
    await sdk.close()
```

### Read Operations

#### `authenticate(*, force=False) -> str`

Performs challenge-response authentication using the operator key. Returns the API key. Caches the key to disk (if `api_key_path` is set) and reuses it on subsequent calls unless `force=True`.

#### `get_account_info() -> AccountInfo`

Returns account balances, pending transfers, and expired allocations for all tokens.

#### `get_account_admin() -> AccountAdmin`

Returns administrative account details: party address, registered instruments, and contract IDs for trading/intent accounts.

#### `get_pool_info() -> PoolsInfo`

Returns all available liquidity pools.

#### `get_swap_quote(...) -> SwapQuote`

```python
await sdk.get_swap_quote(
    sell_amount=Decimal("1"),
    sell_instrument_id="Amulet",
    sell_instrument_admin="DSO::1220...",
    buy_instrument_id="USDCx",
    buy_instrument_admin="usdc-rep::1220...",
)
```

Returns a detailed quote including prices, per-pool breakdown, fee details, and estimated execution time.

### Write Operations

#### `transfer(amount, instrument_id, instrument_admin, receiver, memo="") -> dict`

Transfer tokens to another account.

#### `batch_transfer(transfers, instrument_id, instrument_admin, memo="") -> dict`

Transfer tokens to multiple receivers in a single transaction. Each item in `transfers` must have `receiver` and `amount` keys:

```python
await sdk.batch_transfer(
    [
        {"receiver": "Cantex::1220aaa...", "amount": Decimal("10")},
        {"receiver": "Cantex::1220bbb...", "amount": Decimal("20")},
    ],
    instrument_id="Amulet",
    instrument_admin="DSO::1220...",
)
```

#### `create_intent_trading_account() -> dict`

Create an intent trading account. Requires an `IntentTradingKeySigner`. Raises `RuntimeError` if one already exists.

#### `swap(sell_amount, sell_instrument_id, sell_instrument_admin, buy_instrument_id, buy_instrument_admin) -> dict`

Execute a token swap via the intent-based trading flow. Requires an `IntentTradingKeySigner`.

## Response Models

All response models are frozen dataclasses (immutable after creation).

### `AccountInfo`

Returned by `get_account_info()`.

| Field | Type | Description |
| --- | --- | --- |
| `address` | `str` | Party's Canton address |
| `user_id` | `str` | API user identity |
| `tokens` | `list[TokenBalance]` | Per-token balances and pending operations |

| Method / Property | Returns | Description |
| --- | --- | --- |
| `get_balance(instrument_id, instrument_admin)` | `Decimal` | Unlocked balance for a token, or `Decimal(0)` |
| `expired_transfer_cids` | `list[str]` | All pending-withdraw contract IDs across tokens |
| `expired_allocation_cids` | `list[str]` | All expired allocation contract IDs across tokens |

### `TokenBalance`

One entry per token inside `AccountInfo.tokens`.

| Field | Type | Description |
| --- | --- | --- |
| `instrument_id` | `str` | Token identifier (e.g. `"Amulet"`) |
| `instrument_admin` | `str` | Admin party for the token |
| `instrument_name` | `str` | Human-readable name (e.g. `"Canton Coin"`) |
| `instrument_symbol` | `str` | Ticker symbol (e.g. `"CC"`) |
| `unlocked_amount` | `Decimal` | Available balance |
| `locked_amount` | `Decimal` | Reserved/locked balance |
| `pending_deposit_transfer_cids` | `list[str]` | Contract IDs of pending deposits |
| `pending_withdraw_transfer_cids` | `list[str]` | Contract IDs of pending withdrawals |
| `expired_allocation_cids` | `list[str]` | Contract IDs of expired allocations |

### `AccountAdmin`

Returned by `get_account_admin()`.

| Field | Type | Description |
| --- | --- | --- |
| `address` | `str` | Party's Canton address |
| `user_id` | `str` | API user identity |
| `instruments` | `list[InstrumentInfo]` | Registered instrument metadata |
| `intent_account` | `dict \| None` | Intent account contract details, or `None` |
| `trading_account` | `dict \| None` | Trading account contract details, or `None` |
| `has_intent_account` | `bool` (property) | Whether an intent account exists |
| `has_trading_account` | `bool` (property) | Whether a trading account exists |

### `InstrumentInfo`

One entry per instrument inside `AccountAdmin.instruments`.

| Field | Type | Description |
| --- | --- | --- |
| `instrument_id` | `str` | Token identifier |
| `instrument_admin` | `str` | Admin party |
| `instrument_name` | `str` | Human-readable name |
| `instrument_symbol` | `str` | Ticker symbol |

### `PoolsInfo`

Returned by `get_pool_info()`.

| Field | Type | Description |
| --- | --- | --- |
| `pools` | `list[Pool]` | All available pools |

| Method | Returns | Description |
| --- | --- | --- |
| `get_pool(contract_id)` | `Pool` | Find a pool by contract ID. Raises `ValueError` if not found. |

### `Pool`

One entry per pool inside `PoolsInfo.pools`.

| Field | Type | Description |
| --- | --- | --- |
| `contract_id` | `str` | Pool contract identifier |
| `token_a_instrument_id` | `str` | First token's instrument ID |
| `token_a_instrument_admin` | `str` | First token's admin |
| `token_b_instrument_id` | `str` | Second token's instrument ID |
| `token_b_instrument_admin` | `str` | Second token's admin |

### `SwapQuote`

Returned by `get_swap_quote()`.

| Field | Type | Description |
| --- | --- | --- |
| `estimated_time_seconds` | `Decimal` | Estimated execution time |
| `returned` | `QuoteLeg` | Amount and instrument being returned |
| `pool_size` | `QuoteLeg` | Current pool size |
| `fees` | `QuoteFees` | Aggregate fee breakdown |
| `prices` | `QuotePrices` | Aggregate price breakdown |
| `pools` | `list[QuotePoolDetail]` | Per-pool breakdown (one entry per pool in the route) |
| `sell_amount` | `Decimal` | Amount being sold |
| `sell_instrument` | `InstrumentId` | Sell instrument |
| `buy_instrument` | `InstrumentId` | Buy instrument |
| `returned_amount` | `Decimal` (property) | Shortcut for `returned.amount` |

**Deprecated fields** (still functional, emit `DeprecationWarning`):

| Deprecated Field | Use Instead |
| --- | --- |
| `trade_price` | `prices.trade` |
| `slippage` | `prices.slippage` |
| `pool_price_before_trade` | `prices.pool_before` |
| `pool_price_after_trade` | `prices.pool_after` |

### `QuotePrices`

Price breakdown used at both the top level (`SwapQuote.prices`) and per-pool level (`QuotePoolDetail.prices`).

| Field | Type | Description |
| --- | --- | --- |
| `pool_after` | `Decimal` | Pool price after the trade |
| `pool_before` | `Decimal` | Pool price before the trade |
| `slippage` | `Decimal` | Estimated slippage |
| `trade` | `Decimal` | Effective trade price |
| `trade_no_fees` | `Decimal` | Trade price excluding fees |

### `QuotePoolDetail`

One entry per pool in the swap route, inside `SwapQuote.pools`.

| Field | Type | Description |
| --- | --- | --- |
| `buy` | `QuoteLeg` | Amount and instrument bought from this pool |
| `sell` | `QuoteLeg` | Amount and instrument sold into this pool |
| `contract_id` | `str` | Pool contract identifier |
| `fees` | `QuotePoolFees` | Per-pool fee breakdown |
| `pool_id` | `str` | Pool identifier |
| `pool_price_after` | `Decimal` | Pool price after the trade |
| `pool_price_before` | `Decimal` | Pool price before the trade |
| `prices` | `QuotePrices` | Per-pool price breakdown |
| `size` | `QuoteLeg` | Current pool size |
| `trade_price` | `Decimal` | Effective trade price for this pool |
| `trade_price_no_fees` | `Decimal` | Trade price excluding fees for this pool |

### `QuotePoolFees`

Per-pool fee breakdown inside `QuotePoolDetail.fees`.

| Field | Type | Description |
| --- | --- | --- |
| `admin` | `QuoteLeg` | Admin fee (amount + instrument) |
| `fee_percentage` | `Decimal` | Fee as a decimal fraction |
| `liquidity` | `QuoteLeg` | Liquidity provider fee (amount + instrument) |

### `QuoteFees`

Aggregate fee breakdown inside `SwapQuote.fees`.

| Field | Type | Description |
| --- | --- | --- |
| `fee_percentage` | `Decimal` | Total fee as a decimal fraction |
| `amount_admin` | `Decimal` | Admin fee amount |
| `amount_liquidity` | `Decimal` | Liquidity provider fee amount |
| `instrument` | `InstrumentId` | Fee instrument |
| `network_fee` | `QuoteLeg` | Network fee (amount + instrument) |

### `QuoteLeg`

Reusable amount + instrument pair used throughout the quote models.

| Field | Type | Description |
| --- | --- | --- |
| `amount` | `Decimal` | The amount |
| `instrument` | `InstrumentId` | Instrument identifier |

## Error Handling

All SDK exceptions inherit from `CantexError`:

```text
CantexError
├── CantexAPIError          # Non-success HTTP status (has .status and .body)
│   └── CantexAuthError     # 401 / 403 authentication failures
└── CantexTimeoutError      # Request timed out
```

Usage:

```python
from cantex_sdk import CantexAPIError, CantexAuthError, CantexTimeoutError

try:
    result = await sdk.swap(...)
except CantexAuthError as e:
    print(f"Auth failed (HTTP {e.status}): {e.body}")
except CantexAPIError as e:
    print(f"API error (HTTP {e.status}): {e.body}")
except CantexTimeoutError:
    print("Request timed out -- try again")
```

Transient errors (HTTP 429, 502, 503, 504) and network failures are automatically retried with exponential backoff (configurable via `max_retries` and `retry_base_delay`).

## Example

The [`examples/example.py`](examples/example.py) script demonstrates the full SDK workflow:

1. Load keys from environment variables
2. Authenticate
3. Query account admin and balances
4. List pools
5. Get a swap quote with prices, per-pool breakdown, and fee inspection
6. Error handling patterns

Run it with:

```bash
export CANTEX_OPERATOR_KEY="your_operator_key_hex"
export CANTEX_TRADING_KEY="your_intent_key_hex"      # optional
export CANTEX_BASE_URL="https://api.testnet.cantex.io"  # optional

python examples/example.py
```

## Testing

The test suite uses `pytest` with `pytest-asyncio` and `aioresponses` for HTTP mocking:

```bash
pip install -e ".[dev]"

python -m pytest tests/ -v
```
