# Copyright (c) 2026 CaviarNine
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import asyncio
import base64
import getpass
import json
import logging
import os
import warnings
from abc import ABC, abstractmethod
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Awaitable, Callable, TypedDict

import aiohttp
import ecdsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ecdsa import SECP256k1
from ecdsa.util import sigencode_der

logger = logging.getLogger(__name__)

__all__ = [
    "CantexError",
    "CantexAPIError",
    "CantexAuthError",
    "CantexTimeoutError",
    "InstrumentId",
    "TokenBalance",
    "AccountInfo",
    "InstrumentInfo",
    "AccountAdmin",
    "Pool",
    "PoolsInfo",
    "QuoteLeg",
    "QuotePrices",
    "QuotePoolFees",
    "QuotePoolDetail",
    "QuoteFees",
    "SwapQuote",
    "TransferItem",
    "WsEvent",
    "SwapPendingEvent",
    "SwapFailedEvent",
    "SwapExecutedEvent",
    "FundingEvent",
    "DepositPendingEvent",
    "DepositConfirmedEvent",
    "DepositRejectedEvent",
    "WithdrawalRequestedEvent",
    "WithdrawalCompletedEvent",
    "WithdrawalFailedEvent",
    "BaseSigner",
    "OperatorKeySigner",
    "IntentTradingKeySigner",
    "CantexWebSocket",
    "CantexSDK",
]


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class CantexError(Exception):
    """Base exception for all Cantex SDK errors."""


class CantexAPIError(CantexError):
    """Raised when the API returns a non-success HTTP status."""

    def __init__(self, status: int, body: str, message: str = "") -> None:
        self.status = status
        self.body = body
        super().__init__(message or f"API error {status}: {body[:200]}")


class CantexAuthError(CantexAPIError):
    """Raised on authentication failures (401/403)."""


class CantexTimeoutError(CantexError):
    """Raised when an API request times out."""


# ---------------------------------------------------------------------------
# Type definitions
# ---------------------------------------------------------------------------


class TransferItem(TypedDict):
    """Shape of each item in the *transfers* list for ``batch_transfer``."""

    receiver: str
    amount: Decimal


@dataclass(frozen=True)
class InstrumentId:
    """Unique identifier for a Canton instrument (token), combining the
    instrument ID and its admin party."""

    admin: str
    id: str

    def __str__(self) -> str:
        return f"{self.id} (admin={self.admin})"


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TokenBalance:
    """A single token's balance and pending operations from account info."""

    instrument: InstrumentId
    instrument_name: str
    instrument_symbol: str
    unlocked_amount: Decimal
    locked_amount: Decimal
    pending_deposit_transfer_cids: list[str]
    pending_withdraw_transfer_cids: list[str]
    expired_allocation_cids: list[str]

    @classmethod
    def _from_raw(cls, data: dict) -> TokenBalance:
        balances = data.get("balances", {})
        return cls(
            instrument=InstrumentId(
                id=data["instrument_id"],
                admin=data["instrument_admin"],
            ),
            instrument_name=data.get("instrument_name", ""),
            instrument_symbol=data.get("instrument_symbol", ""),
            unlocked_amount=Decimal(balances.get("unlocked_amount", "0")),
            locked_amount=Decimal(balances.get("locked_amount", "0")),
            pending_deposit_transfer_cids=[
                t["contract_id"]
                for t in data.get("pending_deposit_transfers", [])
            ],
            pending_withdraw_transfer_cids=[
                t["contract_id"]
                for t in data.get("pending_withdraw_transfers", [])
            ],
            expired_allocation_cids=[
                a["contract_id"]
                for a in data.get("expired_allocations", [])
            ],
        )


@dataclass(frozen=True)
class AccountInfo:
    """Parsed response from ``GET /v1/account/info``."""

    address: str
    user_id: str
    tokens: list[TokenBalance]

    def get_balance(self, instrument: InstrumentId) -> Decimal:
        """Return the unlocked balance for a specific token, or zero."""
        for token in self.tokens:
            if token.instrument == instrument:
                return token.unlocked_amount
        return Decimal(0)

    @property
    def expired_transfer_cids(self) -> list[str]:
        """All pending-withdraw transfer contract IDs across every token."""
        return [
            cid
            for token in self.tokens
            for cid in token.pending_withdraw_transfer_cids
        ]

    @property
    def expired_allocation_cids(self) -> list[str]:
        """All expired allocation contract IDs across every token."""
        return [
            cid
            for token in self.tokens
            for cid in token.expired_allocation_cids
        ]

    @classmethod
    def _from_raw(cls, data: dict) -> AccountInfo:
        party_id = data.get("party_id", {})
        return cls(
            address=party_id.get("address", ""),
            user_id=data.get("user_id", ""),
            tokens=[TokenBalance._from_raw(t) for t in data["tokens"]],
        )


@dataclass(frozen=True)
class InstrumentInfo:
    """Metadata for a registered instrument (token) from account admin."""

    instrument: InstrumentId
    instrument_name: str
    instrument_symbol: str

    @classmethod
    def _from_raw(cls, data: dict) -> InstrumentInfo:
        return cls(
            instrument=InstrumentId(
                id=data["instrument_id"],
                admin=data["instrument_admin"],
            ),
            instrument_name=data["instrument_name"],
            instrument_symbol=data["instrument_symbol"],
        )


@dataclass(frozen=True)
class AccountAdmin:
    """Parsed response from ``GET /v1/account/admin``."""

    address: str
    user_id: str
    instruments: list[InstrumentInfo]
    intent_account: dict | None
    trading_account: dict | None

    @property
    def has_intent_account(self) -> bool:
        return self.intent_account is not None

    @property
    def has_trading_account(self) -> bool:
        return self.trading_account is not None

    @classmethod
    def _from_raw(cls, data: dict) -> AccountAdmin:
        party_id = data.get("party_id", {})
        contracts = party_id.get("contracts", {})
        return cls(
            address=party_id.get("address", ""),
            user_id=data.get("user_id", ""),
            instruments=[
                InstrumentInfo._from_raw(t) for t in data.get("tokens", [])
            ],
            intent_account=contracts.get("pool_intent_account"),
            trading_account=contracts.get("pool_trading_account"),
        )


@dataclass(frozen=True)
class Pool:
    """A single liquidity pool from the pools info response."""

    contract_id: str
    token_a: InstrumentId
    token_b: InstrumentId

    @classmethod
    def _from_raw(cls, data: dict) -> Pool:
        return cls(
            contract_id=data["contract_id"],
            token_a=InstrumentId(
                id=data["token_a_instrument_id"],
                admin=data["token_a_instrument_admin"],
            ),
            token_b=InstrumentId(
                id=data["token_b_instrument_id"],
                admin=data["token_b_instrument_admin"],
            ),
        )


@dataclass(frozen=True)
class PoolsInfo:
    """Parsed response from ``GET /v2/pools/info``."""

    pools: list[Pool]

    def get_pool(self, contract_id: str) -> Pool:
        """Find a pool by contract ID, or raise ``ValueError``."""
        for pool in self.pools:
            if pool.contract_id == contract_id:
                return pool
        raise ValueError(f"Pool with contract_id {contract_id!r} not found")

    @classmethod
    def _from_raw(cls, data: dict) -> PoolsInfo:
        return cls(
            pools=[Pool._from_raw(p) for p in data["pools"]],
        )


@dataclass(frozen=True)
class QuoteLeg:
    """An amount + instrument pair within a swap quote."""

    amount: Decimal
    instrument: InstrumentId

    @classmethod
    def _from_raw(cls, data: dict) -> QuoteLeg:
        return cls(
            amount=Decimal(data["amount"]),
            instrument=InstrumentId(
                id=data["instrument_id"],
                admin=data["instrument_admin"],
            ),
        )


@dataclass(frozen=True)
class QuotePrices:
    """Price breakdown used at both the top level and per-pool level."""

    pool_after: Decimal
    pool_before: Decimal
    slippage: Decimal
    trade: Decimal
    trade_no_fees: Decimal

    @classmethod
    def _from_raw(cls, data: dict) -> QuotePrices:
        return cls(
            pool_after=Decimal(data["pool_after"]),
            pool_before=Decimal(data["pool_before"]),
            slippage=Decimal(data["slippage"]),
            trade=Decimal(data["trade"]),
            trade_no_fees=Decimal(data["trade_no_fees"]),
        )


@dataclass(frozen=True)
class QuotePoolFees:
    """Per-pool fee breakdown within a swap quote."""

    admin: QuoteLeg
    fee_percentage: Decimal
    liquidity: QuoteLeg

    @classmethod
    def _from_raw(cls, data: dict) -> QuotePoolFees:
        return cls(
            admin=QuoteLeg._from_raw(data["admin"]),
            fee_percentage=Decimal(data["fee_percentage"]),
            liquidity=QuoteLeg._from_raw(data["liquidity"]),
        )


@dataclass(frozen=True)
class QuotePoolDetail:
    """A single pool's contribution to a multi-pool swap quote."""

    buy: QuoteLeg
    sell: QuoteLeg
    contract_id: str
    fees: QuotePoolFees
    pool_id: str
    pool_price_after: Decimal
    pool_price_before: Decimal
    prices: QuotePrices
    size: QuoteLeg
    trade_price: Decimal
    trade_price_no_fees: Decimal

    @classmethod
    def _from_raw(cls, data: dict) -> QuotePoolDetail:
        return cls(
            buy=QuoteLeg._from_raw(data["buy"]),
            sell=QuoteLeg._from_raw(data["sell"]),
            contract_id=data["contract_id"],
            fees=QuotePoolFees._from_raw(data["fees"]),
            pool_id=data["pool_id"],
            pool_price_after=Decimal(data["pool_price_after"]),
            pool_price_before=Decimal(data["pool_price_before"]),
            prices=QuotePrices._from_raw(data["prices"]),
            size=QuoteLeg._from_raw(data["size"]),
            trade_price=Decimal(data["trade_price"]),
            trade_price_no_fees=Decimal(data["trade_price_no_fees"]),
        )


@dataclass(frozen=True)
class QuoteFees:
    """Fee breakdown for a swap quote."""

    fee_percentage: Decimal
    amount_admin: Decimal
    amount_liquidity: Decimal
    instrument: InstrumentId
    network_fee: QuoteLeg

    @classmethod
    def _from_raw(cls, data: dict) -> QuoteFees:
        return cls(
            fee_percentage=Decimal(data["fee_percentage"]),
            amount_admin=Decimal(data["amount_admin"]),
            amount_liquidity=Decimal(data["amount_liquidity"]),
            instrument=InstrumentId(
                id=data["instrument_id"],
                admin=data["instrument_admin"],
            ),
            network_fee=QuoteLeg._from_raw(data["network_fee"]),
        )


@dataclass(frozen=True)
class SwapQuote:
    """Parsed response from ``POST /v2/pools/quote``."""

    _trade_price: Decimal
    _slippage: Decimal
    estimated_time_seconds: Decimal
    _pool_price_before_trade: Decimal
    _pool_price_after_trade: Decimal
    returned: QuoteLeg
    pool_size: QuoteLeg
    fees: QuoteFees
    prices: QuotePrices
    pools: list[QuotePoolDetail]
    sell_amount: Decimal
    sell_instrument: InstrumentId
    buy_instrument: InstrumentId

    @property
    def trade_price(self) -> Decimal:
        """.. deprecated:: Use ``prices.trade`` instead."""
        warnings.warn(
            "SwapQuote.trade_price is deprecated, use SwapQuote.prices.trade",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._trade_price

    @property
    def slippage(self) -> Decimal:
        """.. deprecated:: Use ``prices.slippage`` instead."""
        warnings.warn(
            "SwapQuote.slippage is deprecated, use SwapQuote.prices.slippage",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._slippage

    @property
    def pool_price_before_trade(self) -> Decimal:
        """.. deprecated:: Use ``prices.pool_before`` instead."""
        warnings.warn(
            "SwapQuote.pool_price_before_trade is deprecated, "
            "use SwapQuote.prices.pool_before",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._pool_price_before_trade

    @property
    def pool_price_after_trade(self) -> Decimal:
        """.. deprecated:: Use ``prices.pool_after`` instead."""
        warnings.warn(
            "SwapQuote.pool_price_after_trade is deprecated, "
            "use SwapQuote.prices.pool_after",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._pool_price_after_trade

    @property
    def returned_amount(self) -> Decimal:
        return self.returned.amount

    @classmethod
    def _from_raw(cls, data: dict) -> SwapQuote:
        sent = data["sent"]
        return cls(
            _trade_price=Decimal(data["trade_price"]),
            _slippage=Decimal(data["slippage"]),
            estimated_time_seconds=Decimal(data["estimated_time_seconds"]),
            _pool_price_before_trade=Decimal(data["pool_price_before_trade"]),
            _pool_price_after_trade=Decimal(data["pool_price_after_trade"]),
            returned=QuoteLeg._from_raw(data["returned"]),
            pool_size=QuoteLeg._from_raw(data["pool_size"]),
            fees=QuoteFees._from_raw(data["fees"]),
            prices=QuotePrices._from_raw(data["prices"]),
            pools=[QuotePoolDetail._from_raw(p) for p in data["pools"]],
            sell_amount=Decimal(sent["sell_amount"]),
            sell_instrument=InstrumentId(
                id=sent["sell_instrument_id"],
                admin=sent["sell_instrument_admin"],
            ),
            buy_instrument=InstrumentId(
                id=sent["buy_instrument_id"],
                admin=sent["buy_instrument_admin"],
            ),
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _b64_encode(data: bytes) -> str:
    """URL-safe base64-encode without padding."""
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


# ---------------------------------------------------------------------------
# Signer hierarchy
# ---------------------------------------------------------------------------


class BaseSigner(ABC):
    """Common interface and key-loading infrastructure for Cantex signers.

    Subclasses only need to implement three hooks:

    * ``_from_key_bytes``  -- raw 32-byte private key  ->  signer
    * ``from_pem_file``    -- PEM file  ->  signer  (crypto-library specific)
    * ``_to_pem``          -- raw bytes ->  PEM data (for persist-on-prompt)

    Everything else (hex, env, hex-file, raw-file, interactive prompt, and
    the unified ``from_file`` loader) is handled here once.
    """

    # -- abstract contract ---------------------------------------------------

    @abstractmethod
    def sign(self, data: bytes) -> bytes:
        """Sign *data* and return the raw signature bytes."""
        ...

    @abstractmethod
    def get_public_key_hex(self) -> str:
        """Return the public key as a hex string."""
        ...

    @classmethod
    @abstractmethod
    def _from_key_bytes(cls, key_bytes: bytes) -> BaseSigner:
        """Construct a signer from raw private-key bytes (32 bytes)."""
        ...

    @classmethod
    def from_pem_file(cls, path: str) -> BaseSigner:
        """Load from a PEM file.  Override per-subclass."""
        raise NotImplementedError(f"{cls.__name__} does not support PEM format")

    @classmethod
    def _to_pem(cls, key_bytes: bytes) -> bytes:
        """Serialize raw key bytes to PEM.  Override per-subclass."""
        raise NotImplementedError(f"{cls.__name__} does not support PEM serialization")

    # -- shared helpers ------------------------------------------------------

    @staticmethod
    def _clean_hex(hex_string: str) -> bytes:
        """Strip ``0x`` prefix and whitespace, then decode hex to bytes."""
        return bytes.fromhex(hex_string.removeprefix("0x").strip())

    # -- shared loading classmethods -----------------------------------------

    @classmethod
    def from_hex(cls, hex_string: str) -> BaseSigner:
        """Construct from a hex-encoded private key string."""
        return cls._from_key_bytes(cls._clean_hex(hex_string))

    @classmethod
    def from_env(cls, var_name: str) -> BaseSigner:
        """Load from an environment variable containing the key as hex."""
        value = os.getenv(var_name)
        if value is None:
            raise ValueError(f"Environment variable '{var_name}' is not set.")
        return cls.from_hex(value)

    @classmethod
    def from_hex_file(cls, path: str) -> BaseSigner:
        """Load from a file containing the key as a hex string."""
        with open(path, "rb") as fh:
            return cls.from_hex(fh.read().decode("utf-8"))

    @classmethod
    def from_raw_file(cls, path: str) -> BaseSigner:
        """Load from a file containing raw key bytes."""
        with open(path, "rb") as fh:
            return cls._from_key_bytes(fh.read())

    @classmethod
    def from_file(
        cls,
        path: str,
        key_type: str = "hex",
        *,
        prompt_if_missing: bool = False,
    ) -> BaseSigner:
        """Unified file loader.

        *key_type* is one of ``"pem"``, ``"hex"``, or ``"raw"``.

        When *prompt_if_missing* is ``True`` and the file does not exist,
        the user is prompted for the private key hex, which is then persisted
        to *path* in the requested format.

        .. warning::
            The interactive prompt uses ``getpass.getpass()`` which blocks the
            thread.  Avoid *prompt_if_missing* in async or headless contexts.
        """
        loaders = {
            "pem": cls.from_pem_file,
            "hex": cls.from_hex_file,
            "raw": cls.from_raw_file,
        }
        if key_type not in loaders:
            raise ValueError(f"Unsupported key_type: '{key_type}'")

        if os.path.exists(path):
            return loaders[key_type](path)

        if not prompt_if_missing:
            raise FileNotFoundError(f"Private key not found at '{path}'.")

        logger.warning("Private key not found at '%s'.", path)
        raw_key_hex = getpass.getpass("Paste your private key hex: ")
        key_bytes = bytes.fromhex(raw_key_hex)

        if key_type == "hex":
            key_data = raw_key_hex.encode("utf-8")
        elif key_type == "raw":
            key_data = key_bytes
        else:
            key_data = cls._to_pem(key_bytes)

        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(key_data)
        os.chmod(path, 0o600)
        logger.info("Private key saved to '%s'.", path)
        return cls._from_key_bytes(key_bytes)


class OperatorKeySigner(BaseSigner):
    """Ed25519 signer for operator-key operations.

    Used for API challenge-response authentication and for signing ledger
    transaction hashes before submission.
    """

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key

    def __repr__(self) -> str:
        return f"OperatorKeySigner(pub={self.get_public_key_hex()[:16]}...)"

    # -- hooks required by BaseSigner ----------------------------------------

    @classmethod
    def _from_key_bytes(cls, key_bytes: bytes) -> OperatorKeySigner:
        return cls(Ed25519PrivateKey.from_private_bytes(key_bytes))

    @classmethod
    def from_pem_file(cls, path: str) -> OperatorKeySigner:
        """Load an Ed25519 private key from a PEM file.

        Raises ``ValueError`` if the PEM contains a non-Ed25519 key.
        """
        with open(path, "rb") as fh:
            private_key = serialization.load_pem_private_key(fh.read(), password=None)
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ValueError(
                f"PEM at '{path}' must contain an Ed25519 key, "
                f"got {type(private_key).__name__}"
            )
        return cls(private_key)

    @classmethod
    def _to_pem(cls, key_bytes: bytes) -> bytes:
        pk = Ed25519PrivateKey.from_private_bytes(key_bytes)
        return pk.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    # -- signing & public key ------------------------------------------------

    def sign(self, data: bytes) -> bytes:
        return self._private_key.sign(data)

    def get_public_key_hex(self) -> str:
        return (
            self._private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            .hex()
        )

    def get_public_key_b64(self) -> str:
        """URL-safe base64-encoded public key (used for API authentication)."""
        return _b64_encode(
            self._private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        )


class IntentTradingKeySigner(BaseSigner):
    """secp256k1 ECDSA signer for intent-based trading operations.

    Signs pre-hashed 32-byte digests and returns DER-encoded signatures.
    """

    # SPKI (SubjectPublicKeyInfo) DER prefix for secp256k1 uncompressed keys.
    # ASN.1: SEQUENCE { SEQUENCE { OID ecPublicKey, OID secp256k1 }, BIT STRING }
    _SPKI_PREFIX = bytes([
        0x30, 0x56, 0x30, 0x10, 0x06, 0x07, 0x2A, 0x86,
        0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x05, 0x2B,
        0x81, 0x04, 0x00, 0x0A, 0x03, 0x42, 0x00,
    ])

    def __init__(self, private_key: ecdsa.SigningKey) -> None:
        self._private_key = private_key

    def __repr__(self) -> str:
        return f"IntentTradingKeySigner(pub={self.get_public_key_hex()[:16]}...)"

    # -- hooks required by BaseSigner ----------------------------------------

    @classmethod
    def _from_key_bytes(cls, key_bytes: bytes) -> IntentTradingKeySigner:
        if len(key_bytes) != 32:
            raise ValueError("secp256k1 private key must be 32 bytes (64 hex chars)")
        return cls(ecdsa.SigningKey.from_string(key_bytes, curve=SECP256k1))

    @classmethod
    def from_pem_file(cls, path: str) -> IntentTradingKeySigner:
        """Load a secp256k1 private key from a PEM file.

        Raises ``ValueError`` if the PEM contains a non-secp256k1 key.
        """
        with open(path, "rb") as fh:
            sk = ecdsa.SigningKey.from_pem(fh.read())
        if sk.curve != SECP256k1:
            raise ValueError(
                f"PEM at '{path}' must contain a secp256k1 key, "
                f"got {sk.curve.name}"
            )
        return cls(sk)

    @classmethod
    def _to_pem(cls, key_bytes: bytes) -> bytes:
        sk = ecdsa.SigningKey.from_string(key_bytes, curve=SECP256k1)
        return sk.to_pem()

    # -- signing & public key ------------------------------------------------

    def sign(self, data: bytes) -> bytes:
        """Sign a pre-hashed 32-byte digest, returning DER-encoded bytes."""
        if len(data) != 32:
            raise ValueError("Digest must be exactly 32 bytes")
        return self._private_key.sign_digest(data, sigencode=sigencode_der)

    def sign_digest_hex(self, digest_hex: str) -> str:
        """Convenience: hex digest in, hex DER signature out."""
        return self.sign(self._clean_hex(digest_hex)).hex()

    def get_public_key_hex(self) -> str:
        """Uncompressed public key (``04 || x || y``) as hex."""
        vk = self._private_key.get_verifying_key()
        return "04" + vk.to_string().hex()

    def get_public_key_hex_der(self) -> str:
        """SPKI DER-wrapped uncompressed public key as hex (88 bytes / 176 hex chars).

        Same format as ``intentTradingPublicKeyHex`` sent to ``create_intent_account``.
        """
        vk = self._private_key.get_verifying_key()
        pub_uncompressed = b"\x04" + vk.to_string()
        spki = self._SPKI_PREFIX + pub_uncompressed
        return spki.hex()


# ---------------------------------------------------------------------------
# WebSocket event models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WsEvent:
    """Base class for all parsed WebSocket events.

    Unknown event types are returned as plain ``WsEvent`` instances with
    the type-specific payload available via :attr:`data`.
    """

    event_type: str
    category: str
    event_id: str
    severity: str
    source: str
    user_id: str
    wallet_address: str
    created_at: str
    data: dict
    raw: dict

    @classmethod
    def _from_raw(cls, raw: dict) -> WsEvent:
        return cls(
            event_type=raw.get("type", ""),
            category=raw.get("category", ""),
            event_id=raw.get("event_id", ""),
            severity=raw.get("severity", ""),
            source=raw.get("source", ""),
            user_id=raw.get("user_id", ""),
            wallet_address=raw.get("wallet_address", ""),
            created_at=raw.get("created_at", ""),
            data=raw.get("data", {}),
            raw=raw,
        )


@dataclass(frozen=True)
class SwapPendingEvent(WsEvent):
    """A swap has been submitted and is pending execution."""

    swap_id: str
    input_instrument: InstrumentId
    output_instrument: InstrumentId
    sender: str

    @classmethod
    def _from_raw(cls, raw: dict) -> SwapPendingEvent:
        d = raw.get("data", {})
        return cls(
            **WsEvent._from_raw(raw).__dict__,
            swap_id=d.get("id", ""),
            input_instrument=InstrumentId(
                id=d.get("input_instrument_id", {}).get("id", ""),
                admin=d.get("input_instrument_id", {}).get("admin", ""),
            ),
            output_instrument=InstrumentId(
                id=d.get("output_instrument_id", {}).get("id", ""),
                admin=d.get("output_instrument_id", {}).get("admin", ""),
            ),
            sender=d.get("sender", ""),
        )


@dataclass(frozen=True)
class SwapFailedEvent(WsEvent):
    """A swap failed to execute."""

    swap_id: str
    input_instrument: InstrumentId
    output_instrument: InstrumentId
    sender: str
    error: str

    @classmethod
    def _from_raw(cls, raw: dict) -> SwapFailedEvent:
        d = raw.get("data", {})
        details = d.get("details", {})
        return cls(
            **WsEvent._from_raw(raw).__dict__,
            swap_id=d.get("id", ""),
            input_instrument=InstrumentId(
                id=d.get("input_instrument_id", {}).get("id", ""),
                admin=d.get("input_instrument_id", {}).get("admin", ""),
            ),
            output_instrument=InstrumentId(
                id=d.get("output_instrument_id", {}).get("id", ""),
                admin=d.get("output_instrument_id", {}).get("admin", ""),
            ),
            sender=d.get("sender", ""),
            error=details.get("error", ""),
        )


@dataclass(frozen=True)
class SwapExecutedEvent(WsEvent):
    """A swap was successfully executed (trade confirmation)."""

    input_amount: Decimal
    input_instrument: InstrumentId
    output_amount: Decimal
    output_instrument: InstrumentId
    admin_fee_amount: Decimal
    liquidity_fee_amount: Decimal
    market: str
    price: Decimal
    ticker_ts: int
    ledger_created_at: str

    @classmethod
    def _from_raw(cls, raw: dict) -> SwapExecutedEvent:
        d = raw.get("data", {})
        sd = d.get("swap_details", {})
        tk = d.get("ticker", {})
        return cls(
            **WsEvent._from_raw(raw).__dict__,
            input_amount=Decimal(sd.get("input_amount", "0")),
            input_instrument=InstrumentId(
                id=sd.get("input_instrument_id", {}).get("id", ""),
                admin=sd.get("input_instrument_id", {}).get("admin", ""),
            ),
            output_amount=Decimal(sd.get("output_amount", "0")),
            output_instrument=InstrumentId(
                id=sd.get("output_instrument_id", {}).get("id", ""),
                admin=sd.get("output_instrument_id", {}).get("admin", ""),
            ),
            admin_fee_amount=Decimal(sd.get("admin_fee_amount", "0")),
            liquidity_fee_amount=Decimal(sd.get("liquidity_fee_amount", "0")),
            market=tk.get("market", ""),
            price=Decimal(tk.get("price", "0")),
            ticker_ts=tk.get("ts", 0),
            ledger_created_at=d.get("ledger_created_at", ""),
        )


@dataclass(frozen=True)
class FundingEvent(WsEvent):
    """Base for all funding events (deposits and withdrawals)."""

    amount: Decimal
    instrument: InstrumentId
    sender: str
    receiver: str
    ledger_created_at: str

    @classmethod
    def _from_raw(cls, raw: dict) -> FundingEvent:
        d = raw.get("data", {})
        return cls(
            **WsEvent._from_raw(raw).__dict__,
            amount=Decimal(d.get("amount", "0")),
            instrument=InstrumentId(
                id=d.get("instrument_id", ""),
                admin=d.get("instrument_admin", ""),
            ),
            sender=d.get("sender", ""),
            receiver=d.get("receiver", ""),
            ledger_created_at=d.get("ledger_created_at", ""),
        )


@dataclass(frozen=True)
class DepositPendingEvent(FundingEvent):
    """A deposit has been initiated and is pending confirmation."""

    execute_before: str
    requested_at: str

    @classmethod
    def _from_raw(cls, raw: dict) -> DepositPendingEvent:
        d = raw.get("data", {})
        return cls(
            **FundingEvent._from_raw(raw).__dict__,
            execute_before=d.get("execute_before", ""),
            requested_at=d.get("requested_at", ""),
        )


@dataclass(frozen=True)
class DepositConfirmedEvent(FundingEvent):
    """A deposit was confirmed on the ledger."""

    @classmethod
    def _from_raw(cls, raw: dict) -> DepositConfirmedEvent:
        return cls(**FundingEvent._from_raw(raw).__dict__)


@dataclass(frozen=True)
class DepositRejectedEvent(FundingEvent):
    """A deposit was rejected."""

    @classmethod
    def _from_raw(cls, raw: dict) -> DepositRejectedEvent:
        return cls(**FundingEvent._from_raw(raw).__dict__)


@dataclass(frozen=True)
class WithdrawalRequestedEvent(FundingEvent):
    """A withdrawal has been requested and is pending execution."""

    execute_before: str
    requested_at: str

    @classmethod
    def _from_raw(cls, raw: dict) -> WithdrawalRequestedEvent:
        d = raw.get("data", {})
        return cls(
            **FundingEvent._from_raw(raw).__dict__,
            execute_before=d.get("execute_before", ""),
            requested_at=d.get("requested_at", ""),
        )


@dataclass(frozen=True)
class WithdrawalCompletedEvent(FundingEvent):
    """A withdrawal was successfully completed."""

    @classmethod
    def _from_raw(cls, raw: dict) -> WithdrawalCompletedEvent:
        return cls(**FundingEvent._from_raw(raw).__dict__)


@dataclass(frozen=True)
class WithdrawalFailedEvent(FundingEvent):
    """A withdrawal failed."""

    @classmethod
    def _from_raw(cls, raw: dict) -> WithdrawalFailedEvent:
        return cls(**FundingEvent._from_raw(raw).__dict__)


# ---------------------------------------------------------------------------
# WebSocket event parser
# ---------------------------------------------------------------------------

_WS_EVENT_PARSERS: dict[str, type[WsEvent]] = {
    "Pool.SwapPending": SwapPendingEvent,
    "Pool.SwapFailed": SwapFailedEvent,
    "Pool.SwapExecuted": SwapExecutedEvent,
    "Funding.DepositPending": DepositPendingEvent,
    "Funding.DepositConfirmed": DepositConfirmedEvent,
    "Funding.DepositRejected": DepositRejectedEvent,
    "Funding.WithdrawalRequested": WithdrawalRequestedEvent,
    "Funding.WithdrawalCompleted": WithdrawalCompletedEvent,
    "Funding.WithdrawalFailed": WithdrawalFailedEvent,
}


def _parse_ws_event(raw: dict) -> WsEvent:
    """Parse a raw WebSocket JSON dict into a typed event."""
    event_type = raw.get("type", "")
    cls = _WS_EVENT_PARSERS.get(event_type, WsEvent)
    return cls._from_raw(raw)


# ---------------------------------------------------------------------------
# WebSocket wrapper
# ---------------------------------------------------------------------------


class CantexWebSocket:
    """Async-iterable wrapper around an aiohttp WebSocket connection.

    Yields typed :class:`WsEvent` instances for each incoming business
    event.  Ping frames are answered with a pong automatically.
    If the connection drops unexpectedly and a *reconnect* callable was
    provided, the wrapper transparently reconnects with exponential backoff.

    Usage::

        async with sdk.connect_public_ws() as ws:
            async for event in ws:
                print(event.event_type, event.data)
    """

    def __init__(
        self,
        ws: aiohttp.ClientWebSocketResponse,
        reconnect: Callable[[], Awaitable[aiohttp.ClientWebSocketResponse]] | None = None,
        max_reconnects: int = 5,
        reconnect_base_delay: float = 1.0,
    ) -> None:
        self._ws = ws
        self._reconnect_fn = reconnect
        self._max_reconnects = max_reconnects
        self._reconnect_base_delay = reconnect_base_delay
        self._closed_by_user = False

    async def __aenter__(self) -> CantexWebSocket:
        return self

    async def __aexit__(self, exc_type: type | None, exc_val: BaseException | None, exc_tb: Any) -> None:
        await self.close()

    def __aiter__(self) -> CantexWebSocket:
        return self

    async def _reconnect(self) -> None:
        """Attempt to re-establish the WebSocket connection with backoff."""
        if self._reconnect_fn is None:
            raise RuntimeError("_reconnect called without a reconnect function")
        for attempt in range(1, self._max_reconnects + 1):
            wait = self._reconnect_base_delay * (2 ** (attempt - 1))
            logger.warning(
                "WS reconnecting (attempt %d/%d) in %.1fs...",
                attempt, self._max_reconnects, wait,
            )
            await asyncio.sleep(wait)
            try:
                self._ws = await self._reconnect_fn()
                logger.info("WS reconnected")
                return
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                logger.warning("WS reconnect attempt %d failed: %s", attempt, exc)
        raise CantexError(
            f"WebSocket reconnection failed after {self._max_reconnects} attempts"
        )

    async def __anext__(self) -> WsEvent:
        while True:
            msg = await self._ws.receive()
            if msg.type == aiohttp.WSMsgType.TEXT:
                logger.debug("WS raw message: %s", msg.data)
                try:
                    raw = json.loads(msg.data)
                except json.JSONDecodeError as exc:
                    raise CantexError(f"Invalid JSON in WebSocket message: {msg.data[:200]}") from exc
            elif msg.type == aiohttp.WSMsgType.BINARY:
                logger.debug("WS binary message (%d bytes)", len(msg.data))
                try:
                    raw = json.loads(msg.data)
                except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                    raise CantexError("Received non-JSON binary WebSocket message") from exc
            elif msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSING, aiohttp.WSMsgType.CLOSED):
                if self._closed_by_user or self._reconnect_fn is None:
                    logger.info("WebSocket closed (code=%s)", msg.data)
                    raise StopAsyncIteration
                logger.warning("WebSocket closed unexpectedly (code=%s), reconnecting...", msg.data)
                await self._reconnect()
                continue
            elif msg.type == aiohttp.WSMsgType.ERROR:
                if self._reconnect_fn is None:
                    raise CantexError(f"WebSocket error: {self._ws.exception()}")
                logger.warning("WebSocket error: %s, reconnecting...", self._ws.exception())
                await self._reconnect()
                continue
            else:
                raise StopAsyncIteration

            if raw.get("op") == "ping":
                logger.debug("WS ping received, sending pong")
                await self._ws.send_json({"op": "pong"})
                continue

            return _parse_ws_event(raw)

    async def close(self) -> None:
        """Close the underlying WebSocket connection."""
        self._closed_by_user = True
        if not self._ws.closed:
            await self._ws.close()

    @property
    def closed(self) -> bool:
        return self._ws.closed


class _WebSocketConnect:
    """Awaitable async-context-manager returned by the ``connect_*_ws`` methods."""

    def __init__(self, coro: Any) -> None:
        self._coro = coro
        self._ws: CantexWebSocket | None = None

    def __await__(self):
        return self._coro.__await__()

    async def __aenter__(self) -> CantexWebSocket:
        self._ws = await self._coro
        return self._ws

    async def __aexit__(self, exc_type: type | None, exc_val: BaseException | None, exc_tb: Any) -> None:
        if self._ws is not None:
            await self._ws.close()


# ---------------------------------------------------------------------------
# SDK
# ---------------------------------------------------------------------------

_RETRYABLE_STATUSES = frozenset({429, 502, 503, 504})


class CantexSDK:
    """Async SDK for the Cantex API.

    Accepts pre-built signer objects so that key management is fully
    decoupled from the API interaction logic.

    Example::

        operator = OperatorKeySigner.from_file("secrets/operator.pem", key_type="pem")
        intent   = IntentTradingKeySigner.from_file("secrets/intent.key")

        async with CantexSDK(operator, intent) as sdk:
            await sdk.authenticate()
            info = await sdk.get_account_info()
    """

    def __init__(
        self,
        operator_signer: OperatorKeySigner,
        intent_signer: IntentTradingKeySigner | None = None,
        *,
        base_url: str = "https://api.testnet.cantex.io",
        api_key_path: str | None = "secrets/api_key.txt",
        timeout: aiohttp.ClientTimeout | None = None,
        max_retries: int = 3,
        retry_base_delay: float = 1.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._operator_signer = operator_signer
        self._intent_signer = intent_signer
        self._api_key: str | None = None
        self._api_key_path = api_key_path
        self._session: aiohttp.ClientSession | None = None
        self._timeout = timeout or aiohttp.ClientTimeout(
            total=30, sock_connect=10, sock_read=30,
        )
        self._max_retries = max_retries
        self._retry_base_delay = retry_base_delay
        self._auth_lock = asyncio.Lock()
        self._open_websockets: list[CantexWebSocket] = []
        self._load_api_key()

    def __repr__(self) -> str:
        return (
            f"CantexSDK(base_url={self.base_url!r}, "
            f"authenticated={self._api_key is not None})"
        )

    # -- session lifecycle ---------------------------------------------------

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(limit=20)
            self._session = aiohttp.ClientSession(
                timeout=self._timeout,
                connector=connector,
                headers={"User-Agent": "CantexSDK/1.0"},
            )
        return self._session

    async def close(self) -> None:
        """Close all open WebSocket connections and the underlying HTTP session."""
        for ws in self._open_websockets:
            if not ws.closed:
                await ws.close()
        self._open_websockets.clear()
        if self._session and not self._session.closed:
            await self._session.close()

    async def __aenter__(self) -> CantexSDK:
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    # -- API-key persistence -------------------------------------------------

    def _load_api_key(self) -> None:
        if self._api_key_path and os.path.exists(self._api_key_path):
            with open(self._api_key_path, "r") as fh:
                self._api_key = fh.read().strip()

    def _save_api_key(self) -> None:
        if self._api_key_path and self._api_key:
            os.makedirs(os.path.dirname(self._api_key_path) or ".", exist_ok=True)
            with open(self._api_key_path, "w") as fh:
                fh.write(self._api_key)
            os.chmod(self._api_key_path, 0o600)

    def _ensure_authenticated(self) -> None:
        if self._api_key is None:
            raise RuntimeError("Not authenticated. Call authenticate() first.")

    def _auth_headers(self) -> dict[str, str]:
        self._ensure_authenticated()
        return {"Authorization": f"Bearer {self._api_key}"}

    @property
    def public_key(self) -> str:
        """Operator public key in URL-safe base64 (for display / API usage)."""
        return self._operator_signer.get_public_key_b64()

    @property
    def _ws_base_url(self) -> str:
        """WebSocket base URL derived from the HTTP base URL."""
        return self.base_url.replace("https://", "wss://").replace("http://", "ws://")

    # -- HTTP helper ---------------------------------------------------------

    @staticmethod
    def _require_key(data: dict, key: str, context: str = "") -> Any:
        """Extract a required key from a response dict, raising on missing keys."""
        try:
            return data[key]
        except KeyError:
            raise CantexError(
                f"Missing required key '{key}' in API response{context}"
            ) from None

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_data: dict | None = None,
        authenticated: bool = True,
    ) -> dict:
        """Send an HTTP request with retry, error extraction, and logging.

        Retries on transient failures (429, 502, 503, 504) and network errors
        with exponential backoff.
        """
        session = await self._get_session()
        url = f"{self.base_url}{path}"
        headers = self._auth_headers() if authenticated else {}

        last_exc: Exception | None = None
        for attempt in range(1, self._max_retries + 1):
            try:
                logger.debug(
                    "API %s %s (attempt %d/%d)", method, path, attempt, self._max_retries,
                )
                async with session.request(
                    method, url, headers=headers, json=json_data,
                ) as resp:
                    body = await resp.text()
                    logger.debug(
                        "API %s %s -> %d (%d bytes)",
                        method, path, resp.status, len(body),
                    )

                    if resp.status in (401, 403):
                        raise CantexAuthError(resp.status, body)

                    if resp.status >= 400:
                        if (
                            resp.status in _RETRYABLE_STATUSES
                            and attempt < self._max_retries
                        ):
                            wait = self._retry_base_delay * (2 ** (attempt - 1))
                            logger.warning(
                                "API %s %s returned %d (attempt %d/%d), "
                                "retrying in %.1fs",
                                method, path, resp.status,
                                attempt, self._max_retries, wait,
                            )
                            await asyncio.sleep(wait)
                            continue
                        raise CantexAPIError(resp.status, body)

                    try:
                        return json.loads(body)
                    except json.JSONDecodeError as exc:
                        raise CantexError(
                            f"Invalid JSON in {resp.status} response "
                            f"from {method} {path}"
                        ) from exc

            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                last_exc = exc
                if attempt < self._max_retries:
                    wait = self._retry_base_delay * (2 ** (attempt - 1))
                    logger.warning(
                        "API %s %s failed (attempt %d/%d): %s, "
                        "retrying in %.1fs",
                        method, path, attempt, self._max_retries, exc, wait,
                    )
                    await asyncio.sleep(wait)
                else:
                    if isinstance(exc, asyncio.TimeoutError):
                        raise CantexTimeoutError(
                            f"{method} {path} timed out after "
                            f"{self._max_retries} attempts"
                        ) from exc
                    raise CantexError(
                        f"{method} {path} failed after "
                        f"{self._max_retries} attempts: {exc}"
                    ) from exc

        raise CantexError(
            f"{method} {path} failed after {self._max_retries} attempts"
        ) from last_exc

    # -- authentication ------------------------------------------------------

    async def authenticate(self, *, force: bool = False) -> str:
        """Challenge-response auth using the operator Ed25519 key.

        Returns the API key for subsequent requests.  Uses an internal lock
        to prevent concurrent authentication flows.
        """
        async with self._auth_lock:
            if not force and self._api_key:
                try:
                    await self._request("GET", "/v1/account/info")
                    logger.debug("Using cached API key")
                    return self._api_key
                except CantexError:
                    logger.debug("Cached API key invalid, re-authenticating")

            logger.info("Authenticating with Cantex API...")

            challenge = await self._request(
                "POST",
                "/v1/auth/api-key/begin",
                json_data={
                    "publicKey": self._operator_signer.get_public_key_b64(),
                },
                authenticated=False,
            )

            message = self._require_key(challenge, "message", " (auth challenge)")
            challenge_id = self._require_key(
                challenge, "challengeId", " (auth challenge)",
            )
            signature = self._operator_signer.sign(message.encode())

            result = await self._request(
                "POST",
                "/v1/auth/api-key/finish",
                json_data={
                    "challengeId": challenge_id,
                    "signature": _b64_encode(signature),
                },
                authenticated=False,
            )

            self._api_key = self._require_key(result, "api_key", " (auth result)")
            self._save_api_key()
            logger.info("Authentication successful")
            return self._api_key

    # -- build -> sign -> submit ---------------------------------------------

    async def _build_sign_submit(
        self,
        build_path: str,
        payload: dict,
        *,
        intent: bool = False,
    ) -> dict:
        """Build a transaction or intent, sign it, and submit.

        When *intent* is False (default), uses the operator-key flow:
        build a ledger transaction, sign its hash with Ed25519, submit.

        When *intent* is True, uses the intent-key flow:
        build an intent, sign its digest with secp256k1, submit.
        """
        if intent and self._intent_signer is None:
            raise RuntimeError(
                "IntentTradingKeySigner not configured. "
                "Pass one to CantexSDK() to use intent operations."
            )

        build_data = await self._request("POST", build_path, json_data=payload)
        build_id = self._require_key(build_data, "id", f" ({build_path})")

        if intent:
            intent_obj = self._require_key(
                build_data, "intent", f" ({build_path})",
            )
            digest = self._require_key(
                intent_obj, "digest", f" ({build_path} intent)",
            )
            signature_hex = self._intent_signer.sign_digest_hex(digest)
            return await self._request(
                "POST",
                "/v1/intent/submit",
                json_data={
                    "id": build_id,
                    "intentTradingKeySignature": signature_hex,
                },
            )

        context = self._require_key(build_data, "context", f" ({build_path})")
        tx_hash_b64 = self._require_key(
            context, "transaction_hash", f" ({build_path} context)",
        )
        tx_hash_bytes = base64.b64decode(tx_hash_b64)
        signature_b64 = _b64_encode(self._operator_signer.sign(tx_hash_bytes))
        return await self._request(
            "POST",
            "/v1/ledger/transaction/submit",
            json_data={
                "id": build_id,
                "operatorKeySignedTransactionHash": signature_b64,
            },
        )

    # -- WebSocket connections -----------------------------------------------

    async def _ws_connect(
        self,
        path: str,
        *,
        authenticated: bool = False,
    ) -> CantexWebSocket:
        """Open a WebSocket connection and return a :class:`CantexWebSocket`.

        The returned wrapper is tracked internally so it is closed
        automatically when :meth:`close` is called.
        """
        session = await self._get_session()
        url = f"{self._ws_base_url}{path}"
        headers = self._auth_headers() if authenticated else {}
        raw_ws = await session.ws_connect(url, headers=headers)
        logger.info("WebSocket connected: %s", path)

        async def reconnect() -> aiohttp.ClientWebSocketResponse:
            s = await self._get_session()
            h = self._auth_headers() if authenticated else {}
            return await s.ws_connect(url, headers=h)

        ws = CantexWebSocket(
            raw_ws,
            reconnect=reconnect,
            max_reconnects=self._max_retries,
            reconnect_base_delay=self._retry_base_delay,
        )
        self._open_websockets = [w for w in self._open_websockets if not w.closed]
        self._open_websockets.append(ws)
        return ws

    def connect_public_ws(self) -> _WebSocketConnect:
        """Connect to the public event stream (no authentication required).

        Returns an awaitable async-context-manager::

            async with sdk.connect_public_ws() as ws:
                async for event in ws:
                    print(event)
        """
        return _WebSocketConnect(self._ws_connect("/v1/ws/public"))

    def connect_private_ws(self) -> _WebSocketConnect:
        """Connect to the private event stream (requires authentication).

        Call :meth:`authenticate` before using this method.

        Returns an awaitable async-context-manager::

            async with sdk.connect_private_ws() as ws:
                async for event in ws:
                    print(event)
        """
        return _WebSocketConnect(
            self._ws_connect("/v1/ws/private", authenticated=True),
        )

    # -- public API ----------------------------------------------------------

    async def get_account_info(self) -> AccountInfo:
        """Retrieve account information including token balances and pending operations."""
        data = await self._request("GET", "/v1/account/info")
        return AccountInfo._from_raw(data)

    async def get_account_admin(self) -> AccountAdmin:
        """Retrieve administrative account details (contracts, party info)."""
        data = await self._request("GET", "/v1/account/admin")
        return AccountAdmin._from_raw(data)

    async def get_pool_info(self) -> PoolsInfo:
        """Retrieve information about all available liquidity pools."""
        data = await self._request("GET", "/v2/pools/info")
        return PoolsInfo._from_raw(data)

    async def get_swap_quote(
        self,
        sell_amount: Decimal,
        sell_instrument: InstrumentId,
        buy_instrument: InstrumentId,
    ) -> SwapQuote:
        """Get a price quote for swapping tokens in a liquidity pool."""
        data = await self._request(
            "POST",
            "/v2/pools/quote",
            json_data={
                "sellAmount": str(sell_amount),
                "sellInstrumentId": sell_instrument.id,
                "sellInstrumentAdmin": sell_instrument.admin,
                "buyInstrumentId": buy_instrument.id,
                "buyInstrumentAdmin": buy_instrument.admin,
            },
        )
        return SwapQuote._from_raw(data)

    async def create_trading_account(self) -> dict:
        """Create a pool trading account (fails if one already exists)."""
        admin = await self.get_account_admin()
        if admin.has_trading_account:
            raise RuntimeError(
                f"Trading account already exists: "
                f"{admin.trading_account.get('contract_id')}"
            )

        logger.info("Creating trading account...")
        result = await self._build_sign_submit(
            "/v1/ledger/transaction/build/pool/create_account", {},
        )
        logger.info("Trading account created successfully")
        return result

    async def transfer(
        self,
        amount: Decimal,
        instrument: InstrumentId,
        receiver: str,
        memo: str = "",
    ) -> dict:
        """Transfer tokens to another account."""
        logger.info(
            "Transferring %s %s to %s...", amount, instrument.id, receiver[:20],
        )
        result = await self._build_sign_submit(
            "/v1/ledger/transaction/build/transfer",
            {
                "instrumentAdmin": instrument.admin,
                "instrumentId": instrument.id,
                "receiver": receiver,
                "amount": str(amount),
                "memo": memo,
            },
        )
        logger.info("Transfer completed")
        return result

    async def batch_transfer(
        self,
        transfers: list[TransferItem],
        instrument: InstrumentId,
        memo: str = "",
    ) -> dict:
        """Transfer tokens to multiple receivers in a single transaction.

        Each item in *transfers* must have ``receiver`` and ``amount`` keys.
        """
        for i, t in enumerate(transfers):
            if "receiver" not in t or "amount" not in t:
                raise ValueError(
                    f"Transfer at index {i} missing required key(s): "
                    f"needs 'receiver' and 'amount', got keys {list(t.keys())}"
                )

        logger.info(
            "Batch transferring %d %s transfers...", len(transfers), instrument.id,
        )
        result = await self._build_sign_submit(
            "/v1/ledger/transaction/build/batch_transfer",
            {
                "instrumentAdmin": instrument.admin,
                "instrumentId": instrument.id,
                "transfers": [
                    {"receiver": t["receiver"], "amount": str(t["amount"])}
                    for t in transfers
                ],
                "memo": memo,
            },
        )
        logger.info("Batch transfer completed")
        return result

    async def reclaim_expired_transfer(self, transfer_cid: str) -> dict:
        """Reclaim tokens from an expired pending transfer."""
        logger.info("Reclaiming transfer: %s...", transfer_cid[:20])
        result = await self._build_sign_submit(
            "/v1/ledger/transaction/build/transfer_action",
            {"transferInstructionCid": transfer_cid, "choice": "withdraw"},
        )
        logger.info("Transfer reclaimed: %s...", transfer_cid[:20])
        return result

    async def reclaim_expired_allocation(self, allocation_cid: str) -> dict:
        """Reclaim tokens from an expired allocation."""
        logger.info("Reclaiming allocation: %s...", allocation_cid[:20])
        result = await self._build_sign_submit(
            "/v1/ledger/transaction/build/allocation_action",
            {"allocationCid": allocation_cid, "choice": "withdraw"},
        )
        logger.info("Allocation reclaimed: %s...", allocation_cid[:20])
        return result

    # -- intent operations ---------------------------------------------------

    async def create_intent_trading_account(self) -> dict:
        """Create an intent trading account (fails if one already exists).

        Requires an ``IntentTradingKeySigner`` to be configured.
        """
        if self._intent_signer is None:
            raise RuntimeError(
                "IntentTradingKeySigner required for "
                "create_intent_trading_account"
            )

        admin = await self.get_account_admin()
        if admin.has_intent_account:
            raise RuntimeError(
                f"Intent trading account already exists: "
                f"{admin.intent_account.get('contract_id')}"
            )

        logger.info("Creating intent trading account...")
        result = await self._build_sign_submit(
            "/v1/ledger/transaction/build/pool/create_intent_account",
            {
                "intentTradingPublicKeyHex":
                    self._intent_signer.get_public_key_hex_der(),
            },
        )
        logger.info("Intent trading account created successfully")
        return result

    async def swap(
        self,
        sell_amount: Decimal,
        sell_instrument: InstrumentId,
        buy_instrument: InstrumentId,
    ) -> dict:
        """Execute a token swap via the intent-based trading flow."""
        logger.info(
            "Intent swap: %s %s -> %s",
            sell_amount, sell_instrument.id, buy_instrument.id,
        )
        result = await self._build_sign_submit(
            "/v1/intent/build/pool/swap",
            {
                "sellAmount": str(sell_amount),
                "sellInstrumentId": sell_instrument.id,
                "sellInstrumentAdmin": sell_instrument.admin,
                "buyInstrumentId": buy_instrument.id,
                "buyInstrumentAdmin": buy_instrument.admin,
            },
            intent=True,
        )
        logger.debug("Intent swap submitted: %s", result)
        return result

    async def swap_and_confirm(
        self,
        sell_amount: Decimal,
        sell_instrument: InstrumentId,
        buy_instrument: InstrumentId,
        *,
        timeout: float = 60.0,
    ) -> SwapExecutedEvent:
        """Execute a token swap and wait for on-ledger confirmation.

        Connects to the private WebSocket **before** submitting the swap so
        that the confirmation event is never missed, then listens for a
        ``Pool.SwapExecuted`` or ``Pool.SwapFailed`` event.

        Returns
        -------
        SwapExecutedEvent
            The confirmed trade details including amounts, fees, and price.

        Raises
        ------
        CantexError
            If the swap fails (wraps the error from ``SwapFailedEvent``).
        CantexTimeoutError
            If no confirmation is received within *timeout* seconds.
        """
        ws = await self._ws_connect("/v1/ws/private", authenticated=True)
        try:
            logger.info(
                "Intent swap: %s %s -> %s",
                sell_amount, sell_instrument.id, buy_instrument.id,
            )
            await self._build_sign_submit(
                "/v1/intent/build/pool/swap",
                {
                    "sellAmount": str(sell_amount),
                    "sellInstrumentId": sell_instrument.id,
                    "sellInstrumentAdmin": sell_instrument.admin,
                    "buyInstrumentId": buy_instrument.id,
                    "buyInstrumentAdmin": buy_instrument.admin,
                },
                intent=True,
            )

            async def _wait_for_confirmation() -> SwapExecutedEvent:
                async for event in ws:
                    if isinstance(event, SwapPendingEvent):
                        logger.info("Swap pending (id=%s)", event.swap_id)
                        continue
                    if isinstance(event, SwapExecutedEvent):
                        logger.info(
                            "Swap confirmed: %s %s -> %s %s",
                            event.input_amount, event.input_instrument.id,
                            event.output_amount, event.output_instrument.id,
                        )
                        return event
                    if isinstance(event, SwapFailedEvent):
                        raise CantexError(f"Swap failed: {event.error}")
                raise CantexError("WebSocket closed before swap confirmation")

            return await asyncio.wait_for(
                _wait_for_confirmation(), timeout=timeout,
            )
        except asyncio.TimeoutError:
            raise CantexTimeoutError(
                f"Swap confirmation timed out after {timeout}s"
            ) from None
        finally:
            await ws.close()
