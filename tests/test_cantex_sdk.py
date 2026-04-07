# Copyright (c) 2026 CaviarNine
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Tests for cantex_sdk — signers and SDK."""
from __future__ import annotations

import asyncio
import base64
import json
import os
import tempfile
import warnings
from decimal import Decimal
from unittest.mock import AsyncMock, patch

import aiohttp
import pytest
from aioresponses import aioresponses

from cantex_sdk import (
    AccountAdmin,
    AccountInfo,
    CantexAPIError,
    CantexAuthError,
    CantexError,
    CantexSDK,
    CantexTimeoutError,
    CantexWebSocket,
    DepositConfirmedEvent,
    DepositPendingEvent,
    DepositRejectedEvent,
    FundingEvent,
    InstrumentId,
    InstrumentInfo,
    IntentTradingKeySigner,
    OperatorKeySigner,
    Pool,
    PoolsInfo,
    QuoteFees,
    QuoteLeg,
    QuotePoolDetail,
    QuotePoolFees,
    QuotePrices,
    SwapExecutedEvent,
    SwapFailedEvent,
    SwapPendingEvent,
    SwapQuote,
    TokenBalance,
    WithdrawalCompletedEvent,
    WithdrawalFailedEvent,
    WithdrawalRequestedEvent,
    WsEvent,
)
from cantex_sdk._sdk import _WebSocketConnect, _b64_encode, _parse_ws_event

# ---------------------------------------------------------------------------
# Fixtures — deterministic key material
# ---------------------------------------------------------------------------

ED25519_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
SECP256K1_HEX = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"

BASE_URL = "https://api.test.cantex.io"


@pytest.fixture
def operator() -> OperatorKeySigner:
    return OperatorKeySigner.from_hex(ED25519_HEX)


@pytest.fixture
def intent() -> IntentTradingKeySigner:
    return IntentTradingKeySigner.from_hex(SECP256K1_HEX)


@pytest.fixture
def sdk(operator, intent) -> CantexSDK:
    return CantexSDK(
        operator,
        intent,
        base_url=BASE_URL,
        api_key_path=None,
        max_retries=1,
        retry_base_delay=0.0,
    )


@pytest.fixture
def authed_sdk(sdk) -> CantexSDK:
    """SDK with a pre-set API key so _ensure_authenticated passes."""
    sdk._api_key = "test-api-key"
    return sdk


# ===================================================================
# Helpers / utilities
# ===================================================================


class TestB64Encode:
    def test_round_trip(self):
        data = b"hello world"
        encoded = _b64_encode(data)
        padding = "=" * (-len(encoded) % 4)
        assert base64.urlsafe_b64decode(encoded + padding) == data

    def test_no_padding(self):
        assert "=" not in _b64_encode(b"\x00\x01\x02\x03")

    def test_empty(self):
        assert _b64_encode(b"") == ""


class TestRequireKey:
    def test_present(self):
        assert CantexSDK._require_key({"a": 1}, "a") == 1

    def test_missing(self):
        with pytest.raises(CantexError, match="Missing required key 'x'"):
            CantexSDK._require_key({"a": 1}, "x")

    def test_context_in_message(self):
        with pytest.raises(CantexError, match="auth challenge"):
            CantexSDK._require_key({}, "message", " (auth challenge)")


# ===================================================================
# Signers
# ===================================================================


class TestOperatorKeySigner:
    def test_from_hex(self, operator):
        assert isinstance(operator, OperatorKeySigner)
        pub = operator.get_public_key_hex()
        assert len(pub) == 64

    def test_sign_and_verify(self, operator):
        data = b"test message"
        sig = operator.sign(data)
        assert isinstance(sig, bytes)
        assert len(sig) == 64  # Ed25519 signatures are 64 bytes

    def test_public_key_b64(self, operator):
        b64 = operator.get_public_key_b64()
        assert isinstance(b64, str)
        assert "=" not in b64

    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("TEST_OP_KEY", ED25519_HEX)
        signer = OperatorKeySigner.from_env("TEST_OP_KEY")
        assert signer.get_public_key_hex() == OperatorKeySigner.from_hex(ED25519_HEX).get_public_key_hex()

    def test_from_env_missing(self):
        with pytest.raises(ValueError, match="not set"):
            OperatorKeySigner.from_env("DEFINITELY_NOT_SET_12345")

    def test_from_hex_file(self, tmp_path):
        key_file = tmp_path / "key.hex"
        key_file.write_text(ED25519_HEX)
        signer = OperatorKeySigner.from_hex_file(str(key_file))
        assert signer.get_public_key_hex() == OperatorKeySigner.from_hex(ED25519_HEX).get_public_key_hex()

    def test_from_raw_file(self, tmp_path):
        key_file = tmp_path / "key.raw"
        key_file.write_bytes(bytes.fromhex(ED25519_HEX))
        signer = OperatorKeySigner.from_raw_file(str(key_file))
        assert signer.get_public_key_hex() == OperatorKeySigner.from_hex(ED25519_HEX).get_public_key_hex()

    def test_from_pem_file_roundtrip(self, tmp_path):
        pem_bytes = OperatorKeySigner._to_pem(bytes.fromhex(ED25519_HEX))
        pem_file = tmp_path / "key.pem"
        pem_file.write_bytes(pem_bytes)
        signer = OperatorKeySigner.from_pem_file(str(pem_file))
        assert signer.get_public_key_hex() == OperatorKeySigner.from_hex(ED25519_HEX).get_public_key_hex()

    def test_from_pem_file_wrong_key_type(self, tmp_path):
        from cryptography.hazmat.primitives.asymmetric import ec

        wrong_key = ec.generate_private_key(ec.SECP256R1())
        from cryptography.hazmat.primitives import serialization

        pem = wrong_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pem_file = tmp_path / "wrong.pem"
        pem_file.write_bytes(pem)
        with pytest.raises(ValueError, match="Ed25519"):
            OperatorKeySigner.from_pem_file(str(pem_file))

    def test_from_file_missing_no_prompt(self):
        with pytest.raises(FileNotFoundError):
            OperatorKeySigner.from_file("/nonexistent/key.hex")

    def test_from_file_unsupported_type(self):
        with pytest.raises(ValueError, match="Unsupported"):
            OperatorKeySigner.from_file("dummy", key_type="der")

    def test_repr(self, operator):
        r = repr(operator)
        assert r.startswith("OperatorKeySigner(pub=")
        assert "..." in r


class TestIntentTradingKeySigner:
    def test_from_hex(self, intent):
        assert isinstance(intent, IntentTradingKeySigner)
        pub = intent.get_public_key_hex()
        assert pub.startswith("04")
        assert len(pub) == 130  # "04" + 64 hex x + 64 hex y

    def test_wrong_key_length(self):
        with pytest.raises(ValueError, match="32 bytes"):
            IntentTradingKeySigner.from_hex("aabb")

    def test_sign_digest(self, intent):
        digest = b"\x00" * 32
        sig = intent.sign(digest)
        assert isinstance(sig, bytes)
        assert len(sig) > 0

    def test_sign_wrong_length(self, intent):
        with pytest.raises(ValueError, match="32 bytes"):
            intent.sign(b"\x00" * 31)

    def test_sign_digest_hex(self, intent):
        digest_hex = "00" * 32
        sig_hex = intent.sign_digest_hex(digest_hex)
        assert isinstance(sig_hex, str)
        bytes.fromhex(sig_hex)  # should be valid hex

    def test_public_key_hex_der(self, intent):
        der_hex = intent.get_public_key_hex_der()
        assert len(der_hex) == 176  # 88 bytes

    def test_from_pem_roundtrip(self, tmp_path):
        pem_bytes = IntentTradingKeySigner._to_pem(bytes.fromhex(SECP256K1_HEX))
        pem_file = tmp_path / "intent.pem"
        pem_file.write_bytes(pem_bytes)
        signer = IntentTradingKeySigner.from_pem_file(str(pem_file))
        assert signer.get_public_key_hex() == IntentTradingKeySigner.from_hex(SECP256K1_HEX).get_public_key_hex()

    def test_from_pem_wrong_curve(self, tmp_path):
        import ecdsa as _ecdsa

        wrong_sk = _ecdsa.SigningKey.generate(curve=_ecdsa.NIST256p)
        pem_file = tmp_path / "wrong.pem"
        pem_file.write_bytes(wrong_sk.to_pem())
        with pytest.raises(ValueError, match="secp256k1"):
            IntentTradingKeySigner.from_pem_file(str(pem_file))

    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("TEST_INTENT_KEY", SECP256K1_HEX)
        signer = IntentTradingKeySigner.from_env("TEST_INTENT_KEY")
        assert signer.get_public_key_hex() == IntentTradingKeySigner.from_hex(SECP256K1_HEX).get_public_key_hex()

    def test_repr(self, intent):
        r = repr(intent)
        assert r.startswith("IntentTradingKeySigner(pub=")
        assert "..." in r


# ===================================================================
# SDK core — initialization, persistence & session lifecycle
# ===================================================================


class TestCantexSDKInit:
    def test_base_url_trailing_slash_stripped(self, operator):
        sdk = CantexSDK(operator, base_url="https://example.com/", api_key_path=None)
        assert sdk.base_url == "https://example.com"

    def test_repr_unauthenticated(self, sdk):
        r = repr(sdk)
        assert "authenticated=False" in r

    def test_repr_authenticated(self, authed_sdk):
        r = repr(authed_sdk)
        assert "authenticated=True" in r

    def test_public_key_property(self, sdk, operator):
        assert sdk.public_key == operator.get_public_key_b64()

    def test_ensure_authenticated_raises(self, sdk):
        with pytest.raises(RuntimeError, match="Not authenticated"):
            sdk._ensure_authenticated()


class TestCantexSDKApiKeyPersistence:
    def test_load_and_save(self, operator, tmp_path):
        key_path = str(tmp_path / "api_key.txt")
        sdk = CantexSDK(operator, base_url=BASE_URL, api_key_path=key_path)
        assert sdk._api_key is None

        sdk._api_key = "my-secret-key"
        sdk._save_api_key()

        sdk2 = CantexSDK(operator, base_url=BASE_URL, api_key_path=key_path)
        assert sdk2._api_key == "my-secret-key"

    def test_save_sets_permissions(self, operator, tmp_path):
        key_path = str(tmp_path / "api_key.txt")
        sdk = CantexSDK(operator, base_url=BASE_URL, api_key_path=key_path)
        sdk._api_key = "secret"
        sdk._save_api_key()
        mode = os.stat(key_path).st_mode & 0o777
        assert mode == 0o600

    def test_save_bare_filename(self, operator, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        sdk = CantexSDK(operator, base_url=BASE_URL, api_key_path="api_key.txt")
        sdk._api_key = "secret"
        sdk._save_api_key()
        assert (tmp_path / "api_key.txt").read_text() == "secret"


@pytest.mark.asyncio
class TestSessionLifecycle:
    async def test_context_manager(self, operator):
        async with CantexSDK(operator, base_url=BASE_URL, api_key_path=None) as sdk:
            session = await sdk._get_session()
            assert not session.closed
        assert session.closed

    async def test_close_idempotent(self, sdk):
        await sdk.close()
        await sdk.close()  # should not raise


# ===================================================================
# SDK HTTP / _request
# ===================================================================


@pytest.mark.asyncio
class TestRequest:
    async def test_get_success(self, authed_sdk):
        with aioresponses() as m:
            m.get(f"{BASE_URL}/v1/account/info", payload={"status": "ok"})
            result = await authed_sdk._request("GET", "/v1/account/info")
            assert result == {"status": "ok"}
        await authed_sdk.close()

    async def test_post_with_json(self, authed_sdk):
        with aioresponses() as m:
            m.post(f"{BASE_URL}/v1/test", payload={"result": "done"})
            result = await authed_sdk._request(
                "POST", "/v1/test", json_data={"key": "value"},
            )
            assert result == {"result": "done"}
        await authed_sdk.close()

    async def test_401_raises_auth_error(self, authed_sdk):
        with aioresponses() as m:
            m.get(f"{BASE_URL}/v1/account/info", status=401, body="Unauthorized")
            with pytest.raises(CantexAuthError) as exc_info:
                await authed_sdk._request("GET", "/v1/account/info")
            assert exc_info.value.status == 401
        await authed_sdk.close()

    async def test_403_raises_auth_error(self, authed_sdk):
        with aioresponses() as m:
            m.get(f"{BASE_URL}/v1/account/info", status=403, body="Forbidden")
            with pytest.raises(CantexAuthError) as exc_info:
                await authed_sdk._request("GET", "/v1/account/info")
            assert exc_info.value.status == 403
        await authed_sdk.close()

    async def test_400_raises_api_error(self, authed_sdk):
        with aioresponses() as m:
            m.get(f"{BASE_URL}/v1/test", status=400, body="Bad Request")
            with pytest.raises(CantexAPIError) as exc_info:
                await authed_sdk._request("GET", "/v1/test")
            assert exc_info.value.status == 400
        await authed_sdk.close()

    async def test_502_retries_then_fails(self, operator, intent):
        sdk = CantexSDK(
            operator, intent,
            base_url=BASE_URL, api_key_path=None,
            max_retries=2, retry_base_delay=0.0,
        )
        sdk._api_key = "key"
        with aioresponses() as m:
            m.get(f"{BASE_URL}/v1/test", status=502, body="Bad Gateway")
            m.get(f"{BASE_URL}/v1/test", status=502, body="Bad Gateway")
            with pytest.raises(CantexAPIError) as exc_info:
                await sdk._request("GET", "/v1/test")
            assert exc_info.value.status == 502
        await sdk.close()

    async def test_502_then_success(self, operator, intent):
        sdk = CantexSDK(
            operator, intent,
            base_url=BASE_URL, api_key_path=None,
            max_retries=2, retry_base_delay=0.0,
        )
        sdk._api_key = "key"
        with aioresponses() as m:
            m.get(f"{BASE_URL}/v1/test", status=502, body="Bad Gateway")
            m.get(f"{BASE_URL}/v1/test", payload={"ok": True})
            result = await sdk._request("GET", "/v1/test")
            assert result == {"ok": True}
        await sdk.close()

    async def test_invalid_json_raises(self, authed_sdk):
        with aioresponses() as m:
            m.get(f"{BASE_URL}/v1/test", status=200, body="not json")
            with pytest.raises(CantexError, match="Invalid JSON"):
                await authed_sdk._request("GET", "/v1/test")
        await authed_sdk.close()

    async def test_unauthenticated_request(self, sdk):
        with aioresponses() as m:
            m.post(f"{BASE_URL}/v1/auth/begin", payload={"token": "abc"})
            result = await sdk._request(
                "POST", "/v1/auth/begin", authenticated=False,
            )
            assert result == {"token": "abc"}
        await sdk.close()

    async def test_network_error_retries(self, operator, intent):
        sdk = CantexSDK(
            operator, intent,
            base_url=BASE_URL, api_key_path=None,
            max_retries=2, retry_base_delay=0.0,
        )
        sdk._api_key = "key"
        with aioresponses() as m:
            m.get(
                f"{BASE_URL}/v1/test",
                exception=aiohttp.ClientConnectionError("conn refused"),
            )
            m.get(f"{BASE_URL}/v1/test", payload={"recovered": True})
            result = await sdk._request("GET", "/v1/test")
            assert result == {"recovered": True}
        await sdk.close()

    async def test_network_error_exhausted(self, authed_sdk):
        with aioresponses() as m:
            m.get(
                f"{BASE_URL}/v1/test",
                exception=aiohttp.ClientConnectionError("conn refused"),
            )
            with pytest.raises(CantexError, match="failed after"):
                await authed_sdk._request("GET", "/v1/test")
        await authed_sdk.close()


# ===================================================================
# Authentication
# ===================================================================


@pytest.mark.asyncio
class TestAuthenticate:
    async def test_full_auth_flow(self, sdk, operator):
        pub_b64 = operator.get_public_key_b64()
        with aioresponses() as m:
            m.post(
                f"{BASE_URL}/v1/auth/api-key/begin",
                payload={
                    "message": "challenge-text",
                    "challengeId": "chal-123",
                },
            )
            m.post(
                f"{BASE_URL}/v1/auth/api-key/finish",
                payload={"api_key": "new-api-key-456"},
            )
            key = await sdk.authenticate()
            assert key == "new-api-key-456"
            assert sdk._api_key == "new-api-key-456"
        await sdk.close()

    async def test_cached_key_valid(self, authed_sdk):
        with aioresponses() as m:
            m.get(f"{BASE_URL}/v1/account/info", payload={"ok": True})
            key = await authed_sdk.authenticate()
            assert key == "test-api-key"
        await authed_sdk.close()

    async def test_cached_key_expired_reauths(self, authed_sdk):
        with aioresponses() as m:
            m.get(f"{BASE_URL}/v1/account/info", status=401, body="expired")
            m.post(
                f"{BASE_URL}/v1/auth/api-key/begin",
                payload={"message": "msg", "challengeId": "c1"},
            )
            m.post(
                f"{BASE_URL}/v1/auth/api-key/finish",
                payload={"api_key": "refreshed-key"},
            )
            key = await authed_sdk.authenticate()
            assert key == "refreshed-key"
        await authed_sdk.close()

    async def test_force_reauth(self, authed_sdk):
        with aioresponses() as m:
            m.post(
                f"{BASE_URL}/v1/auth/api-key/begin",
                payload={"message": "msg", "challengeId": "c2"},
            )
            m.post(
                f"{BASE_URL}/v1/auth/api-key/finish",
                payload={"api_key": "forced-key"},
            )
            key = await authed_sdk.authenticate(force=True)
            assert key == "forced-key"
        await authed_sdk.close()

    async def test_missing_challenge_key(self, sdk):
        with aioresponses() as m:
            m.post(
                f"{BASE_URL}/v1/auth/api-key/begin",
                payload={"challengeId": "c3"},
            )
            with pytest.raises(CantexError, match="message"):
                await sdk.authenticate()
        await sdk.close()


# ===================================================================
# Build-sign-submit
# ===================================================================


@pytest.mark.asyncio
class TestBuildSignSubmit:
    async def test_operator_flow(self, authed_sdk):
        tx_hash = base64.b64encode(b"\x00" * 32).decode()
        with aioresponses() as m:
            m.post(
                f"{BASE_URL}/v1/ledger/transaction/build/test",
                payload={
                    "id": "build-1",
                    "context": {"transaction_hash": tx_hash},
                },
            )
            m.post(
                f"{BASE_URL}/v1/ledger/transaction/submit",
                payload={"status": "submitted"},
            )
            result = await authed_sdk._build_sign_submit(
                "/v1/ledger/transaction/build/test", {},
            )
            assert result == {"status": "submitted"}
        await authed_sdk.close()

    async def test_intent_flow(self, authed_sdk):
        digest_hex = "00" * 32
        with aioresponses() as m:
            m.post(
                f"{BASE_URL}/v1/intent/build/pool/swap",
                payload={
                    "id": "build-2",
                    "intent": {"digest": digest_hex},
                },
            )
            m.post(
                f"{BASE_URL}/v1/intent/submit",
                payload={"status": "intent-submitted"},
            )
            result = await authed_sdk._build_sign_submit(
                "/v1/intent/build/pool/swap", {}, intent=True,
            )
            assert result == {"status": "intent-submitted"}
        await authed_sdk.close()

    async def test_intent_without_signer(self, operator):
        sdk = CantexSDK(operator, None, base_url=BASE_URL, api_key_path=None)
        sdk._api_key = "key"
        with pytest.raises(RuntimeError, match="IntentTradingKeySigner not configured"):
            await sdk._build_sign_submit("/v1/intent/build/test", {}, intent=True)
        await sdk.close()

    async def test_missing_context_key(self, authed_sdk):
        with aioresponses() as m:
            m.post(
                f"{BASE_URL}/v1/ledger/transaction/build/test",
                payload={"id": "build-3"},
            )
            with pytest.raises(CantexError, match="context"):
                await authed_sdk._build_sign_submit(
                    "/v1/ledger/transaction/build/test", {},
                )
        await authed_sdk.close()


# ===================================================================
# Public API methods
# ===================================================================


@pytest.mark.asyncio
class TestPublicAPIMethods:
    async def test_get_account_info(self, authed_sdk):
        with aioresponses() as m:
            m.get(
                f"{BASE_URL}/v1/account/info",
                payload={
                    "party_id": {"address": "Cantex::1220xyz"},
                    "user_id": "uid-info",
                    "tokens": [
                        {
                            "instrument_id": "USDC",
                            "instrument_admin": "admin1",
                            "instrument_name": "USD Coin",
                            "instrument_symbol": "USDC",
                            "balances": {
                                "unlocked_amount": "500.0",
                                "locked_amount": "50.0",
                            },
                            "pending_deposit_transfers": [],
                            "pending_withdraw_transfers": [],
                            "expired_allocations": [],
                        },
                    ],
                },
            )
            result = await authed_sdk.get_account_info()
            assert isinstance(result, AccountInfo)
            assert result.address == "Cantex::1220xyz"
            assert result.user_id == "uid-info"
            assert len(result.tokens) == 1
            assert result.tokens[0].instrument.id == "USDC"
            assert result.tokens[0].locked_amount == Decimal("50.0")
            assert result.get_balance(InstrumentId(id="USDC", admin="admin1")) == Decimal("500.0")
        await authed_sdk.close()

    async def test_get_account_admin(self, authed_sdk):
        with aioresponses() as m:
            m.get(
                f"{BASE_URL}/v1/account/admin",
                payload={
                    "party_id": {
                        "address": "Cantex::1220abc",
                        "contracts": {
                            "pool_intent_account": {"contract_id": "ia"},
                        },
                    },
                    "tokens": [
                        {
                            "instrument_id": "Amulet",
                            "instrument_admin": "DSO::1220",
                            "instrument_name": "Canton Coin",
                            "instrument_symbol": "CC",
                        },
                    ],
                    "user_id": "uid-1",
                },
            )
            result = await authed_sdk.get_account_admin()
            assert isinstance(result, AccountAdmin)
            assert result.address == "Cantex::1220abc"
            assert result.user_id == "uid-1"
            assert result.has_intent_account
            assert not result.has_trading_account
            assert len(result.instruments) == 1
            assert result.instruments[0].instrument.id == "Amulet"
        await authed_sdk.close()

    async def test_get_pool_info(self, authed_sdk):
        with aioresponses() as m:
            m.get(f"{BASE_URL}/v2/pools/info", payload={"pools": []})
            result = await authed_sdk.get_pool_info()
            assert isinstance(result, PoolsInfo)
            assert result.pools == []
        await authed_sdk.close()

    async def test_get_swap_quote(self, authed_sdk):
        with aioresponses() as m:
            m.post(
                f"{BASE_URL}/v2/pools/quote",
                payload=SAMPLE_QUOTE_RAW,
            )
            result = await authed_sdk.get_swap_quote(
                Decimal("100"),
                InstrumentId(id="USDC", admin="admin1"),
                InstrumentId(id="BTC", admin="admin2"),
            )
            assert isinstance(result, SwapQuote)
            assert result.returned_amount == Decimal("0.1547451638")
            assert result.fees.fee_percentage == Decimal("0.0005000000")
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                assert result.trade_price == Decimal("0.1548225750")
                assert result.slippage == Decimal("0.0000015358")
                assert len(w) == 2
                assert all(issubclass(x.category, DeprecationWarning) for x in w)
        await authed_sdk.close()

    async def test_batch_transfer_validation(self, authed_sdk):
        with pytest.raises(ValueError, match="index 1"):
            await authed_sdk.batch_transfer(
                [
                    {"receiver": "alice", "amount": Decimal("10")},
                    {"receiver": "bob"},  # missing amount
                ],
                InstrumentId(id="USDC", admin="admin"),
            )
        await authed_sdk.close()

    async def test_create_intent_trading_account_no_signer(self, operator):
        sdk = CantexSDK(operator, None, base_url=BASE_URL, api_key_path=None)
        sdk._api_key = "key"
        with pytest.raises(RuntimeError, match="IntentTradingKeySigner required"):
            await sdk.create_intent_trading_account()
        await sdk.close()


# ===================================================================
# Response models — Account
# ===================================================================


SAMPLE_TOKEN_RAW = {
    "instrument_id": "USDC",
    "instrument_admin": "admin::usdc",
    "instrument_name": "USD Coin",
    "instrument_symbol": "USDC",
    "balances": {"unlocked_amount": "1234.56", "locked_amount": "100.00"},
    "pending_deposit_transfers": [{"contract_id": "dep-001"}],
    "pending_withdraw_transfers": [
        {"contract_id": "tx-001"},
        {"contract_id": "tx-002"},
    ],
    "expired_allocations": [
        {"contract_id": "alloc-001"},
    ],
}

SAMPLE_TOKEN_RAW_EMPTY = {
    "instrument_id": "BTC",
    "instrument_admin": "admin::btc",
    "instrument_name": "Bitcoin",
    "instrument_symbol": "BTC",
    "balances": {"unlocked_amount": "0.5", "locked_amount": "0"},
}


class TestTokenBalance:
    def test_from_raw(self):
        t = TokenBalance._from_raw(SAMPLE_TOKEN_RAW)
        assert t.instrument.id == "USDC"
        assert t.instrument.admin == "admin::usdc"
        assert t.instrument_name == "USD Coin"
        assert t.instrument_symbol == "USDC"
        assert t.unlocked_amount == Decimal("1234.56")
        assert t.locked_amount == Decimal("100.00")
        assert t.pending_deposit_transfer_cids == ["dep-001"]
        assert t.pending_withdraw_transfer_cids == ["tx-001", "tx-002"]
        assert t.expired_allocation_cids == ["alloc-001"]

    def test_from_raw_missing_optional_lists(self):
        t = TokenBalance._from_raw(SAMPLE_TOKEN_RAW_EMPTY)
        assert t.pending_deposit_transfer_cids == []
        assert t.pending_withdraw_transfer_cids == []
        assert t.expired_allocation_cids == []
        assert t.locked_amount == Decimal("0")

    def test_frozen(self):
        t = TokenBalance._from_raw(SAMPLE_TOKEN_RAW)
        with pytest.raises(AttributeError):
            t.instrument = "nope"


class TestAccountInfo:
    def test_from_raw(self):
        raw = {
            "party_id": {"address": "Cantex::1220abc"},
            "user_id": "uid-42",
            "tokens": [SAMPLE_TOKEN_RAW, SAMPLE_TOKEN_RAW_EMPTY],
        }
        info = AccountInfo._from_raw(raw)
        assert info.address == "Cantex::1220abc"
        assert info.user_id == "uid-42"
        assert len(info.tokens) == 2
        assert info.tokens[0].instrument.id == "USDC"
        assert info.tokens[1].instrument.id == "BTC"

    def test_get_balance_found(self):
        info = AccountInfo._from_raw({"tokens": [SAMPLE_TOKEN_RAW]})
        assert info.get_balance(InstrumentId(id="USDC", admin="admin::usdc")) == Decimal("1234.56")

    def test_get_balance_not_found(self):
        info = AccountInfo._from_raw({"tokens": [SAMPLE_TOKEN_RAW]})
        assert info.get_balance(InstrumentId(id="ETH", admin="admin::eth")) == Decimal(0)

    def test_expired_transfer_cids(self):
        info = AccountInfo._from_raw(
            {"tokens": [SAMPLE_TOKEN_RAW, SAMPLE_TOKEN_RAW_EMPTY]},
        )
        assert info.expired_transfer_cids == ["tx-001", "tx-002"]

    def test_expired_allocation_cids(self):
        info = AccountInfo._from_raw(
            {"tokens": [SAMPLE_TOKEN_RAW, SAMPLE_TOKEN_RAW_EMPTY]},
        )
        assert info.expired_allocation_cids == ["alloc-001"]

    def test_empty_tokens(self):
        info = AccountInfo._from_raw({"tokens": []})
        assert info.address == ""
        assert info.user_id == ""
        assert info.get_balance(InstrumentId(id="USDC", admin="admin")) == Decimal(0)
        assert info.expired_transfer_cids == []
        assert info.expired_allocation_cids == []


class TestInstrumentInfo:
    def test_from_raw(self):
        raw = {
            "instrument_id": "Amulet",
            "instrument_admin": "DSO::1220abc",
            "instrument_name": "Canton Coin",
            "instrument_symbol": "CC",
        }
        info = InstrumentInfo._from_raw(raw)
        assert info.instrument.id == "Amulet"
        assert info.instrument.admin == "DSO::1220abc"
        assert info.instrument_name == "Canton Coin"
        assert info.instrument_symbol == "CC"

    def test_frozen(self):
        raw = {
            "instrument_id": "X",
            "instrument_admin": "A",
            "instrument_name": "N",
            "instrument_symbol": "S",
        }
        info = InstrumentInfo._from_raw(raw)
        with pytest.raises(AttributeError):
            info.instrument = "nope"


SAMPLE_ADMIN_RAW = {
    "party_id": {
        "address": "Cantex::1220abc",
        "contracts": {
            "merge_delegation": None,
            "pool_intent_account": {"contract_id": "ia-1"},
            "pool_trading_account": {"contract_id": "ta-1"},
        },
        "status": "success",
    },
    "tokens": [
        {
            "contracts": {"transfer_preapproval": None},
            "instrument_admin": "DSO::1220abc",
            "instrument_id": "Amulet",
            "instrument_name": "Canton Coin",
            "instrument_symbol": "CC",
        },
        {
            "contracts": {"transfer_preapproval": None},
            "instrument_admin": "usdc-rep::1220def",
            "instrument_id": "USDCx",
            "instrument_name": "USDCx",
            "instrument_symbol": "USDCx",
        },
    ],
    "user_id": "test-user-id",
}


class TestAccountAdmin:
    def test_from_raw_full(self):
        admin = AccountAdmin._from_raw(SAMPLE_ADMIN_RAW)
        assert admin.address == "Cantex::1220abc"
        assert admin.user_id == "test-user-id"
        assert admin.has_intent_account
        assert admin.has_trading_account
        assert admin.intent_account == {"contract_id": "ia-1"}
        assert admin.trading_account == {"contract_id": "ta-1"}
        assert len(admin.instruments) == 2
        assert admin.instruments[0].instrument.id == "Amulet"
        assert admin.instruments[0].instrument_symbol == "CC"
        assert admin.instruments[1].instrument.id == "USDCx"

    def test_from_raw_no_accounts(self):
        admin = AccountAdmin._from_raw(
            {"party_id": {"contracts": {}}, "tokens": []},
        )
        assert not admin.has_intent_account
        assert not admin.has_trading_account
        assert admin.instruments == []
        assert admin.address == ""
        assert admin.user_id == ""

    def test_from_raw_missing_keys(self):
        admin = AccountAdmin._from_raw({})
        assert not admin.has_intent_account
        assert not admin.has_trading_account
        assert admin.instruments == []


# ===================================================================
# Response models — Pool & quote
# ===================================================================


SAMPLE_POOL_RAW = {
    "contract_id": "pool-abc",
    "token_a_instrument_id": "USDC",
    "token_a_instrument_admin": "admin::usdc",
    "token_b_instrument_id": "BTC",
    "token_b_instrument_admin": "admin::btc",
}


class TestPool:
    def test_from_raw(self):
        p = Pool._from_raw(SAMPLE_POOL_RAW)
        assert p.contract_id == "pool-abc"
        assert p.token_a.id == "USDC"
        assert p.token_a.admin == "admin::usdc"
        assert p.token_b.id == "BTC"
        assert p.token_b.admin == "admin::btc"

    def test_frozen(self):
        p = Pool._from_raw(SAMPLE_POOL_RAW)
        with pytest.raises(AttributeError):
            p.contract_id = "nope"


class TestPoolsInfo:
    def test_from_raw(self):
        raw = {"pools": [SAMPLE_POOL_RAW]}
        info = PoolsInfo._from_raw(raw)
        assert len(info.pools) == 1
        assert info.pools[0].contract_id == "pool-abc"

    def test_get_pool_found(self):
        info = PoolsInfo._from_raw({"pools": [SAMPLE_POOL_RAW]})
        pool = info.get_pool("pool-abc")
        assert pool.token_a.id == "USDC"

    def test_get_pool_not_found(self):
        info = PoolsInfo._from_raw({"pools": [SAMPLE_POOL_RAW]})
        with pytest.raises(ValueError, match="pool-xyz"):
            info.get_pool("pool-xyz")

    def test_empty_pools(self):
        info = PoolsInfo._from_raw({"pools": []})
        assert info.pools == []
        with pytest.raises(ValueError):
            info.get_pool("any")


SAMPLE_QUOTE_RAW = {
    "estimated_time_seconds": "4.72",
    "fees": {
        "amount_admin": "0.0000500000",
        "amount_liquidity": "0.0004500000",
        "fee_percentage": "0.0005000000",
        "instrument_admin": "DSO::1220abc",
        "instrument_id": "Amulet",
        "network_fee": {
            "amount": "0.1000",
            "instrument_admin": "DSO::1220abc",
            "instrument_id": "Amulet",
        },
    },
    "pool_price_after_trade": "0.1548223373",
    "pool_price_before_trade": "0.1548228128",
    "pool_size": {
        "amount": "1301596.7091451541",
        "instrument_admin": "DSO::1220abc",
        "instrument_id": "Amulet",
    },
    "pools": [
        {
            "buy": {
                "amount": "51.6618488092",
                "instrument_admin": "DSO::1220abc",
                "instrument_id": "Amulet",
            },
            "contract_id": "pool-contract-001",
            "fees": {
                "admin": {
                    "amount": "0.0003685538",
                    "instrument_admin": "usdc-rep::1220def",
                    "instrument_id": "USDCx",
                },
                "fee_percentage": "0.0005000000",
                "liquidity": {
                    "amount": "0.0033169843",
                    "instrument_admin": "usdc-rep::1220def",
                    "instrument_id": "USDCx",
                },
            },
            "pool_id": "2820898830768735469",
            "pool_price_after": "0.1426125549",
            "pool_price_before": "0.1426033624",
            "prices": {
                "pool_after": "7.0120053636",
                "pool_before": "7.0124573744",
                "slippage": "0.0000322297",
                "trade": "7.0087252497",
                "trade_no_fees": "7.0122313653",
            },
            "sell": {
                "amount": "7.3710763325",
                "instrument_admin": "usdc-rep::1220def",
                "instrument_id": "USDCx",
            },
            "size": {
                "amount": "3205755.1364746202",
                "instrument_admin": "DSO::1220abc",
                "instrument_id": "Amulet",
            },
            "trade_price": "0.1426792982",
            "trade_price_no_fees": "0.1426079586",
        },
    ],
    "prices": {
        "pool_after": "0.1548223373",
        "pool_before": "0.1548228128",
        "slippage": "0.0000015358",
        "trade": "0.1548225750",
        "trade_no_fees": "0.1548226500",
    },
    "returned": {
        "amount": "0.1547451638",
        "instrument_admin": "usdc-rep::1220def",
        "instrument_id": "USDCx",
    },
    "sent": {
        "buy_instrument_admin": "usdc-rep::1220def",
        "buy_instrument_id": "USDCx",
        "sell_amount": "1",
        "sell_instrument_admin": "DSO::1220abc",
        "sell_instrument_id": "Amulet",
    },
    "slippage": "0.0000015358",
    "trade_price": "0.1548225750",
}


class TestQuoteLeg:
    def test_from_raw(self):
        raw = {
            "amount": "99.5",
            "instrument_id": "USDCx",
            "instrument_admin": "admin::usdc",
        }
        leg = QuoteLeg._from_raw(raw)
        assert leg.amount == Decimal("99.5")
        assert leg.instrument.id == "USDCx"
        assert leg.instrument.admin == "admin::usdc"

    def test_frozen(self):
        leg = QuoteLeg._from_raw(
            {"amount": "1", "instrument_id": "X", "instrument_admin": "A"},
        )
        with pytest.raises(AttributeError):
            leg.amount = Decimal("2")


class TestQuoteFees:
    def test_from_raw(self):
        fees = QuoteFees._from_raw(SAMPLE_QUOTE_RAW["fees"])
        assert fees.fee_percentage == Decimal("0.0005000000")
        assert fees.amount_admin == Decimal("0.0000500000")
        assert fees.amount_liquidity == Decimal("0.0004500000")
        assert fees.instrument.id == "Amulet"
        assert isinstance(fees.network_fee, QuoteLeg)
        assert fees.network_fee.amount == Decimal("0.1000")


class TestSwapQuote:
    def test_from_raw(self):
        q = SwapQuote._from_raw(SAMPLE_QUOTE_RAW)
        assert q.estimated_time_seconds == Decimal("4.72")
        assert q.sell_amount == Decimal("1")
        assert q.sell_instrument.id == "Amulet"
        assert q.buy_instrument.id == "USDCx"

    def test_deprecated_fields(self):
        q = SwapQuote._from_raw(SAMPLE_QUOTE_RAW)
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            assert q.trade_price == Decimal("0.1548225750")
            assert q.slippage == Decimal("0.0000015358")
            assert q.pool_price_before_trade == Decimal("0.1548228128")
            assert q.pool_price_after_trade == Decimal("0.1548223373")
            assert len(w) == 4
            assert all(issubclass(x.category, DeprecationWarning) for x in w)

    def test_returned_amount_property(self):
        q = SwapQuote._from_raw(SAMPLE_QUOTE_RAW)
        assert q.returned_amount == Decimal("0.1547451638")
        assert q.returned_amount == q.returned.amount
        assert q.returned.instrument.id == "USDCx"

    def test_pool_size(self):
        q = SwapQuote._from_raw(SAMPLE_QUOTE_RAW)
        assert q.pool_size.amount == Decimal("1301596.7091451541")
        assert q.pool_size.instrument.id == "Amulet"

    def test_fees(self):
        q = SwapQuote._from_raw(SAMPLE_QUOTE_RAW)
        assert isinstance(q.fees, QuoteFees)
        assert q.fees.fee_percentage == Decimal("0.0005000000")
        assert q.fees.network_fee.amount == Decimal("0.1000")

    def test_prices(self):
        q = SwapQuote._from_raw(SAMPLE_QUOTE_RAW)
        assert isinstance(q.prices, QuotePrices)
        assert q.prices.pool_after == Decimal("0.1548223373")
        assert q.prices.pool_before == Decimal("0.1548228128")
        assert q.prices.slippage == Decimal("0.0000015358")
        assert q.prices.trade == Decimal("0.1548225750")
        assert q.prices.trade_no_fees == Decimal("0.1548226500")

    def test_pools(self):
        q = SwapQuote._from_raw(SAMPLE_QUOTE_RAW)
        assert len(q.pools) == 1
        pool = q.pools[0]
        assert isinstance(pool, QuotePoolDetail)
        assert pool.contract_id == "pool-contract-001"
        assert pool.pool_id == "2820898830768735469"
        assert pool.buy.amount == Decimal("51.6618488092")
        assert pool.sell.instrument.id == "USDCx"
        assert pool.trade_price == Decimal("0.1426792982")
        assert pool.trade_price_no_fees == Decimal("0.1426079586")
        assert isinstance(pool.fees, QuotePoolFees)
        assert pool.fees.admin.amount == Decimal("0.0003685538")
        assert isinstance(pool.prices, QuotePrices)
        assert pool.prices.trade == Decimal("7.0087252497")

    def test_frozen(self):
        q = SwapQuote._from_raw(SAMPLE_QUOTE_RAW)
        with pytest.raises(AttributeError):
            q.estimated_time_seconds = Decimal("2.0")


class TestQuotePrices:
    def test_from_raw(self):
        raw = {
            "pool_after": "7.0120053636",
            "pool_before": "7.0124573744",
            "slippage": "0.0000322297",
            "trade": "7.0087252497",
            "trade_no_fees": "7.0122313653",
        }
        prices = QuotePrices._from_raw(raw)
        assert prices.pool_after == Decimal("7.0120053636")
        assert prices.pool_before == Decimal("7.0124573744")
        assert prices.slippage == Decimal("0.0000322297")
        assert prices.trade == Decimal("7.0087252497")
        assert prices.trade_no_fees == Decimal("7.0122313653")

    def test_frozen(self):
        prices = QuotePrices._from_raw({
            "pool_after": "1", "pool_before": "2",
            "slippage": "0", "trade": "3", "trade_no_fees": "4",
        })
        with pytest.raises(AttributeError):
            prices.trade = Decimal("0")


class TestQuotePoolFees:
    def test_from_raw(self):
        raw = SAMPLE_QUOTE_RAW["pools"][0]["fees"]
        fees = QuotePoolFees._from_raw(raw)
        assert fees.fee_percentage == Decimal("0.0005000000")
        assert isinstance(fees.admin, QuoteLeg)
        assert fees.admin.amount == Decimal("0.0003685538")
        assert fees.admin.instrument.id == "USDCx"
        assert isinstance(fees.liquidity, QuoteLeg)
        assert fees.liquidity.amount == Decimal("0.0033169843")
        assert fees.liquidity.instrument.id == "USDCx"

    def test_frozen(self):
        raw = SAMPLE_QUOTE_RAW["pools"][0]["fees"]
        fees = QuotePoolFees._from_raw(raw)
        with pytest.raises(AttributeError):
            fees.fee_percentage = Decimal("1")


class TestQuotePoolDetail:
    def test_from_raw(self):
        raw = SAMPLE_QUOTE_RAW["pools"][0]
        pool = QuotePoolDetail._from_raw(raw)
        assert pool.contract_id == "pool-contract-001"
        assert pool.pool_id == "2820898830768735469"
        assert pool.buy.amount == Decimal("51.6618488092")
        assert pool.buy.instrument.id == "Amulet"
        assert pool.sell.amount == Decimal("7.3710763325")
        assert pool.sell.instrument.id == "USDCx"
        assert pool.pool_price_after == Decimal("0.1426125549")
        assert pool.pool_price_before == Decimal("0.1426033624")
        assert pool.trade_price == Decimal("0.1426792982")
        assert pool.trade_price_no_fees == Decimal("0.1426079586")
        assert pool.size.amount == Decimal("3205755.1364746202")
        assert pool.size.instrument.id == "Amulet"
        assert isinstance(pool.fees, QuotePoolFees)
        assert isinstance(pool.prices, QuotePrices)

    def test_frozen(self):
        raw = SAMPLE_QUOTE_RAW["pools"][0]
        pool = QuotePoolDetail._from_raw(raw)
        with pytest.raises(AttributeError):
            pool.trade_price = Decimal("0")


# ===================================================================
# WebSocket — Event models
# ===================================================================


SAMPLE_WS_SWAP_PENDING_RAW = {
    "category": "trading",
    "created_at": "2026-04-07T05:57:54.896253+00:00",
    "data": {
        "created_at": "2026-04-07T05:57:54.899210+00:00",
        "id": "8c8ad51f-2c8b-486f-bd3d-6a2b0e66f986",
        "input_instrument_id": {
            "admin": "usdc-rep::1220abc",
            "id": "USDCx",
        },
        "output_instrument_id": {
            "admin": "DSO::1220def",
            "id": "Amulet",
        },
        "sender": "Cantex::1220sender",
    },
    "event_id": "b8b7f7c2-4fe8-4549-9001-8dd4fd8c5f2f",
    "severity": "info",
    "source": "ledger",
    "type": "Pool.SwapPending",
    "user_id": "uid-1",
    "wallet_address": "Cantex::1220wallet",
}

SAMPLE_WS_SWAP_EXECUTED_RAW = {
    "category": "trading",
    "created_at": "2026-04-07T05:58:04.353447+00:00",
    "data": {
        "ledger_created_at": "2026-04-07T05:57:58.790361+00:00",
        "swap_details": {
            "admin_fee_amount": "0.0005538314",
            "input_amount": "11.0766285914",
            "input_instrument_id": {"admin": "usdc-rep::1220abc", "id": "USDCx"},
            "liquidity_fee_amount": "0.0049844829",
            "output_amount": "74.8590517011",
            "output_instrument_id": {"admin": "DSO::1220def", "id": "Amulet"},
        },
        "ticker": {
            "market": "CC-USDC",
            "price": "0.14815",
            "ts": 1775541451587,
        },
    },
    "event_id": "bc324667-38fd-4fb8-8bdc-998472fbc802",
    "severity": "info",
    "source": "ledger",
    "type": "Pool.SwapExecuted",
    "user_id": "uid-1",
    "wallet_address": "Cantex::1220wallet",
}

SAMPLE_WS_SWAP_FAILED_RAW = {
    "category": "trading",
    "created_at": "2026-04-07T06:00:00+00:00",
    "data": {
        "id": "fail-swap-id",
        "input_instrument_id": {"admin": "usdc-rep::1220abc", "id": "USDCx"},
        "output_instrument_id": {"admin": "DSO::1220def", "id": "Amulet"},
        "sender": "Cantex::1220sender",
        "details": {"error": "insufficient balance"},
    },
    "event_id": "ev-fail-1",
    "severity": "error",
    "source": "ledger",
    "type": "Pool.SwapFailed",
    "user_id": "uid-1",
    "wallet_address": "Cantex::1220wallet",
}

SAMPLE_WS_DEPOSIT_PENDING_RAW = {
    "category": "funding",
    "created_at": "2026-04-07T06:01:00+00:00",
    "data": {
        "amount": "100.5",
        "instrument_id": "USDCx",
        "instrument_admin": "usdc-rep::1220abc",
        "sender": "External::1220ext",
        "receiver": "Cantex::1220wallet",
        "ledger_created_at": "2026-04-07T06:01:01+00:00",
        "execute_before": "2026-04-07T06:11:00+00:00",
        "requested_at": "2026-04-07T06:00:59+00:00",
    },
    "event_id": "ev-dep-pend-1",
    "severity": "info",
    "source": "ledger",
    "type": "Funding.DepositPending",
    "user_id": "uid-1",
    "wallet_address": "Cantex::1220wallet",
}

SAMPLE_WS_DEPOSIT_CONFIRMED_RAW = {
    "category": "funding",
    "created_at": "2026-04-07T06:02:00+00:00",
    "data": {
        "amount": "100.5",
        "instrument_id": "USDCx",
        "instrument_admin": "usdc-rep::1220abc",
        "sender": "External::1220ext",
        "receiver": "Cantex::1220wallet",
        "ledger_created_at": "2026-04-07T06:02:01+00:00",
    },
    "event_id": "ev-dep-conf-1",
    "severity": "info",
    "source": "ledger",
    "type": "Funding.DepositConfirmed",
    "user_id": "uid-1",
    "wallet_address": "Cantex::1220wallet",
}

SAMPLE_WS_DEPOSIT_REJECTED_RAW = {
    "category": "funding",
    "created_at": "2026-04-07T06:03:00+00:00",
    "data": {
        "amount": "50.0",
        "instrument_id": "Amulet",
        "instrument_admin": "DSO::1220def",
        "sender": "External::1220ext",
        "receiver": "Cantex::1220wallet",
        "ledger_created_at": "2026-04-07T06:03:01+00:00",
    },
    "event_id": "ev-dep-rej-1",
    "severity": "warning",
    "source": "ledger",
    "type": "Funding.DepositRejected",
    "user_id": "uid-1",
    "wallet_address": "Cantex::1220wallet",
}

SAMPLE_WS_WITHDRAWAL_REQUESTED_RAW = {
    "category": "funding",
    "created_at": "2026-04-07T06:04:00+00:00",
    "data": {
        "amount": "200.0",
        "instrument_id": "USDCx",
        "instrument_admin": "usdc-rep::1220abc",
        "sender": "Cantex::1220wallet",
        "receiver": "External::1220ext",
        "ledger_created_at": "2026-04-07T06:04:01+00:00",
        "execute_before": "2026-04-07T06:14:00+00:00",
        "requested_at": "2026-04-07T06:03:59+00:00",
    },
    "event_id": "ev-wd-req-1",
    "severity": "info",
    "source": "ledger",
    "type": "Funding.WithdrawalRequested",
    "user_id": "uid-1",
    "wallet_address": "Cantex::1220wallet",
}

SAMPLE_WS_WITHDRAWAL_COMPLETED_RAW = {
    "category": "funding",
    "created_at": "2026-04-07T06:05:00+00:00",
    "data": {
        "amount": "200.0",
        "instrument_id": "USDCx",
        "instrument_admin": "usdc-rep::1220abc",
        "sender": "Cantex::1220wallet",
        "receiver": "External::1220ext",
        "ledger_created_at": "2026-04-07T06:05:01+00:00",
    },
    "event_id": "ev-wd-comp-1",
    "severity": "info",
    "source": "ledger",
    "type": "Funding.WithdrawalCompleted",
    "user_id": "uid-1",
    "wallet_address": "Cantex::1220wallet",
}

SAMPLE_WS_WITHDRAWAL_FAILED_RAW = {
    "category": "funding",
    "created_at": "2026-04-07T06:06:00+00:00",
    "data": {
        "amount": "200.0",
        "instrument_id": "USDCx",
        "instrument_admin": "usdc-rep::1220abc",
        "sender": "Cantex::1220wallet",
        "receiver": "External::1220ext",
        "ledger_created_at": "2026-04-07T06:06:01+00:00",
    },
    "event_id": "ev-wd-fail-1",
    "severity": "error",
    "source": "ledger",
    "type": "Funding.WithdrawalFailed",
    "user_id": "uid-1",
    "wallet_address": "Cantex::1220wallet",
}


class TestWsEventParsing:
    def test_parse_swap_pending(self):
        event = _parse_ws_event(SAMPLE_WS_SWAP_PENDING_RAW)
        assert isinstance(event, SwapPendingEvent)
        assert event.event_type == "Pool.SwapPending"
        assert event.category == "trading"
        assert event.event_id == "b8b7f7c2-4fe8-4549-9001-8dd4fd8c5f2f"
        assert event.severity == "info"
        assert event.source == "ledger"
        assert event.user_id == "uid-1"
        assert event.wallet_address == "Cantex::1220wallet"
        assert event.swap_id == "8c8ad51f-2c8b-486f-bd3d-6a2b0e66f986"
        assert event.input_instrument.id == "USDCx"
        assert event.input_instrument.admin == "usdc-rep::1220abc"
        assert event.output_instrument.id == "Amulet"
        assert event.output_instrument.admin == "DSO::1220def"
        assert event.sender == "Cantex::1220sender"
        assert event.raw is SAMPLE_WS_SWAP_PENDING_RAW

    def test_parse_swap_executed(self):
        event = _parse_ws_event(SAMPLE_WS_SWAP_EXECUTED_RAW)
        assert isinstance(event, SwapExecutedEvent)
        assert event.event_type == "Pool.SwapExecuted"
        assert event.input_amount == Decimal("11.0766285914")
        assert event.input_instrument.id == "USDCx"
        assert event.output_amount == Decimal("74.8590517011")
        assert event.output_instrument.id == "Amulet"
        assert event.admin_fee_amount == Decimal("0.0005538314")
        assert event.liquidity_fee_amount == Decimal("0.0049844829")
        assert event.market == "CC-USDC"
        assert event.price == Decimal("0.14815")
        assert event.ticker_ts == 1775541451587
        assert event.ledger_created_at == "2026-04-07T05:57:58.790361+00:00"

    def test_parse_swap_failed(self):
        event = _parse_ws_event(SAMPLE_WS_SWAP_FAILED_RAW)
        assert isinstance(event, SwapFailedEvent)
        assert event.event_type == "Pool.SwapFailed"
        assert event.swap_id == "fail-swap-id"
        assert event.error == "insufficient balance"
        assert event.input_instrument.id == "USDCx"
        assert event.output_instrument.id == "Amulet"
        assert event.sender == "Cantex::1220sender"

    def test_parse_deposit_pending(self):
        event = _parse_ws_event(SAMPLE_WS_DEPOSIT_PENDING_RAW)
        assert isinstance(event, DepositPendingEvent)
        assert isinstance(event, FundingEvent)
        assert event.event_type == "Funding.DepositPending"
        assert event.amount == Decimal("100.5")
        assert event.instrument.id == "USDCx"
        assert event.instrument.admin == "usdc-rep::1220abc"
        assert event.sender == "External::1220ext"
        assert event.receiver == "Cantex::1220wallet"
        assert event.ledger_created_at == "2026-04-07T06:01:01+00:00"
        assert event.execute_before == "2026-04-07T06:11:00+00:00"
        assert event.requested_at == "2026-04-07T06:00:59+00:00"

    def test_parse_deposit_confirmed(self):
        event = _parse_ws_event(SAMPLE_WS_DEPOSIT_CONFIRMED_RAW)
        assert isinstance(event, DepositConfirmedEvent)
        assert isinstance(event, FundingEvent)
        assert event.event_type == "Funding.DepositConfirmed"
        assert event.amount == Decimal("100.5")

    def test_parse_deposit_rejected(self):
        event = _parse_ws_event(SAMPLE_WS_DEPOSIT_REJECTED_RAW)
        assert isinstance(event, DepositRejectedEvent)
        assert isinstance(event, FundingEvent)
        assert event.event_type == "Funding.DepositRejected"
        assert event.amount == Decimal("50.0")
        assert event.instrument.id == "Amulet"

    def test_parse_withdrawal_requested(self):
        event = _parse_ws_event(SAMPLE_WS_WITHDRAWAL_REQUESTED_RAW)
        assert isinstance(event, WithdrawalRequestedEvent)
        assert isinstance(event, FundingEvent)
        assert event.event_type == "Funding.WithdrawalRequested"
        assert event.amount == Decimal("200.0")
        assert event.execute_before == "2026-04-07T06:14:00+00:00"
        assert event.requested_at == "2026-04-07T06:03:59+00:00"

    def test_parse_withdrawal_completed(self):
        event = _parse_ws_event(SAMPLE_WS_WITHDRAWAL_COMPLETED_RAW)
        assert isinstance(event, WithdrawalCompletedEvent)
        assert isinstance(event, FundingEvent)
        assert event.event_type == "Funding.WithdrawalCompleted"

    def test_parse_withdrawal_failed(self):
        event = _parse_ws_event(SAMPLE_WS_WITHDRAWAL_FAILED_RAW)
        assert isinstance(event, WithdrawalFailedEvent)
        assert isinstance(event, FundingEvent)
        assert event.event_type == "Funding.WithdrawalFailed"

    def test_parse_unknown_event_type(self):
        raw = {
            "type": "Unknown.EventType",
            "category": "other",
            "event_id": "ev-unknown",
            "severity": "info",
            "source": "system",
            "user_id": "uid-2",
            "wallet_address": "Cantex::1220other",
            "created_at": "2026-04-07T07:00:00+00:00",
            "data": {"custom_field": "custom_value"},
        }
        event = _parse_ws_event(raw)
        assert type(event) is WsEvent
        assert event.event_type == "Unknown.EventType"
        assert event.data == {"custom_field": "custom_value"}

    def test_frozen_swap_pending(self):
        event = _parse_ws_event(SAMPLE_WS_SWAP_PENDING_RAW)
        with pytest.raises(AttributeError):
            event.swap_id = "new-id"

    def test_frozen_swap_executed(self):
        event = _parse_ws_event(SAMPLE_WS_SWAP_EXECUTED_RAW)
        with pytest.raises(AttributeError):
            event.input_amount = Decimal("0")

    def test_frozen_funding(self):
        event = _parse_ws_event(SAMPLE_WS_DEPOSIT_PENDING_RAW)
        with pytest.raises(AttributeError):
            event.amount = Decimal("0")

    def test_frozen_base(self):
        event = _parse_ws_event({"type": "X", "data": {}})
        with pytest.raises(AttributeError):
            event.event_type = "Y"


# ===================================================================
# WebSocket — Client
# ===================================================================


def _make_ws_msg(msg_type, data):
    """Create an aiohttp.WSMessage for testing."""
    return aiohttp.WSMessage(msg_type, data, None)


def _mock_raw_ws(messages):
    """Create a mock ClientWebSocketResponse that yields the given messages."""
    mock_ws = AsyncMock(spec=aiohttp.ClientWebSocketResponse)
    mock_ws.receive = AsyncMock(side_effect=messages)
    mock_ws.closed = False
    mock_ws.close = AsyncMock()
    mock_ws.send_json = AsyncMock()
    mock_ws.exception = lambda: Exception("ws error")
    return mock_ws


@pytest.mark.asyncio
class TestCantexWebSocket:
    async def test_text_message_yields_event(self):
        raw = _mock_raw_ws([
            _make_ws_msg(aiohttp.WSMsgType.TEXT, json.dumps(SAMPLE_WS_SWAP_PENDING_RAW)),
        ])
        ws = CantexWebSocket(raw)
        event = await ws.__anext__()
        assert isinstance(event, SwapPendingEvent)
        assert event.swap_id == "8c8ad51f-2c8b-486f-bd3d-6a2b0e66f986"

    async def test_binary_message_yields_event(self):
        raw = _mock_raw_ws([
            _make_ws_msg(
                aiohttp.WSMsgType.BINARY,
                json.dumps(SAMPLE_WS_SWAP_EXECUTED_RAW).encode(),
            ),
        ])
        ws = CantexWebSocket(raw)
        event = await ws.__anext__()
        assert isinstance(event, SwapExecutedEvent)
        assert event.price == Decimal("0.14815")

    async def test_ping_sends_pong_and_continues(self):
        ping_msg = _make_ws_msg(
            aiohttp.WSMsgType.TEXT, json.dumps({"op": "ping"}),
        )
        event_msg = _make_ws_msg(
            aiohttp.WSMsgType.TEXT, json.dumps(SAMPLE_WS_SWAP_PENDING_RAW),
        )
        raw = _mock_raw_ws([ping_msg, event_msg])
        ws = CantexWebSocket(raw)
        event = await ws.__anext__()
        raw.send_json.assert_awaited_once_with({"op": "pong"})
        assert isinstance(event, SwapPendingEvent)

    async def test_invalid_json_raises_cantex_error(self):
        raw = _mock_raw_ws([
            _make_ws_msg(aiohttp.WSMsgType.TEXT, "not valid json{"),
        ])
        ws = CantexWebSocket(raw)
        with pytest.raises(CantexError, match="Invalid JSON"):
            await ws.__anext__()

    async def test_invalid_binary_raises_cantex_error(self):
        raw = _mock_raw_ws([
            _make_ws_msg(aiohttp.WSMsgType.BINARY, b"\xff\xfe"),
        ])
        ws = CantexWebSocket(raw)
        with pytest.raises(CantexError, match="non-JSON binary"):
            await ws.__anext__()

    async def test_close_stops_iteration_no_reconnect(self):
        raw = _mock_raw_ws([
            _make_ws_msg(aiohttp.WSMsgType.CLOSE, None),
        ])
        ws = CantexWebSocket(raw, reconnect=None)
        with pytest.raises(StopAsyncIteration):
            await ws.__anext__()

    async def test_close_stops_iteration_user_closed(self):
        raw = _mock_raw_ws([
            _make_ws_msg(aiohttp.WSMsgType.CLOSE, None),
        ])
        reconnect_fn = AsyncMock()
        ws = CantexWebSocket(raw, reconnect=reconnect_fn)
        ws._closed_by_user = True
        with pytest.raises(StopAsyncIteration):
            await ws.__anext__()
        reconnect_fn.assert_not_awaited()

    async def test_close_reconnects_when_fn_provided(self):
        new_raw = _mock_raw_ws([
            _make_ws_msg(aiohttp.WSMsgType.TEXT, json.dumps(SAMPLE_WS_SWAP_PENDING_RAW)),
        ])
        reconnect_fn = AsyncMock(return_value=new_raw)
        old_raw = _mock_raw_ws([
            _make_ws_msg(aiohttp.WSMsgType.CLOSE, 1006),
        ])
        ws = CantexWebSocket(
            old_raw,
            reconnect=reconnect_fn,
            max_reconnects=3,
            reconnect_base_delay=0.0,
        )
        event = await ws.__anext__()
        reconnect_fn.assert_awaited_once()
        assert isinstance(event, SwapPendingEvent)

    async def test_error_reconnects(self):
        new_raw = _mock_raw_ws([
            _make_ws_msg(aiohttp.WSMsgType.TEXT, json.dumps(SAMPLE_WS_SWAP_EXECUTED_RAW)),
        ])
        reconnect_fn = AsyncMock(return_value=new_raw)
        old_raw = _mock_raw_ws([
            _make_ws_msg(aiohttp.WSMsgType.ERROR, None),
        ])
        old_raw.exception = lambda: Exception("transport error")
        ws = CantexWebSocket(
            old_raw,
            reconnect=reconnect_fn,
            max_reconnects=3,
            reconnect_base_delay=0.0,
        )
        event = await ws.__anext__()
        reconnect_fn.assert_awaited_once()
        assert isinstance(event, SwapExecutedEvent)

    async def test_error_no_reconnect_raises(self):
        raw = _mock_raw_ws([
            _make_ws_msg(aiohttp.WSMsgType.ERROR, None),
        ])
        raw.exception = lambda: Exception("transport error")
        ws = CantexWebSocket(raw, reconnect=None)
        with pytest.raises(CantexError, match="WebSocket error"):
            await ws.__anext__()

    async def test_reconnect_exhausted_raises(self):
        old_raw = _mock_raw_ws([
            _make_ws_msg(aiohttp.WSMsgType.CLOSE, 1006),
        ])
        reconnect_fn = AsyncMock(
            side_effect=aiohttp.ClientConnectionError("refused"),
        )
        ws = CantexWebSocket(
            old_raw,
            reconnect=reconnect_fn,
            max_reconnects=2,
            reconnect_base_delay=0.0,
        )
        with pytest.raises(CantexError, match="reconnection failed after 2"):
            await ws.__anext__()
        assert reconnect_fn.await_count == 2

    async def test_user_close(self):
        raw = _mock_raw_ws([])
        ws = CantexWebSocket(raw)
        assert not ws._closed_by_user
        await ws.close()
        assert ws._closed_by_user
        raw.close.assert_awaited_once()

    async def test_close_idempotent(self):
        raw = _mock_raw_ws([])
        raw.closed = False
        ws = CantexWebSocket(raw)
        await ws.close()
        raw.closed = True
        await ws.close()
        raw.close.assert_awaited_once()

    async def test_closed_property(self):
        raw = _mock_raw_ws([])
        raw.closed = False
        ws = CantexWebSocket(raw)
        assert not ws.closed
        raw.closed = True
        assert ws.closed

    async def test_context_manager(self):
        raw = _mock_raw_ws([])
        ws = CantexWebSocket(raw)
        async with ws as ctx:
            assert ctx is ws
        raw.close.assert_awaited_once()

    async def test_reconnect_without_fn_raises_runtime_error(self):
        raw = _mock_raw_ws([])
        ws = CantexWebSocket(raw, reconnect=None)
        with pytest.raises(RuntimeError, match="reconnect function"):
            await ws._reconnect()


@pytest.mark.asyncio
class TestWebSocketConnect:
    async def test_async_context_manager(self):
        raw = _mock_raw_ws([])
        inner_ws = CantexWebSocket(raw)

        async def coro():
            return inner_ws

        connect = _WebSocketConnect(coro())
        async with connect as ws:
            assert ws is inner_ws
        raw.close.assert_awaited_once()

    async def test_await(self):
        raw = _mock_raw_ws([])
        inner_ws = CantexWebSocket(raw)

        async def coro():
            return inner_ws

        connect = _WebSocketConnect(coro())
        ws = await connect
        assert ws is inner_ws


# ===================================================================
# WebSocket — SDK integration & swap_and_confirm
# ===================================================================


@pytest.mark.asyncio
class TestSDKWebSocketMethods:
    async def test_ws_base_url_https(self, operator):
        sdk = CantexSDK(
            operator, base_url="https://api.cantex.io", api_key_path=None,
        )
        assert sdk._ws_base_url == "wss://api.cantex.io"
        await sdk.close()

    async def test_ws_base_url_http(self, operator):
        sdk = CantexSDK(
            operator, base_url="http://localhost:8080", api_key_path=None,
        )
        assert sdk._ws_base_url == "ws://localhost:8080"
        await sdk.close()

    async def test_connect_public_ws_url(self, authed_sdk):
        mock_raw_ws = _mock_raw_ws([])
        with patch.object(
            aiohttp.ClientSession, "ws_connect",
            new_callable=AsyncMock, return_value=mock_raw_ws,
        ) as mock_connect:
            ws = await authed_sdk.connect_public_ws()
            mock_connect.assert_awaited_once()
            call_args = mock_connect.call_args
            assert "/v1/ws/public" in call_args[0][0]
            assert call_args[1].get("headers") == {}
            await ws.close()
        await authed_sdk.close()

    async def test_connect_private_ws_url(self, authed_sdk):
        mock_raw_ws = _mock_raw_ws([])
        with patch.object(
            aiohttp.ClientSession, "ws_connect",
            new_callable=AsyncMock, return_value=mock_raw_ws,
        ) as mock_connect:
            ws = await authed_sdk.connect_private_ws()
            mock_connect.assert_awaited_once()
            call_args = mock_connect.call_args
            assert "/v1/ws/private" in call_args[0][0]
            headers = call_args[1].get("headers", {})
            assert "Authorization" in headers
            assert headers["Authorization"] == "Bearer test-api-key"
            await ws.close()
        await authed_sdk.close()

    async def test_close_cleans_up_websockets(self, authed_sdk):
        mock_raw_ws = _mock_raw_ws([])
        with patch.object(
            aiohttp.ClientSession, "ws_connect",
            new_callable=AsyncMock, return_value=mock_raw_ws,
        ):
            ws = await authed_sdk.connect_public_ws()
            assert len(authed_sdk._open_websockets) == 1
            assert not ws.closed
        await authed_sdk.close()
        assert authed_sdk._open_websockets == []
        mock_raw_ws.close.assert_awaited()

    async def test_prune_closed_websockets(self, authed_sdk):
        mock_ws_1 = _mock_raw_ws([])
        mock_ws_2 = _mock_raw_ws([])
        mock_ws_3 = _mock_raw_ws([])
        mocks = iter([mock_ws_1, mock_ws_2, mock_ws_3])
        with patch.object(
            aiohttp.ClientSession, "ws_connect",
            new_callable=AsyncMock, side_effect=lambda *a, **kw: next(mocks),
        ):
            ws1 = await authed_sdk.connect_public_ws()
            ws2 = await authed_sdk.connect_public_ws()
            assert len(authed_sdk._open_websockets) == 2

            await ws1.close()
            mock_ws_1.closed = True

            _ = await authed_sdk.connect_public_ws()
            assert len(authed_sdk._open_websockets) == 2
            assert ws1 not in authed_sdk._open_websockets
        await authed_sdk.close()


DIGEST_HEX = "00" * 32


def _intent_build_submit_mocks(m):
    """Register aioresponses mocks for the intent build + submit flow."""
    m.post(
        f"{BASE_URL}/v1/intent/build/pool/swap",
        payload={"id": "build-swap-1", "intent": {"digest": DIGEST_HEX}},
    )
    m.post(
        f"{BASE_URL}/v1/intent/submit",
        payload={"status": "submitted"},
    )


@pytest.mark.asyncio
class TestSwapAndConfirm:
    async def test_success_pending_then_executed(self, authed_sdk):
        """SwapPending followed by SwapExecuted returns the executed event."""
        mock_ws = _mock_raw_ws([
            _make_ws_msg(aiohttp.WSMsgType.TEXT, json.dumps(SAMPLE_WS_SWAP_PENDING_RAW)),
            _make_ws_msg(aiohttp.WSMsgType.TEXT, json.dumps(SAMPLE_WS_SWAP_EXECUTED_RAW)),
        ])
        with aioresponses() as m, patch.object(
            aiohttp.ClientSession, "ws_connect",
            new_callable=AsyncMock, return_value=mock_ws,
        ):
            _intent_build_submit_mocks(m)
            result = await authed_sdk.swap_and_confirm(
                sell_amount=Decimal("11"),
                sell_instrument=InstrumentId(id="USDCx", admin="usdc-rep::1220abc"),
                buy_instrument=InstrumentId(id="Amulet", admin="DSO::1220def"),
            )
            assert isinstance(result, SwapExecutedEvent)
            assert result.input_instrument.id == "USDCx"
            assert result.output_instrument.id == "Amulet"
            assert result.input_amount == Decimal("11.0766285914")
        await authed_sdk.close()

    async def test_success_executed_immediately(self, authed_sdk):
        """SwapExecuted without a preceding SwapPending still works."""
        mock_ws = _mock_raw_ws([
            _make_ws_msg(aiohttp.WSMsgType.TEXT, json.dumps(SAMPLE_WS_SWAP_EXECUTED_RAW)),
        ])
        with aioresponses() as m, patch.object(
            aiohttp.ClientSession, "ws_connect",
            new_callable=AsyncMock, return_value=mock_ws,
        ):
            _intent_build_submit_mocks(m)
            result = await authed_sdk.swap_and_confirm(
                sell_amount=Decimal("11"),
                sell_instrument=InstrumentId(id="USDCx", admin="usdc-rep::1220abc"),
                buy_instrument=InstrumentId(id="Amulet", admin="DSO::1220def"),
            )
            assert isinstance(result, SwapExecutedEvent)
        await authed_sdk.close()

    async def test_swap_failed_raises(self, authed_sdk):
        """SwapFailedEvent causes CantexError with the error message."""
        mock_ws = _mock_raw_ws([
            _make_ws_msg(aiohttp.WSMsgType.TEXT, json.dumps(SAMPLE_WS_SWAP_PENDING_RAW)),
            _make_ws_msg(aiohttp.WSMsgType.TEXT, json.dumps(SAMPLE_WS_SWAP_FAILED_RAW)),
        ])
        with aioresponses() as m, patch.object(
            aiohttp.ClientSession, "ws_connect",
            new_callable=AsyncMock, return_value=mock_ws,
        ):
            _intent_build_submit_mocks(m)
            with pytest.raises(CantexError, match="Swap failed: insufficient balance"):
                await authed_sdk.swap_and_confirm(
                    sell_amount=Decimal("11"),
                    sell_instrument=InstrumentId(id="USDCx", admin="usdc-rep::1220abc"),
                    buy_instrument=InstrumentId(id="Amulet", admin="DSO::1220def"),
                )
        await authed_sdk.close()

    async def test_timeout_raises(self, authed_sdk):
        """No confirmation within timeout raises CantexTimeoutError."""
        async def hang_forever():
            await asyncio.sleep(999)
            return _make_ws_msg(aiohttp.WSMsgType.TEXT, "{}")

        mock_ws = _mock_raw_ws([])
        mock_ws.receive = AsyncMock(side_effect=hang_forever)
        with aioresponses() as m, patch.object(
            aiohttp.ClientSession, "ws_connect",
            new_callable=AsyncMock, return_value=mock_ws,
        ):
            _intent_build_submit_mocks(m)
            with pytest.raises(CantexTimeoutError, match="timed out after 0.1s"):
                await authed_sdk.swap_and_confirm(
                    sell_amount=Decimal("11"),
                    sell_instrument=InstrumentId(id="USDCx", admin="usdc-rep::1220abc"),
                    buy_instrument=InstrumentId(id="Amulet", admin="DSO::1220def"),
                    timeout=0.1,
                )
        await authed_sdk.close()

    async def test_ignores_non_trading_events(self, authed_sdk):
        """Funding events are ignored while waiting for swap confirmation."""
        mock_ws = _mock_raw_ws([
            _make_ws_msg(aiohttp.WSMsgType.TEXT, json.dumps(SAMPLE_WS_DEPOSIT_CONFIRMED_RAW)),
            _make_ws_msg(aiohttp.WSMsgType.TEXT, json.dumps(SAMPLE_WS_SWAP_EXECUTED_RAW)),
        ])
        with aioresponses() as m, patch.object(
            aiohttp.ClientSession, "ws_connect",
            new_callable=AsyncMock, return_value=mock_ws,
        ):
            _intent_build_submit_mocks(m)
            result = await authed_sdk.swap_and_confirm(
                sell_amount=Decimal("11"),
                sell_instrument=InstrumentId(id="USDCx", admin="usdc-rep::1220abc"),
                buy_instrument=InstrumentId(id="Amulet", admin="DSO::1220def"),
            )
            assert isinstance(result, SwapExecutedEvent)
        await authed_sdk.close()

    async def test_ws_closed_before_confirmation(self, authed_sdk):
        """WS closing before any swap event raises CantexError."""
        mock_ws = _mock_raw_ws([
            _make_ws_msg(aiohttp.WSMsgType.CLOSE, None),
        ])
        with aioresponses() as m, patch.object(
            aiohttp.ClientSession, "ws_connect",
            new_callable=AsyncMock, return_value=mock_ws,
        ):
            _intent_build_submit_mocks(m)
            with pytest.raises(CantexError, match="WebSocket closed before swap confirmation"):
                await authed_sdk.swap_and_confirm(
                    sell_amount=Decimal("11"),
                    sell_instrument=InstrumentId(id="USDCx", admin="usdc-rep::1220abc"),
                    buy_instrument=InstrumentId(id="Amulet", admin="DSO::1220def"),
                )
        await authed_sdk.close()

    async def test_ws_closed_after_confirm(self, authed_sdk):
        """The private WS is always closed after swap_and_confirm returns."""
        mock_ws = _mock_raw_ws([
            _make_ws_msg(aiohttp.WSMsgType.TEXT, json.dumps(SAMPLE_WS_SWAP_EXECUTED_RAW)),
        ])
        with aioresponses() as m, patch.object(
            aiohttp.ClientSession, "ws_connect",
            new_callable=AsyncMock, return_value=mock_ws,
        ):
            _intent_build_submit_mocks(m)
            await authed_sdk.swap_and_confirm(
                sell_amount=Decimal("11"),
                sell_instrument=InstrumentId(id="USDCx", admin="usdc-rep::1220abc"),
                buy_instrument=InstrumentId(id="Amulet", admin="DSO::1220def"),
            )
            mock_ws.close.assert_awaited()
        await authed_sdk.close()
