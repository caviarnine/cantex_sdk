# Copyright (c) 2026 CaviarNine
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Tests for cantex_sdk — signers and SDK."""
from __future__ import annotations

import asyncio
import base64
import json
import os
import tempfile
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
    InstrumentInfo,
    IntentTradingKeySigner,
    OperatorKeySigner,
    Pool,
    PoolsInfo,
    QuoteFees,
    QuoteLeg,
    SwapQuote,
    TokenBalance,
)
from cantex_sdk._sdk import _b64_encode

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
# Helper tests
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


# ===================================================================
# OperatorKeySigner tests
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


# ===================================================================
# IntentTradingKeySigner tests
# ===================================================================


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
# CantexSDK tests
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
# SDK HTTP / _request tests
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
# Authentication tests
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
# Build-sign-submit tests
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
# Public API method tests
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
            assert result.tokens[0].instrument_id == "USDC"
            assert result.tokens[0].locked_amount == Decimal("50.0")
            assert result.get_balance("USDC", "admin1") == Decimal("500.0")
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
            assert result.instruments[0].instrument_id == "Amulet"
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
                Decimal("100"), "USDC", "admin1", "BTC", "admin2",
            )
            assert isinstance(result, SwapQuote)
            assert result.trade_price == Decimal("0.1548225750")
            assert result.returned_amount == Decimal("0.1547451638")
            assert result.slippage == Decimal("0.0000015358")
            assert result.fees.fee_percentage == Decimal("0.0005000000")
        await authed_sdk.close()

    async def test_batch_transfer_validation(self, authed_sdk):
        with pytest.raises(ValueError, match="index 1"):
            await authed_sdk.batch_transfer(
                [
                    {"receiver": "alice", "amount": Decimal("10")},
                    {"receiver": "bob"},  # missing amount
                ],
                "USDC", "admin",
            )
        await authed_sdk.close()

    async def test_create_intent_trading_account_no_signer(self, operator):
        sdk = CantexSDK(operator, None, base_url=BASE_URL, api_key_path=None)
        sdk._api_key = "key"
        with pytest.raises(RuntimeError, match="IntentTradingKeySigner required"):
            await sdk.create_intent_trading_account()
        await sdk.close()


# ===================================================================
# Session lifecycle tests
# ===================================================================


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
# Response model tests
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
        assert t.instrument_id == "USDC"
        assert t.instrument_admin == "admin::usdc"
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
            t.instrument_id = "nope"


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
        assert info.tokens[0].instrument_id == "USDC"
        assert info.tokens[1].instrument_id == "BTC"

    def test_get_balance_found(self):
        info = AccountInfo._from_raw({"tokens": [SAMPLE_TOKEN_RAW]})
        assert info.get_balance("USDC", "admin::usdc") == Decimal("1234.56")

    def test_get_balance_not_found(self):
        info = AccountInfo._from_raw({"tokens": [SAMPLE_TOKEN_RAW]})
        assert info.get_balance("ETH", "admin::eth") == Decimal(0)

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
        assert info.get_balance("USDC", "admin") == Decimal(0)
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
        assert info.instrument_id == "Amulet"
        assert info.instrument_admin == "DSO::1220abc"
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
            info.instrument_id = "nope"


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
        assert admin.instruments[0].instrument_id == "Amulet"
        assert admin.instruments[0].instrument_symbol == "CC"
        assert admin.instruments[1].instrument_id == "USDCx"

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
        assert p.token_a_instrument_id == "USDC"
        assert p.token_b_instrument_id == "BTC"

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
        assert pool.token_a_instrument_id == "USDC"

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
        assert leg.instrument_id == "USDCx"
        assert leg.instrument_admin == "admin::usdc"

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
        assert fees.instrument_id == "Amulet"
        assert isinstance(fees.network_fee, QuoteLeg)
        assert fees.network_fee.amount == Decimal("0.1000")


class TestSwapQuote:
    def test_from_raw(self):
        q = SwapQuote._from_raw(SAMPLE_QUOTE_RAW)
        assert q.trade_price == Decimal("0.1548225750")
        assert q.slippage == Decimal("0.0000015358")
        assert q.estimated_time_seconds == Decimal("4.72")
        assert q.pool_price_before_trade == Decimal("0.1548228128")
        assert q.pool_price_after_trade == Decimal("0.1548223373")
        assert q.sell_amount == Decimal("1")
        assert q.sell_instrument_id == "Amulet"
        assert q.buy_instrument_id == "USDCx"

    def test_returned_amount_property(self):
        q = SwapQuote._from_raw(SAMPLE_QUOTE_RAW)
        assert q.returned_amount == Decimal("0.1547451638")
        assert q.returned_amount == q.returned.amount
        assert q.returned.instrument_id == "USDCx"

    def test_pool_size(self):
        q = SwapQuote._from_raw(SAMPLE_QUOTE_RAW)
        assert q.pool_size.amount == Decimal("1301596.7091451541")
        assert q.pool_size.instrument_id == "Amulet"

    def test_fees(self):
        q = SwapQuote._from_raw(SAMPLE_QUOTE_RAW)
        assert isinstance(q.fees, QuoteFees)
        assert q.fees.fee_percentage == Decimal("0.0005000000")
        assert q.fees.network_fee.amount == Decimal("0.1000")

    def test_frozen(self):
        q = SwapQuote._from_raw(SAMPLE_QUOTE_RAW)
        with pytest.raises(AttributeError):
            q.trade_price = Decimal("2.0")
