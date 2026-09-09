"""OCI API Gateway authorizer for secured Event Hub to OIC delivery."""

from __future__ import annotations

import base64
import hmac
import io
import json
import logging
import os
import threading
import time
from datetime import UTC, datetime
from typing import Any, Dict, Optional, Tuple

import requests
from fdk import response

from vault import VaultSecretReader

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())
DEFAULT_SCOPE = "oic.invoke"
DEFAULT_SECRET_CACHE_TTL_SECONDS = 300
DEFAULT_TOKEN_EXPIRY_SKEW_SECONDS = 60
TOKEN_TIMEOUT_SECONDS = 10
TOKEN_CACHE: Dict[str, Tuple[str, int]] = {}
TOKEN_LOCK = threading.Lock()
SECRET_READERS: Dict[int, VaultSecretReader] = {}
SECRET_READER_LOCK = threading.Lock()


def _config(name: str, *aliases: str, default: Optional[str] = None) -> Optional[str]:
    for key in (name, *aliases):
        value = os.getenv(key)
        if value and value.strip():
            return value.strip()
    return default


def _required_config(name: str, *aliases: str) -> str:
    value = _config(name, *aliases)
    if not value:
        raise ValueError(f"Missing required function configuration: {', '.join((name, *aliases))}")
    return value


def _mask(value: Optional[str], visible: int = 4) -> str:
    """Return a safe, compact value for logs; never log credentials in full."""
    if not value:
        return "<missing>"
    value = str(value)
    if len(value) <= visible:
        return "*" * len(value)
    return f"{'*' * max(4, len(value) - visible)}{value[-visible:]}"


def _log(event: str, **fields: Any) -> None:
    LOGGER.info(json.dumps({"event": event, **fields}, separators=(",", ":"), default=str))


def _as_single_value(value: Any) -> Optional[str]:
    if isinstance(value, list):
        if len(value) != 1:
            return None
        value = value[0]
    return value.strip() if isinstance(value, str) and value.strip() else None


def _incoming_api_key(payload: Dict[str, Any]) -> Optional[str]:
    data = payload.get("data")
    return _as_single_value(data.get("api_key")) if isinstance(data, dict) else None


def _authorizer_response(ctx: Any, active: bool, *, token: Optional[str] = None,
                         expires_at: Optional[int] = None) -> response.Response:
    body: Dict[str, Any] = {"active": active}
    if active:
        body["scope"] = [_config("AUTHORIZED_SCOPE", default=DEFAULT_SCOPE)]
        body["context"] = {"oic_access_token": token, "api_key_valid": "true"}
        if expires_at:
            body["expiresAt"] = datetime.fromtimestamp(expires_at, UTC).isoformat().replace("+00:00", "Z")
    return response.Response(ctx, response_data=json.dumps(body), status_code=200,
                             headers={"Content-Type": "application/json"})


def _basic_auth(client_id: str, client_secret: str) -> str:
    raw = f"{client_id}:{client_secret}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def _secret_reader(cache_ttl_seconds: int) -> VaultSecretReader:
    with SECRET_READER_LOCK:
        return SECRET_READERS.setdefault(cache_ttl_seconds, VaultSecretReader(cache_ttl_seconds))


def _get_oic_token(secret_reader: VaultSecretReader) -> Tuple[str, int]:
    token_url = _required_config("TOKEN_URL", "OIC_TOKEN_URL")
    scope = _required_config("OIC_SCOPE")
    client_id = _required_config("CLIENT_ID", "OIC_CLIENT_ID")
    secret_ocid = _required_config("CLIENT_SECRET_OCID", "OIC_CLIENT_SECRET_OCID")
    skew = int(_config("TOKEN_EXPIRY_SKEW_SECONDS", default=str(DEFAULT_TOKEN_EXPIRY_SKEW_SECONDS)) or "60")
    cache_key = "|".join((token_url, scope, client_id))
    now = int(time.time())
    with TOKEN_LOCK:
        cached = TOKEN_CACHE.get(cache_key)
        if cached and now < cached[1] - skew:
            _log("oic_token_cache_hit", client_id=_mask(client_id), expires_at=cached[1])
            return cached

    client_secret = secret_reader.get_secret(secret_ocid)
    started = time.monotonic()
    token_response = requests.post(
        token_url,
        headers={"Authorization": _basic_auth(client_id, client_secret),
                 "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        data={"grant_type": "client_credentials", "scope": scope}, timeout=TOKEN_TIMEOUT_SECONDS)
    _log("oic_token_request_complete", status_code=token_response.status_code,
         elapsed_ms=round((time.monotonic() - started) * 1000))
    token_response.raise_for_status()
    token_body = token_response.json()
    access_token = token_body.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise RuntimeError("Token endpoint response did not include an access_token")
    expires_in = int(token_body.get("expires_in", 3600))
    if expires_in <= skew:
        raise RuntimeError("Token endpoint returned an expiry too short for the configured safety skew")
    expires_at = now + expires_in
    with TOKEN_LOCK:
        TOKEN_CACHE[cache_key] = (access_token, expires_at)
    return access_token, expires_at


def handler(ctx: Any, data: io.BytesIO | None = None) -> response.Response:
    """Validate the Gateway authorizer input and return OIC token context."""
    try:
        payload = json.loads((data.getvalue() if data else b"{}").decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("Authorizer payload must be a JSON object")
        supplied_key = _incoming_api_key(payload)
        secret_ttl = int(_config("SECRET_CACHE_TTL_SECONDS", default=str(DEFAULT_SECRET_CACHE_TTL_SECONDS)) or "300")
        secret_reader = _secret_reader(secret_ttl)
        api_key_secret_ocid = _required_config(
            "API_KEY_SECRET_OCID", "INBOUND_API_KEY_SECRET_OCID"
        )
        expected_key = secret_reader.get_secret(api_key_secret_ocid)
        if not supplied_key or not hmac.compare_digest(supplied_key, expected_key):
            _log("authorization_denied", reason="invalid_api_key", api_key=_mask(supplied_key))
            return _authorizer_response(ctx, False)

        _log("authorization_accepted", api_key=_mask(supplied_key))
        token, expires_at = _get_oic_token(secret_reader)
        _log("authorization_complete", token_expires_at=expires_at)
        return _authorizer_response(ctx, True, token=token, expires_at=expires_at)
    except (ValueError, json.JSONDecodeError) as exc:
        _log("authorizer_configuration_or_input_error", error_type=type(exc).__name__, message=str(exc))
        return response.Response(ctx, response_data=json.dumps({"error": "authorizer configuration or input error"}), status_code=500)
    except requests.RequestException as exc:
        _log("oic_token_request_failed", error_type=type(exc).__name__)
        return response.Response(ctx, response_data=json.dumps({"error": "token service unavailable"}), status_code=500)
    except Exception as exc:
        LOGGER.exception("authorizer_unexpected_error", extra={"error_type": type(exc).__name__})
        return response.Response(ctx, response_data=json.dumps({"error": "authorizer unavailable"}), status_code=500)
