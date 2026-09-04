"""OCI Vault secret retrieval with per-process caching for OCI Functions."""

from __future__ import annotations

import base64
import threading
import time
from typing import Dict, Tuple

import oci


class VaultSecretReader:
    """Reads a Vault secret through OCI Function resource principals."""

    def __init__(self, cache_ttl_seconds: int = 300) -> None:
        self._cache_ttl_seconds = cache_ttl_seconds
        self._cache: Dict[str, Tuple[str, float]] = {}
        self._client: oci.secrets.SecretsClient | None = None
        self._lock = threading.Lock()

    def get_secret(self, secret_ocid: str) -> str:
        """Return decoded secret content. Values are never logged."""
        if not secret_ocid or not secret_ocid.strip():
            raise ValueError("A Vault secret OCID is required")

        ocid = secret_ocid.strip()
        now = time.monotonic()
        with self._lock:
            cached = self._cache.get(ocid)
            if cached and now < cached[1]:
                return cached[0]

            if self._client is None:
                signer = oci.auth.signers.get_resource_principals_signer()
                self._client = oci.secrets.SecretsClient({}, signer=signer)

            bundle = self._client.get_secret_bundle(ocid).data
            try:
                value = base64.b64decode(bundle.secret_bundle_content.content).decode("utf-8").strip()
            except (ValueError, UnicodeDecodeError) as exc:
                raise RuntimeError("Vault secret content could not be decoded") from exc
            if not value:
                raise RuntimeError("Vault secret is empty")

            self._cache[ocid] = (value, now + self._cache_ttl_seconds)
            return value
