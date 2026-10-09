"""Configuration loaded from environment variables (optionally via a .env file)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value


def _env_bool(name: str, default: bool) -> bool:
    raw = _env(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = _env(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc


def _env_float(name: str, default: float) -> float:
    raw = _env(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number, got {raw!r}") from exc


class ConfigError(RuntimeError):
    """Raised when the environment is missing or contradicts required settings."""


@dataclass(slots=True)
class ServerApiConfig:
    """Wazuh Server API (management plane, default port 55000)."""

    url: str
    user: str
    password: str
    verify_ssl: bool = True
    ca_bundle: str | None = None
    timeout: float = 30.0
    # Refresh the JWT this many seconds before it actually expires.
    token_leeway: float = 60.0


@dataclass(slots=True)
class IndexerConfig:
    """Wazuh Indexer / OpenSearch (data plane, default port 9200)."""

    url: str
    user: str
    password: str
    verify_ssl: bool = True
    ca_bundle: str | None = None
    timeout: float = 60.0
    alerts_index: str = "wazuh-alerts-*"
    archives_index: str = "wazuh-archives-*"
    vulnerabilities_index: str = "wazuh-states-vulnerabilities-*"


@dataclass(slots=True)
class Config:
    api: ServerApiConfig
    indexer: IndexerConfig | None
    # Active Response and agent restarts are gated behind this flag.
    allow_active_response: bool = False
    # Hard ceiling on how many documents/items any tool may return, so a stray
    # `limit=100000` cannot blow up the model's context window.
    max_results: int = 500
    # Commands Active Response may invoke. Empty set means "any command".
    active_response_allowlist: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def from_env(cls, *, dotenv_path: str | os.PathLike[str] | None = None) -> Config:
        """Build a config from the process environment.

        A `.env` file is loaded first if present, but real environment variables
        always win over the file so container/systemd overrides behave as expected.
        """
        if dotenv_path is not None:
            load_dotenv(dotenv_path, override=False)
        else:
            found = _find_dotenv()
            if found is not None:
                load_dotenv(found, override=False)

        api_url = _env("WAZUH_API_URL")
        if api_url is None:
            raise ConfigError(
                "WAZUH_API_URL is required (e.g. https://wazuh.example.com:55000). "
                "Copy .env.example to .env and fill it in."
            )
        api_user = _env("WAZUH_API_USER")
        api_password = _env("WAZUH_API_PASSWORD")
        if not api_user or not api_password:
            raise ConfigError("WAZUH_API_USER and WAZUH_API_PASSWORD are required.")

        verify_default = _env_bool("WAZUH_VERIFY_SSL", True)
        ca_default = _env("WAZUH_CA_BUNDLE")

        api = ServerApiConfig(
            url=api_url.rstrip("/"),
            user=api_user,
            password=api_password,
            verify_ssl=_env_bool("WAZUH_API_VERIFY_SSL", verify_default),
            ca_bundle=_env("WAZUH_API_CA_BUNDLE", ca_default),
            timeout=_env_float("WAZUH_API_TIMEOUT", 30.0),
        )

        indexer: IndexerConfig | None = None
        indexer_url = _env("WAZUH_INDEXER_URL")
        if indexer_url is not None:
            indexer_user = _env("WAZUH_INDEXER_USER", api_user)
            indexer_password = _env("WAZUH_INDEXER_PASSWORD", api_password)
            assert indexer_user is not None and indexer_password is not None
            indexer = IndexerConfig(
                url=indexer_url.rstrip("/"),
                user=indexer_user,
                password=indexer_password,
                verify_ssl=_env_bool("WAZUH_INDEXER_VERIFY_SSL", verify_default),
                ca_bundle=_env("WAZUH_INDEXER_CA_BUNDLE", ca_default),
                timeout=_env_float("WAZUH_INDEXER_TIMEOUT", 60.0),
                alerts_index=_env("WAZUH_ALERTS_INDEX", "wazuh-alerts-*") or "wazuh-alerts-*",
                archives_index=_env("WAZUH_ARCHIVES_INDEX", "wazuh-archives-*")
                or "wazuh-archives-*",
                vulnerabilities_index=_env(
                    "WAZUH_VULNERABILITIES_INDEX", "wazuh-states-vulnerabilities-*"
                )
                or "wazuh-states-vulnerabilities-*",
            )

        allowlist_raw = _env("WAZUH_ACTIVE_RESPONSE_COMMANDS", "")
        allowlist = frozenset(
            item.strip() for item in (allowlist_raw or "").split(",") if item.strip()
        )

        return cls(
            api=api,
            indexer=indexer,
            allow_active_response=_env_bool("WAZUH_ALLOW_ACTIVE_RESPONSE", False),
            max_results=_env_int("WAZUH_MAX_RESULTS", 500),
            active_response_allowlist=allowlist,
        )


def _find_dotenv() -> Path | None:
    """Look for a .env next to the CWD or walking up from this package."""
    candidates = [Path.cwd() / ".env"]
    here = Path(__file__).resolve()
    candidates.extend(parent / ".env" for parent in here.parents[:4])
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None
