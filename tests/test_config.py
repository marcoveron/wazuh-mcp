"""Configuration is the first thing a new deployment gets wrong; fail loudly."""

from __future__ import annotations

import pytest

from wazuh_mcp import _transport_options
from wazuh_mcp.config import Config, ConfigError


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for key in list(__import__("os").environ):
        if key.startswith("WAZUH_"):
            monkeypatch.delenv(key, raising=False)


def load(monkeypatch, **env) -> Config:
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    # Point at a directory with no .env so the test environment is the whole story.
    return Config.from_env(dotenv_path="/nonexistent/.env")


def test_missing_url_names_the_variable_and_the_fix(monkeypatch):
    with pytest.raises(ConfigError, match="WAZUH_API_URL"):
        load(monkeypatch)


def test_missing_credentials_are_reported(monkeypatch):
    with pytest.raises(ConfigError, match="WAZUH_API_USER"):
        load(monkeypatch, WAZUH_API_URL="https://wazuh:55000")


def test_trailing_slashes_are_stripped_so_paths_do_not_double_up(monkeypatch):
    config = load(
        monkeypatch,
        WAZUH_API_URL="https://wazuh:55000/",
        WAZUH_API_USER="u",
        WAZUH_API_PASSWORD="p",
        WAZUH_INDEXER_URL="https://wazuh:9200/",
    )
    assert config.api.url == "https://wazuh:55000"
    assert config.indexer.url == "https://wazuh:9200"


def test_indexer_is_optional(monkeypatch):
    config = load(
        monkeypatch, WAZUH_API_URL="https://wazuh:55000",
        WAZUH_API_USER="u", WAZUH_API_PASSWORD="p",
    )
    assert config.indexer is None


def test_indexer_falls_back_to_the_api_credentials(monkeypatch):
    config = load(
        monkeypatch, WAZUH_API_URL="https://wazuh:55000",
        WAZUH_API_USER="analyst", WAZUH_API_PASSWORD="secret",
        WAZUH_INDEXER_URL="https://wazuh:9200",
    )
    assert config.indexer.user == "analyst"
    assert config.indexer.password == "secret"


def test_component_ssl_settings_override_the_shared_one(monkeypatch):
    config = load(
        monkeypatch, WAZUH_API_URL="https://wazuh:55000",
        WAZUH_API_USER="u", WAZUH_API_PASSWORD="p",
        WAZUH_INDEXER_URL="https://wazuh:9200",
        WAZUH_VERIFY_SSL="false", WAZUH_INDEXER_VERIFY_SSL="true",
    )
    assert config.api.verify_ssl is False
    assert config.indexer.verify_ssl is True


@pytest.mark.parametrize("value,expected", [
    ("true", True), ("True", True), ("1", True), ("yes", True), ("on", True),
    ("false", False), ("0", False), ("no", False), ("", True),
])
def test_boolean_parsing_accepts_what_people_actually_write(monkeypatch, value, expected):
    config = load(
        monkeypatch, WAZUH_API_URL="https://wazuh:55000",
        WAZUH_API_USER="u", WAZUH_API_PASSWORD="p", WAZUH_VERIFY_SSL=value,
    )
    assert config.api.verify_ssl is expected


def test_active_response_is_off_unless_asked_for(monkeypatch):
    config = load(
        monkeypatch, WAZUH_API_URL="https://wazuh:55000",
        WAZUH_API_USER="u", WAZUH_API_PASSWORD="p",
    )
    assert config.allow_active_response is False
    assert config.active_response_allowlist == frozenset()


def test_allowlist_tolerates_spacing_and_trailing_commas(monkeypatch):
    config = load(
        monkeypatch, WAZUH_API_URL="https://wazuh:55000",
        WAZUH_API_USER="u", WAZUH_API_PASSWORD="p",
        WAZUH_ACTIVE_RESPONSE_COMMANDS=" firewall-drop , host-deny ,",
    )
    assert config.active_response_allowlist == frozenset({"firewall-drop", "host-deny"})


def test_a_non_numeric_limit_is_rejected_rather_than_ignored(monkeypatch):
    with pytest.raises(ConfigError, match="WAZUH_MAX_RESULTS"):
        load(
            monkeypatch, WAZUH_API_URL="https://wazuh:55000",
            WAZUH_API_USER="u", WAZUH_API_PASSWORD="p", WAZUH_MAX_RESULTS="lots",
        )


# ------------------------------------------------------------------ transport


def test_stdio_takes_no_socket_options():
    assert _transport_options("stdio") == {}


def test_http_transports_default_to_loopback(monkeypatch):
    """Binding wide by default would publish an unauthenticated SIEM."""
    monkeypatch.delenv("WAZUH_MCP_HOST", raising=False)
    monkeypatch.delenv("WAZUH_MCP_PORT", raising=False)
    monkeypatch.delenv("WAZUH_MCP_PATH", raising=False)
    assert _transport_options("streamable-http") == {"host": "127.0.0.1", "port": 8000}


def test_bind_address_is_overridable(monkeypatch):
    monkeypatch.setenv("WAZUH_MCP_HOST", "10.0.0.5")
    monkeypatch.setenv("WAZUH_MCP_PORT", "9100")
    monkeypatch.setenv("WAZUH_MCP_PATH", "/wazuh")
    assert _transport_options("streamable-http") == {
        "host": "10.0.0.5", "port": 9100, "streamable_http_path": "/wazuh"
    }


def test_sse_names_its_path_differently(monkeypatch):
    monkeypatch.setenv("WAZUH_MCP_PATH", "/wazuh")
    assert _transport_options("sse")["sse_path"] == "/wazuh"


def test_a_bad_port_fails_before_the_server_starts(monkeypatch):
    monkeypatch.setenv("WAZUH_MCP_PORT", "https")
    with pytest.raises(ConfigError):
        _transport_options("streamable-http")
