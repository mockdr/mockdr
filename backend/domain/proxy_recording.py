"""Domain types for the recording proxy feature."""
from __future__ import annotations

from dataclasses import dataclass, field

# ── Vendor constants ─────────────────────────────────────────────────────────

VENDOR_NAMES = frozenset({
    "s1", "crowdstrike", "mde", "elastic", "cortex_xdr",
    "splunk", "sentinel", "graph",
})

VENDOR_LABELS: dict[str, str] = {
    "s1": "SentinelOne",
    "crowdstrike": "CrowdStrike Falcon",
    "mde": "Microsoft Defender for Endpoint",
    "elastic": "Elastic Security",
    "cortex_xdr": "Cortex XDR",
    "splunk": "Splunk SIEM",
    "sentinel": "Microsoft Sentinel",
    "graph": "Microsoft Graph API",
}


# ── Auth strategy dataclasses ────────────────────────────────────────────────

@dataclass
class AuthApiToken:
    """SentinelOne-style ``Authorization: ApiToken <token>`` header."""

    type: str = "api_token"
    token: str = ""


@dataclass
class AuthOAuth2:
    """OAuth2 client credentials (CrowdStrike, MDE, Sentinel, Graph).

    ``token_url`` is the full URL to POST for token exchange -- varies by
    vendor and tenant (e.g. ``https://api.crowdstrike.com/oauth2/token``).
    """

    type: str = "oauth2"
    client_id: str = ""
    client_secret: str = ""
    token_url: str = ""


@dataclass
class AuthBasic:
    """Basic Auth or API Key (Elastic, Splunk)."""

    type: str = "basic"
    username: str = ""
    password: str = ""
    api_key: str = ""  # if set, use ``Authorization: ApiKey <key>`` instead


@dataclass
class AuthHmac:
    """Cortex XDR HMAC authentication."""

    type: str = "hmac"
    key_id: str = ""
    key_secret: str = ""


VendorAuth = AuthApiToken | AuthOAuth2 | AuthBasic | AuthHmac

# Default auth type per vendor (used by UI to show the right form).
VENDOR_DEFAULT_AUTH: dict[str, str] = {
    "s1": "api_token",
    "crowdstrike": "oauth2",
    "mde": "oauth2",
    "elastic": "basic",
    "cortex_xdr": "hmac",
    "splunk": "basic",
    "sentinel": "oauth2",
    "graph": "oauth2",
}


# ── Per-vendor proxy config ──────────────────────────────────────────────────

@dataclass
class VendorProxyConfig:
    """Upstream connection settings for a single vendor."""

    vendor: str  # one of VENDOR_NAMES
    base_url: str = ""  # e.g. "https://tenant.sentinelone.net"
    auth: VendorAuth = field(default_factory=AuthApiToken)
    enabled: bool = True


# ── Top-level proxy config ───────────────────────────────────────────────────

@dataclass
class ProxyConfig:
    """Global proxy mode plus per-vendor upstream settings."""

    mode: str = "off"  # "off" | "record" | "replay"
    vendors: dict[str, VendorProxyConfig] = field(default_factory=dict)

    # Legacy flat fields kept for backward compat during migration.
    base_url: str = ""
    api_token: str = ""


# ── Recording ────────────────────────────────────────────────────────────────

@dataclass
class ProxyRecording:
    """A single recorded request/response exchange with a real vendor API."""

    id: str
    method: str
    path: str
    query_string: str
    request_body: str
    response_status: int
    response_body: str
    response_content_type: str
    recorded_at: str
    base_url: str
    vendor: str = "s1"
