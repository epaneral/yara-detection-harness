#!/usr/bin/env python3
"""
VirusTotal enrichment MCP server.

The enrichment layer for the yara-detection-harness. The harness detects
malicious *patterns*; the natural next question in an investigation is
"this rule fired -- is the indicator it surfaced actually known-bad?"
This server wraps the VirusTotal v3 reputation API as MCP tools an LLM agent
can call mid-investigation, returning a *normalized* verdict for an indicator
(a file hash or a URL) instead of VirusTotal's full raw report.

Design notes:
  - Read-only. Only GET lookups; nothing here submits, mutates, or deletes.
  - One source now (VirusTotal), but the tool interface is built so additional
    reputation sources could slot in behind the same normalized verdict shape.
  - API key is read from the VT_API_KEY environment variable, never hardcoded.
  - Local stdio transport: launched as a subprocess by an MCP client.

Scope fence (deliberately NOT built here): multi-source fan-out, auto-extracting
indicators from corpus samples, caching/persistence, and a formal eval suite.
See README.md "Roadmap" for those.
"""

import base64
import ipaddress
import json
import os
import re

import httpx
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field, field_validator

# Optional convenience: auto-load a local .env when present (e.g. for Inspector
# testing). The server works fine with a plain VT_API_KEY env var without this.
try:
    from dotenv import load_dotenv

    # Load the .env beside this file (not relative to the client's cwd) so the key
    # loads regardless of where the MCP client launches the process from.
    load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))
except ImportError:
    pass

# --- Configuration ---------------------------------------------------------
VT_API_BASE = "https://www.virustotal.com/api/v3"
VT_API_KEY = os.environ.get("VT_API_KEY", "")
REQUEST_TIMEOUT = 30.0  # seconds

# Domain label/TLD shape (LDH). Used to validate domain input.
_DOMAIN_RE = re.compile(
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}",
    re.IGNORECASE,
)

mcp = FastMCP("virustotal_mcp")


# --- Input models ----------------------------------------------------------
class HashLookupInput(BaseModel):
    """Input for a file-hash reputation lookup."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    file_hash: str = Field(
        ...,
        description="MD5 (32), SHA-1 (40), or SHA-256 (64) hex digest of the file to look up",
        min_length=32,
        max_length=64,
    )

    @field_validator("file_hash")
    @classmethod
    def _validate_hash(cls, v: str) -> str:
        v = v.strip().lower()
        if len(v) not in (32, 40, 64):
            raise ValueError("hash must be MD5 (32), SHA-1 (40), or SHA-256 (64) hex chars")
        if any(c not in "0123456789abcdef" for c in v):
            raise ValueError("hash must be hexadecimal")
        return v


class UrlLookupInput(BaseModel):
    """Input for a URL reputation lookup."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    url: str = Field(
        ...,
        description="The URL to look up, including scheme (e.g. 'http://192.0.2.10/stage2.ps1')",
        min_length=4,
        max_length=2048,
    )


class IpLookupInput(BaseModel):
    """Input for an IPv4-address reputation lookup."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    ip: str = Field(
        ...,
        description="IPv4 address to look up (e.g. '192.0.2.10')",
        min_length=7,
        max_length=15,
    )

    @field_validator("ip")
    @classmethod
    def _validate_ip(cls, v: str) -> str:
        v = v.strip()
        try:
            ipaddress.IPv4Address(v)
        except ValueError as err:
            raise ValueError("must be a valid IPv4 address") from err
        return v


class DomainLookupInput(BaseModel):
    """Input for a domain reputation lookup."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    domain: str = Field(
        ...,
        description="Domain name to look up (e.g. 'api.telegram.org')",
        min_length=4,
        max_length=253,
    )

    @field_validator("domain")
    @classmethod
    def _validate_domain(cls, v: str) -> str:
        v = v.strip().lower()
        try:
            ipaddress.ip_address(v)
        except ValueError:
            pass  # not an IP literal -- good, that's what we want
        else:
            raise ValueError("expected a domain, not an IP address")
        if not _DOMAIN_RE.fullmatch(v):
            raise ValueError("must be a valid domain name")
        return v


# --- Shared helpers --------------------------------------------------------
def _require_key() -> str | None:
    """Return an actionable error string if the API key is missing, else None."""
    if not VT_API_KEY:
        return (
            "Error: VT_API_KEY is not set. Get a free key at "
            "https://www.virustotal.com/gui/my-apikey and provide it as the "
            "VT_API_KEY environment variable."
        )
    return None


def _url_id(url: str) -> str:
    """VirusTotal addresses a URL object by base64url(url) with padding stripped."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


async def _vt_get(path: str) -> dict:
    """GET {VT_API_BASE}/{path} with auth. Lets httpx errors propagate to the caller."""
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
        resp = await client.get(
            f"{VT_API_BASE}/{path}",
            headers={"x-apikey": VT_API_KEY},
        )
        resp.raise_for_status()
        return resp.json()


def _handle_error(e: Exception, indicator: str) -> str:
    """Map an exception to an actionable, indicator-aware message (no stack traces)."""
    if isinstance(e, httpx.HTTPStatusError):
        code = e.response.status_code
        if code == 404:
            return f"Not found: '{indicator}' is not in VirusTotal's dataset (no reputation data)."
        if code == 401:
            return "Error: VirusTotal rejected the API key (401). Check that VT_API_KEY is valid."
        if code == 429:
            return (
                "Error: VirusTotal rate limit hit (429). The free tier allows ~4 lookups/min "
                "and 500/day -- wait a moment and retry."
            )
        return f"Error: VirusTotal returned HTTP {code} for '{indicator}'."
    if isinstance(e, httpx.TimeoutException):
        return f"Error: request to VirusTotal timed out after {REQUEST_TIMEOUT:.0f}s. Try again."
    if isinstance(e, httpx.RequestError):
        return (
            f"Error: network error contacting VirusTotal ({type(e).__name__}). Check connectivity."
        )
    return f"Error: unexpected {type(e).__name__} while looking up '{indicator}'."


def _normalize(
    indicator: str, kind: str, gui_id: str, attributes: dict, gui_kind: str | None = None
) -> str:
    """Collapse a VirusTotal object's attributes into a compact verdict (JSON string).

    This is the point of the server: return the *answer*, not VT's full blob.
    The same shape is produced for every indicator type so callers (and future
    sources) stay uniform. gui_kind overrides the permalink path segment when it
    differs from the verdict type (e.g. permalink 'ip-address' vs type 'ip_address').
    """
    stats = attributes.get("last_analysis_stats", {}) or {}
    results = attributes.get("last_analysis_results", {}) or {}

    flagged = sorted(
        engine
        for engine, r in results.items()
        if (r or {}).get("category") in ("malicious", "suspicious")
    )

    verdict = {
        "indicator": indicator,
        "type": kind,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": attributes.get("reputation"),
        "flagged_by": flagged[:5],
        "permalink": f"https://www.virustotal.com/gui/{gui_kind or kind}/{gui_id}",
    }
    return json.dumps(verdict, indent=2)


# --- Per-indicator lookups (shared by the tools and investigate_sample) -----
async def _lookup_file(file_hash: str) -> str:
    """Look up a file hash; return the normalized verdict (or an error line)."""
    key_err = _require_key()
    if key_err:
        return key_err
    try:
        data = await _vt_get(f"files/{file_hash}")
        obj = data.get("data", {})
        return _normalize(file_hash, "file", obj.get("id", file_hash), obj.get("attributes", {}))
    except Exception as e:  # noqa: BLE001 - mapped to actionable text by _handle_error
        return _handle_error(e, file_hash)


async def _lookup_url(url: str) -> str:
    """Look up a URL; return the normalized verdict (or an error line)."""
    key_err = _require_key()
    if key_err:
        return key_err
    url_id = _url_id(url)
    try:
        data = await _vt_get(f"urls/{url_id}")
        obj = data.get("data", {})
        return _normalize(url, "url", obj.get("id", url_id), obj.get("attributes", {}))
    except Exception as e:  # noqa: BLE001 - mapped to actionable text by _handle_error
        return _handle_error(e, url)


async def _lookup_ip(ip: str) -> str:
    """Look up an IPv4 address; return the normalized verdict (or an error line)."""
    key_err = _require_key()
    if key_err:
        return key_err
    try:
        data = await _vt_get(f"ip_addresses/{ip}")
        obj = data.get("data", {})
        return _normalize(
            ip, "ip_address", obj.get("id", ip), obj.get("attributes", {}), gui_kind="ip-address"
        )
    except Exception as e:  # noqa: BLE001 - mapped to actionable text by _handle_error
        return _handle_error(e, ip)


async def _lookup_domain(domain: str) -> str:
    """Look up a domain; return the normalized verdict (or an error line)."""
    key_err = _require_key()
    if key_err:
        return key_err
    try:
        data = await _vt_get(f"domains/{domain}")
        obj = data.get("data", {})
        return _normalize(domain, "domain", obj.get("id", domain), obj.get("attributes", {}))
    except Exception as e:  # noqa: BLE001 - mapped to actionable text by _handle_error
        return _handle_error(e, domain)


# --- Tools -----------------------------------------------------------------
@mcp.tool(
    name="vt_lookup_file_hash",
    annotations={
        "title": "VirusTotal File-Hash Reputation",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def vt_lookup_file_hash(params: HashLookupInput) -> str:
    """Look up a file hash's reputation on VirusTotal and return a normalized verdict.

    Use this when an investigation surfaces a file hash (MD5/SHA-1/SHA-256) and you
    need to know whether it is known-bad. Returns vendor detection counts, a
    reputation score, the top flagging engines, and a permalink -- not VirusTotal's
    full raw report.

    Args:
        params (HashLookupInput): Validated input containing:
            - file_hash (str): MD5/SHA-1/SHA-256 hex digest.

    Returns:
        str: On success, a JSON verdict:
            {
                "indicator": str,        # the hash queried
                "type": "file",
                "malicious": int,        # vendors flagging malicious
                "suspicious": int,
                "harmless": int,
                "undetected": int,
                "reputation": int | null,
                "flagged_by": [str, ...],  # up to 5 engine names
                "permalink": str         # VT GUI link
            }
        On failure, a single-line "Error: ..." or "Not found: ..." message.
    """
    return await _lookup_file(params.file_hash)


@mcp.tool(
    name="vt_lookup_url",
    annotations={
        "title": "VirusTotal URL Reputation",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def vt_lookup_url(params: UrlLookupInput) -> str:
    """Look up a URL's reputation on VirusTotal and return a normalized verdict.

    Use this when an investigation surfaces a URL and you need to know whether it
    is known-bad. Same normalized verdict shape as vt_lookup_file_hash, so callers
    treat both indicator types uniformly.

    Args:
        params (UrlLookupInput): Validated input containing:
            - url (str): The URL to look up, including scheme.

    Returns:
        str: On success, a JSON verdict with "type": "url" and the same fields as
            vt_lookup_file_hash. On failure, a single-line "Error: ..." or
            "Not found: ..." message (404 means VT has never seen this URL).
    """
    return await _lookup_url(params.url)


@mcp.tool(
    name="vt_lookup_ip_address",
    annotations={
        "title": "VirusTotal IP-Address Reputation",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def vt_lookup_ip_address(params: IpLookupInput) -> str:
    """Look up an IPv4 address's reputation on VirusTotal and return a normalized verdict.

    Use this when an investigation surfaces an IP (e.g. a C2 or staging host) and you
    need to know whether it is known-bad. Same normalized verdict shape as the other
    lookups, with "type": "ip_address".

    Args:
        params (IpLookupInput): Validated input containing:
            - ip (str): IPv4 address.

    Returns:
        str: On success, a JSON verdict with "type": "ip_address". On failure, a
            single-line "Error: ..." or "Not found: ..." message.
    """
    return await _lookup_ip(params.ip)


@mcp.tool(
    name="vt_lookup_domain",
    annotations={
        "title": "VirusTotal Domain Reputation",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def vt_lookup_domain(params: DomainLookupInput) -> str:
    """Look up a domain's reputation on VirusTotal and return a normalized verdict.

    Use this when an investigation surfaces a domain and you need to know whether it
    is known-bad. Same normalized verdict shape as the other lookups, with
    "type": "domain".

    Args:
        params (DomainLookupInput): Validated input containing:
            - domain (str): Domain name.

    Returns:
        str: On success, a JSON verdict with "type": "domain". On failure, a
            single-line "Error: ..." or "Not found: ..." message.
    """
    return await _lookup_domain(params.domain)


if __name__ == "__main__":
    mcp.run()
