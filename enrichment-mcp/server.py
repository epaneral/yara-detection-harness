#!/usr/bin/env python3
"""
VirusTotal enrichment MCP server.

The enrichment layer for the yara-detection-harness. The harness detects
malicious *patterns*; the natural next question in an investigation is
"this rule fired -- is the indicator it surfaced actually known-bad?"
This server wraps the VirusTotal v3 reputation API as MCP tools an LLM agent
can call mid-investigation, returning a *normalized* verdict for an indicator
(a file hash, URL, IP, or domain) instead of VirusTotal's full raw report.

Design notes:
  - Read-only. Reputation lookups only -- nothing here submits, mutates, or deletes.
  - Sources sit behind a small adapter interface (ReputationSource). VirusTotal
    and URLhaus are wired in, and the lookup_indicator tool fans out across every
    configured source, returning each one's verdict under the SAME normalized
    shape plus a combined consensus. More sources slot in without changing that shape.
  - API key is read from the VT_API_KEY environment variable, never hardcoded.
  - Local stdio transport: launched as a subprocess by an MCP client.
  - One pooled HTTP client is reused across lookups (closed on shutdown), and a
    transient 429/5xx is retried with bounded backoff before it degrades to the
    usual one-line error.
  - Successful lookups are served through a small in-process TTL cache, so
    repeated indicators (including across an investigate_sample run) do not
    re-hit VirusTotal.

Scope fence (deliberately NOT built here yet): further sources (urlscan/Censys),
durable cache persistence, and a formal eval suite. See README.md "Roadmap" and
multi-source-design.md for those.
"""

import asyncio
import base64
import ipaddress
import json
import os
import re
import time
from collections import OrderedDict
from contextlib import asynccontextmanager
from typing import Literal

import httpx
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

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
# URLhaus (abuse.ch): a read-only reputation source. Its lookup endpoints are
# POSTs (query-only, nothing submitted) authenticated with a free Auth-Key,
# mandatory since 2025-06-30. A missing key just skips the source in the fan-out.
URLHAUS_API_BASE = "https://urlhaus-api.abuse.ch/v1"
URLHAUS_API_KEY = os.environ.get("URLHAUS_API_KEY", "")
REQUEST_TIMEOUT = 30.0  # seconds

# Retry policy for *transient* failures only (429 rate-limit and 5xx). Bounded
# so a persistently failing endpoint still returns an actionable one-line
# message rather than hanging: at most MAX_RETRIES extra attempts, each preceded
# by a wait that honors a Retry-After header when present, else grows
# exponentially (BACKOFF_BASE_SECONDS * 2**attempt) up to BACKOFF_MAX_SECONDS.
MAX_RETRIES = 3
RETRY_STATUS_CODES = frozenset({429, 500, 502, 503, 504})
BACKOFF_BASE_SECONDS = 0.5
BACKOFF_MAX_SECONDS = 8.0
RETRY_AFTER_MAX_SECONDS = 60.0  # cap an honored Retry-After so a huge value can't stall us

# In-process read-through lookup cache. Keyed by VT resource path (which uniquely
# encodes an indicator's type and value), so repeated lookups -- and an
# investigate_sample run whose indicators overlap a prior lookup -- reuse the
# stored response instead of re-hitting VirusTotal. Bounded by TTL (a verdict
# stays fresh enough within one investigation) and entry count (oldest evicted).
# In-memory only; durable persistence is deliberately left for later.
CACHE_TTL_SECONDS = 300.0
CACHE_MAX_ENTRIES = 512

# Indicator-extraction patterns. Domains are taken from URL hosts and email
# addresses only; standalone bare-domain scanning is skipped because dotted code
# identifiers (e.g. System.Net.WebClient) are indistinguishable from domains
# without a TLD list (future work).
# "|" is excluded: it must be %-encoded in a URL (RFC 3986), and in shell samples it
# is pipe syntax -- "curl https://192.0.2.88/x|bash" ends the URL at the pipe.
# ")", "]", "}" are excluded on the same reasoning: sample text wraps URLs in prose
# and code -- "(see http://x/a)" must end at the ")". The accepted cost is that a
# literal bracket in a path ("http://x/items[0]") truncates the match there; RFC 3986
# wants those %-encoded anyway, and prose-wrapped URLs dominate in scanned samples.
_URL_RE = re.compile(r"""https?://[^\s"'<>)\]}|]+""", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_EMAIL_RE = re.compile(r"[a-z0-9._%+-]+@([a-z0-9.-]+\.[a-z]{2,63})", re.IGNORECASE)
# Domain label/TLD shape (LDH); validates domain input (DomainLookupInput).
_DOMAIN_RE = re.compile(
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}",
    re.IGNORECASE,
)
_URL_TRAILING_PUNCT = ".,;:!?)\"']}>"


# --- Shared HTTP client ----------------------------------------------------
# One pooled AsyncClient is reused across every lookup instead of standing up a
# fresh connection pool per request. Created lazily on first use (so importing
# the module -- and the offline tests, which stub _vt_get -- never opens a real
# client or socket) and closed on server shutdown by the lifespan hook below.
_client: httpx.AsyncClient | None = None


def _get_client() -> httpx.AsyncClient:
    """Return the shared AsyncClient, creating it on first use."""
    global _client
    if _client is None:
        _client = httpx.AsyncClient(timeout=REQUEST_TIMEOUT)
    return _client


async def _close_client() -> None:
    """Close and drop the shared client (idempotent). Called on shutdown."""
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


@asynccontextmanager
async def _lifespan(_server: FastMCP):
    """Own the shared client's lifecycle: nothing to set up (it's created lazily
    on the first lookup), but close it on shutdown so the pool doesn't leak."""
    try:
        yield
    finally:
        await _close_client()


mcp = FastMCP("virustotal_mcp", lifespan=_lifespan)


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

    @field_validator("url")
    @classmethod
    def _validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v.lower().startswith(("http://", "https://")):
            raise ValueError("URL must include an http:// or https:// scheme")
        return v


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


class ExtractInput(BaseModel):
    """Input for indicator extraction from sample text."""

    model_config = ConfigDict(extra="forbid")

    text: str = Field(
        ...,
        description="Sample text (e.g. a flagged corpus sample) to scan for indicators",
        min_length=1,
        max_length=200_000,
    )


class InvestigateInput(BaseModel):
    """Input for a chained sample investigation."""

    model_config = ConfigDict(extra="forbid")

    text: str = Field(
        ...,
        description="Sample text to extract indicators from and look up",
        min_length=1,
        max_length=200_000,
    )
    max_indicators: int = Field(
        10,
        description="Max indicators to look up (the rest are reported as skipped)",
        ge=1,
        le=25,
    )
    delay_seconds: float = Field(
        0.0,
        description="Pause between successive lookups; ~15 stays under the VT free-tier ~4/min",
        ge=0.0,
        le=60.0,
    )


# Maps an indicator kind to the existing typed input model (and its field) that
# validates and normalizes it, so lookup_indicator reuses the exact same rules as
# the vt_lookup_* tools instead of duplicating them.
_KIND_INPUT = {
    "file": (HashLookupInput, "file_hash"),
    "url": (UrlLookupInput, "url"),
    "ip_address": (IpLookupInput, "ip"),
    "domain": (DomainLookupInput, "domain"),
}


class IndicatorLookupInput(BaseModel):
    """Input for a multi-source lookup of a single indicator of any of the four kinds."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    indicator: str = Field(
        ...,
        description="The indicator value: file hash, URL (incl. scheme), IPv4, or domain",
        min_length=1,
        max_length=2048,
    )
    type: Literal["file", "url", "ip_address", "domain"] = Field(
        ...,
        description="Indicator kind: 'file' (hash), 'url', 'ip_address', or 'domain'",
    )

    @model_validator(mode="after")
    def _validate_indicator_for_type(self) -> "IndicatorLookupInput":
        # Delegate to the matching typed model so the value is validated and
        # normalized identically to the single-source tools (e.g. lowercased hash).
        model_cls, field = _KIND_INPUT[self.type]
        try:
            validated = model_cls(**{field: self.indicator})
        except ValidationError as err:
            msg = err.errors()[0].get("msg", "invalid indicator")
            raise ValueError(f"invalid {self.type} indicator: {msg}") from err
        self.indicator = getattr(validated, field)
        return self


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


class _TTLCache:
    """A tiny bounded, time-to-live cache for successful lookups.

    Read-through and in-memory: _vt_get consults it before any network call and
    stores only successful responses, so a transient 429/5xx or a 404 is never
    cached. Bounded two ways -- each entry expires after `ttl` seconds, and the
    store holds at most `max_entries` (the oldest is evicted first). The clock is
    injectable so expiry is testable without real time passing.
    """

    def __init__(self, ttl: float, max_entries: int, clock=time.monotonic):
        self._ttl = ttl
        self._max = max_entries
        self._clock = clock
        self._store: OrderedDict[str, tuple[float, dict]] = OrderedDict()

    def get(self, key: str) -> dict | None:
        entry = self._store.get(key)
        if entry is None:
            return None
        expires_at, value = entry
        if self._clock() >= expires_at:
            del self._store[key]  # lazily drop the expired entry
            return None
        self._store.move_to_end(key)  # mark as most-recently used
        return value

    def set(self, key: str, value: dict) -> None:
        self._store[key] = (self._clock() + self._ttl, value)
        self._store.move_to_end(key)
        while len(self._store) > self._max:
            self._store.popitem(last=False)  # evict the oldest entry

    def clear(self) -> None:
        self._store.clear()


_cache = _TTLCache(CACHE_TTL_SECONDS, CACHE_MAX_ENTRIES)


def _retry_delay(resp: httpx.Response, attempt: int) -> float:
    """Seconds to wait before the next retry.

    Honors a numeric Retry-After header (capped, so a hostile/huge value can't
    stall us); the HTTP-date form is not parsed and falls through to bounded
    exponential backoff (BACKOFF_BASE_SECONDS * 2**attempt, capped).
    """
    retry_after = resp.headers.get("Retry-After")
    if retry_after:
        try:
            secs = float(retry_after)
        except ValueError:
            pass  # HTTP-date form -- fall through to backoff
        else:
            return max(0.0, min(secs, RETRY_AFTER_MAX_SECONDS))
    return min(BACKOFF_BASE_SECONDS * (2**attempt), BACKOFF_MAX_SECONDS)


async def _request_json(
    method: str, url: str, *, headers: dict, data: dict | None = None, cache_key: str
) -> dict:
    """Shared read-through + retry wrapper for a JSON GET/POST via the shared client.

    A fresh cache hit for `cache_key` skips the network entirely. On a miss, a 429
    or transient 5xx is retried up to MAX_RETRIES times (waiting per _retry_delay
    between attempts); once retries are exhausted the final response's status
    raises, and every other error propagates immediately, so each source maps it
    to its own one-line message. Only a successful response is cached. Dispatches
    on method with client.get/client.post (not client.request) so existing GET
    fakes keep working.
    """
    cached = _cache.get(cache_key)
    if cached is not None:
        return cached

    client = _get_client()
    for attempt in range(MAX_RETRIES + 1):
        if method == "POST":
            resp = await client.post(url, headers=headers, data=data)
        else:
            resp = await client.get(url, headers=headers)
        if resp.status_code in RETRY_STATUS_CODES and attempt < MAX_RETRIES:
            await asyncio.sleep(_retry_delay(resp, attempt))
            continue
        resp.raise_for_status()
        payload = resp.json()
        _cache.set(cache_key, payload)
        return payload


async def _vt_get(path: str) -> dict:
    """GET {VT_API_BASE}/{path} with auth, via the shared cached/retrying wrapper.

    The cache key is the VT path (which uniquely encodes the indicator's type and
    value); see _request_json for the retry/cache behavior.
    """
    return await _request_json(
        "GET", f"{VT_API_BASE}/{path}", headers={"x-apikey": VT_API_KEY}, cache_key=path
    )


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


def _verdict(
    indicator: str,
    kind: str,
    *,
    malicious: int = 0,
    suspicious: int = 0,
    harmless: int = 0,
    undetected: int = 0,
    reputation=None,
    flagged_by=(),
    permalink: str = "",
) -> str:
    """Build the normalized verdict JSON that EVERY source returns (the answer, not
    a raw blob). Centralized so VirusTotal and other sources can't drift in shape;
    flagged_by is capped at five names.
    """
    return json.dumps(
        {
            "indicator": indicator,
            "type": kind,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "reputation": reputation,
            "flagged_by": list(flagged_by)[:5],
            "permalink": permalink,
        },
        indent=2,
    )


def _normalize(
    indicator: str, kind: str, gui_id: str, attributes: dict, gui_kind: str | None = None
) -> str:
    """Collapse a VirusTotal object's attributes into the normalized verdict.

    This is the point of the server: return the *answer*, not VT's full blob.
    gui_kind overrides the permalink path segment when it differs from the verdict
    type (e.g. permalink 'ip-address' vs type 'ip_address').
    """
    stats = attributes.get("last_analysis_stats", {}) or {}
    results = attributes.get("last_analysis_results", {}) or {}

    flagged = sorted(
        engine
        for engine, r in results.items()
        if (r or {}).get("category") in ("malicious", "suspicious")
    )

    return _verdict(
        indicator,
        kind,
        malicious=stats.get("malicious", 0),
        suspicious=stats.get("suspicious", 0),
        harmless=stats.get("harmless", 0),
        undetected=stats.get("undetected", 0),
        reputation=attributes.get("reputation"),
        flagged_by=flagged,
        permalink=f"https://www.virustotal.com/gui/{gui_kind or kind}/{gui_id}",
    )


def _extract_indicators(text: str) -> list[dict]:
    """Extract network indicators (URLs, bare IPv4s, email domains) from sample text.

    URLs are matched first and their spans masked, so a host *inside* a URL is not
    re-emitted as a separate IP. Domains come from email addresses only -- URL hosts
    are already captured as URLs, and standalone bare-domain scanning is skipped
    because dotted code identifiers (e.g. System.Net.WebClient) are indistinguishable
    from domains without a TLD list. No file hashes (the corpus has none).

    Returns [{"indicator": str, "type": "url"|"ip_address"|"domain"}], deduped
    case-insensitively, ordered URLs then IPs then domains (first-seen within each).
    """
    indicators: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(value: str, kind: str) -> None:
        key = (kind, value.lower())
        if key not in seen:
            seen.add(key)
            indicators.append({"indicator": value, "type": kind})

    # URLs first; blank their spans so hosts inside a URL aren't re-counted.
    masked = list(text)
    for m in _URL_RE.finditer(text):
        url = m.group(0).rstrip(_URL_TRAILING_PUNCT)
        add(url, "url")
        for i in range(m.start(), m.start() + len(url)):
            masked[i] = " "
    masked_text = "".join(masked)

    for m in _IPV4_RE.finditer(masked_text):
        add(m.group(0), "ip_address")

    # Domains: from email addresses only (URL hosts are already covered above).
    for m in _EMAIL_RE.finditer(masked_text):
        add(m.group(1).lower(), "domain")

    return indicators


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


async def _dispatch_lookup(indicator: dict) -> str:
    """Route an extracted indicator to the matching per-type lookup."""
    value, kind = indicator["indicator"], indicator["type"]
    if kind == "url":
        return await _lookup_url(value)
    if kind == "ip_address":
        return await _lookup_ip(value)
    if kind == "domain":
        return await _lookup_domain(value)
    return f"Error: unknown indicator type '{kind}'"


# --- Reputation sources (adapter layer for multi-source fan-out) ------------
class ReputationSource:
    """Interface every reputation source implements so the fan-out treats them
    uniformly. A source answers a supported indicator kind with the normalized
    verdict shape (a JSON string) or an actionable error line -- the same
    contract the per-indicator lookups above already honor.
    """

    name: str = ""

    def supports(self, kind: str) -> bool:
        """Whether this source can answer the given indicator kind."""
        raise NotImplementedError

    def configured(self) -> bool:
        """Whether this source has the credentials it needs (else it's skipped)."""
        raise NotImplementedError

    async def lookup(self, kind: str, value: str) -> str:
        """Return the normalized verdict JSON, or an actionable error line."""
        raise NotImplementedError


class VirusTotalSource(ReputationSource):
    """VirusTotal adapter -- the first (and today only) source. It wraps the
    existing per-kind VT lookups unchanged; more sources slot in behind this
    same interface without touching it or the normalized verdict shape.
    """

    name = "virustotal"

    def supports(self, kind: str) -> bool:
        return kind in ("file", "url", "ip_address", "domain")

    def configured(self) -> bool:
        return bool(VT_API_KEY)

    async def lookup(self, kind: str, value: str) -> str:
        if kind == "file":
            return await _lookup_file(value)
        if kind == "url":
            return await _lookup_url(value)
        if kind == "ip_address":
            return await _lookup_ip(value)
        if kind == "domain":
            return await _lookup_domain(value)
        return f"Error: unknown indicator type '{kind}'"


async def _urlhaus_query(endpoint: str, data: dict) -> dict:
    """POST a read-only query to a URLhaus endpoint and return the parsed JSON."""
    # A source-prefixed cache key so URLhaus entries never collide with VT paths
    # and repeated URLhaus lookups (or overlapping investigate_sample runs) reuse it.
    cache_key = "urlhaus:" + endpoint + ":" + ":".join(f"{k}={v}" for k, v in sorted(data.items()))
    return await _request_json(
        "POST",
        f"{URLHAUS_API_BASE}/{endpoint}/",
        headers={"Auth-Key": URLHAUS_API_KEY},
        data=data,
        cache_key=cache_key,
    )


def _urlhaus_error(e: Exception, indicator: str) -> str:
    """Map a URLhaus transport error to an actionable line (no stack traces)."""
    if isinstance(e, httpx.HTTPStatusError):
        code = e.response.status_code
        if code == 401:
            return "Error: URLhaus rejected the API key (401). Check that URLHAUS_API_KEY is valid."
        if code == 429:
            return "Error: URLhaus rate limit hit (429) -- wait a moment and retry."
        return f"Error: URLhaus returned HTTP {code} for '{indicator}'."
    if isinstance(e, httpx.TimeoutException):
        return f"Error: request to URLhaus timed out after {REQUEST_TIMEOUT:.0f}s. Try again."
    if isinstance(e, httpx.RequestError):
        return f"Error: network error contacting URLhaus ({type(e).__name__}). Check connectivity."
    return f"Error: unexpected {type(e).__name__} while looking up '{indicator}' on URLhaus."


def _urlhaus_verdict(indicator: str, kind: str, data: dict) -> str:
    """Map a URLhaus response into the normalized verdict (or a not-found/error line).

    URLhaus is a blocklist of *known-malicious* URLs, so a `query_status: ok` means
    the indicator is bad: malicious = the number of listed URLs (1 for a URL lookup,
    url_count for a host), flagged_by = URLhaus plus any external blacklist listing
    it. `no_results` is 'no data' (a not-found, like a VT 404); anything else
    (invalid_*, http_post_expected) is an error.
    """
    status = data.get("query_status")
    if status == "no_results":
        return f"Not found: '{indicator}' is not in URLhaus's dataset (no reputation data)."
    if status != "ok":
        return f"Error: URLhaus returned query_status '{status}' for '{indicator}'."

    if kind == "url":
        malicious = 1
    else:  # host lookup (ip_address / domain)
        try:
            malicious = int(data.get("url_count"))  # preferred: the true total
        except (TypeError, ValueError):
            malicious = len(data.get("urls") or [])  # missing/non-numeric -> count returned URLs

    blacklists = data.get("blacklists") or {}
    listed = sorted(name for name, st in blacklists.items() if st and st != "not listed")
    flagged = ["urlhaus", *listed]
    return _verdict(
        indicator,
        kind,
        malicious=malicious,
        flagged_by=flagged,
        permalink=data.get("urlhaus_reference", ""),
    )


class URLhausSource(ReputationSource):
    """URLhaus (abuse.ch) adapter. Answers url/ip/domain via the host and url query
    endpoints (read-only POSTs); file-hash payload lookups are a later extension.
    Behind the same interface and normalized shape as VirusTotal.
    """

    name = "urlhaus"

    def supports(self, kind: str) -> bool:
        return kind in ("url", "ip_address", "domain")

    def configured(self) -> bool:
        return bool(URLHAUS_API_KEY)

    async def lookup(self, kind: str, value: str) -> str:
        try:
            if kind == "url":
                data = await _urlhaus_query("url", {"url": value})
            else:  # ip_address or domain -> host endpoint
                data = await _urlhaus_query("host", {"host": value})
        except Exception as e:  # noqa: BLE001 - mapped to actionable text by _urlhaus_error
            return _urlhaus_error(e, value)
        return _urlhaus_verdict(value, kind, data)


# The source registry the fan-out iterates; order here is the display order in
# the envelope's per-source map. New sources are appended.
_SOURCES: list[ReputationSource] = [VirusTotalSource(), URLhausSource()]


def _sources_for(kind: str) -> tuple[list[ReputationSource], list[str]]:
    """Partition the sources that support `kind` into (configured, skipped-names)."""
    supporting = [s for s in _SOURCES if s.supports(kind)]
    active = [s for s in supporting if s.configured()]
    skipped = [s.name for s in supporting if not s.configured()]
    return active, skipped


def _no_source_configured(kind: str) -> str:
    """Actionable one-line message when no configured source can answer `kind`."""
    # Only VirusTotal exists today, so a missing key is the cause; _require_key's
    # message names the env var and where to get a key. Generalizes as sources grow.
    key_err = _require_key()
    if key_err:
        return key_err
    return f"Error: no configured reputation source supports '{kind}' indicators."


def _classify_source_result(raw: str) -> dict:
    """Map a source's raw return into its envelope entry: a parsed verdict, a
    not-found marker, or an error marker (mirrors investigate_sample's row rule).
    """
    try:
        return json.loads(raw)
    except ValueError:
        if raw.startswith("Not found:"):
            return {"not_found": raw}
        return {"error": raw}


def _build_consensus(sources: dict, skipped: list[str]) -> dict:
    """Summarize per-source verdicts WITHOUT merging incomparable counts.

    Reports booleans plus rosters (which sources called it malicious/suspicious),
    the max malicious count seen (a severity hint, never a sum across sources),
    and which sources completed, were skipped (unconfigured), or errored.
    """
    malicious, suspicious, completed, errored = [], [], [], []
    max_malicious = 0
    for name, entry in sources.items():
        if "error" in entry:
            errored.append(name)
            continue
        completed.append(name)  # a verdict or a not-found both mean the source answered
        mal = entry.get("malicious", 0) or 0
        sus = entry.get("suspicious", 0) or 0
        if mal > 0:
            malicious.append(name)
            max_malicious = max(max_malicious, mal)
        if sus > 0:
            suspicious.append(name)
    return {
        "malicious": bool(malicious),
        "suspicious": bool(suspicious),
        "sources_malicious": sorted(malicious),
        "sources_suspicious": sorted(suspicious),
        "max_malicious": max_malicious,
        "sources_completed": sorted(completed),
        "sources_skipped": sorted(skipped),
        "sources_errored": sorted(errored),
    }


async def _fanout_lookup(kind: str, value: str) -> dict:
    """Query every configured source that supports `kind` concurrently and build
    the multi-source envelope (per-source verdicts + a consensus).
    """
    active, skipped = _sources_for(kind)
    results = await asyncio.gather(*(s.lookup(kind, value) for s in active))
    sources = {
        src.name: _classify_source_result(raw) for src, raw in zip(active, results, strict=True)
    }
    return {
        "indicator": value,
        "type": kind,
        "sources": sources,
        "consensus": _build_consensus(sources, skipped),
    }


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


@mcp.tool(
    name="lookup_indicator",
    annotations={
        "title": "Multi-Source Indicator Reputation",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def lookup_indicator(params: IndicatorLookupInput) -> str:
    """Look up one indicator across every configured reputation source and return a
    combined envelope: each source's normalized verdict plus a consensus.

    Use this when you want more than one source's opinion on an indicator. Today
    only VirusTotal is wired in, so the envelope carries a single source; as more
    sources are added they appear alongside it under the SAME per-source verdict
    shape the vt_lookup_* tools return. Counts are never merged across sources
    (they aren't comparable) -- only summarized in `consensus`.

    A source with no API key is silently skipped (named in
    `consensus.sources_skipped`), and a per-source error becomes that source's
    `error` entry without sinking the others. If no configured source can answer
    the given kind, a single actionable line is returned instead.

    Args:
        params (IndicatorLookupInput): Validated input containing:
            - indicator (str): the value (hash, URL incl. scheme, IPv4, or domain).
            - type (str): 'file', 'url', 'ip_address', or 'domain'.

    Returns:
        str: On success, a JSON envelope:
            {
                "indicator": str,
                "type": str,
                "sources": {
                    "<name>": <verdict> | {"error": str} | {"not_found": str}, ...
                },
                "consensus": {
                    "malicious": bool,              # any source with malicious > 0
                    "suspicious": bool,             # any source with suspicious > 0
                    "sources_malicious": [str, ...],
                    "sources_suspicious": [str, ...],
                    "max_malicious": int,           # max across sources, never a sum
                    "sources_completed": [str, ...],
                    "sources_skipped": [str, ...],  # not configured (no key)
                    "sources_errored": [str, ...]
                }
            }
        On no configured source for the kind, a single-line "Error: ..." message.
    """
    kind, value = params.type, params.indicator
    active, _skipped = _sources_for(kind)
    if not active:
        return _no_source_configured(kind)
    return json.dumps(await _fanout_lookup(kind, value), indent=2)


@mcp.tool(
    name="extract_indicators",
    annotations={
        "title": "Extract Indicators from Text",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
def extract_indicators(params: ExtractInput) -> str:
    """Extract network indicators (URLs, IPv4s, domains) from sample text.

    Pure and local -- no network, no API key. Use this to triage a flagged sample
    before spending lookup budget, or to choose which indicators to look up.

    Args:
        params (ExtractInput): Validated input containing:
            - text (str): the sample text to scan.

    Returns:
        str: JSON {"count": int, "indicators": [{"indicator": str, "type": str}]}
            where type is "url", "ip_address", or "domain".
    """
    inds = _extract_indicators(params.text)
    return json.dumps({"count": len(inds), "indicators": inds}, indent=2)


@mcp.tool(
    name="investigate_sample",
    annotations={
        "title": "Investigate Sample (extract + chain lookups)",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def investigate_sample(params: InvestigateInput) -> str:
    """Extract indicators from sample text and chain a VirusTotal lookup for each.

    The chained capability behind the "auto-extract + chain" roadmap item: hand it a
    flagged sample's text and it extracts the indicators, looks each up sequentially
    (for stable ordering and output), and returns one aggregated report. Lookups are
    unpaced by default; on the free tier (~4/min) that can surface as per-row 429
    errors -- set delay_seconds to pace them. A single indicator's 404/429/error
    becomes that row's "error" without sinking the rest.

    Args:
        params (InvestigateInput): Validated input containing:
            - text (str): the sample text.
            - max_indicators (int): cap on lookups (default 10, max 25).
            - delay_seconds (float): pause between successive lookups (default 0,
              max 60); ~15 stays under the free-tier rate limit.

    Returns:
        str: JSON with a "summary" tally, per-indicator "results" (each carrying a
            "verdict" or an "error"), any "skipped" indicators beyond the cap, and a
            "note". On a missing key, the single-line key-not-set message.
    """
    key_err = _require_key()
    if key_err:
        return key_err

    indicators = _extract_indicators(params.text)
    looked = indicators[: params.max_indicators]
    skipped = indicators[params.max_indicators :]

    tally = {"malicious": 0, "suspicious": 0, "clean_or_unknown": 0, "not_found": 0, "errors": 0}
    results = []
    for i, ind in enumerate(looked):
        if i and params.delay_seconds:
            await asyncio.sleep(params.delay_seconds)
        raw = await _dispatch_lookup(ind)
        row = {"indicator": ind["indicator"], "type": ind["type"]}
        try:
            verdict = json.loads(raw)
        except ValueError:
            row["error"] = raw
            tally["not_found" if raw.startswith("Not found:") else "errors"] += 1
        else:
            row["verdict"] = verdict
            if verdict.get("malicious", 0) > 0:
                tally["malicious"] += 1
            elif verdict.get("suspicious", 0) > 0:
                tally["suspicious"] += 1
            else:
                tally["clean_or_unknown"] += 1
        results.append(row)

    report = {
        "summary": {
            "indicators_found": len(indicators),
            "looked_up": len(looked),
            "skipped_for_cap": len(skipped),
            **tally,
        },
        "results": results,
        "skipped": skipped,
        "note": (
            f"Looked up {len(looked)} of {len(indicators)} indicators sequentially, "
            + (
                f"paced {params.delay_seconds:g}s apart"
                if params.delay_seconds
                else "with no pacing delay (set delay_seconds to pace)"
            )
            + "; VT free tier is ~4/min, 500/day."
        ),
    }
    return json.dumps(report, indent=2)


if __name__ == "__main__":
    mcp.run()
