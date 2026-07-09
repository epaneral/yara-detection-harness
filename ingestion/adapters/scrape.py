"""Scraped-source adapter: pull IOCs out of an HTML/text page, defang-aware.

Unstructured pages (advisories, paste dumps) list IOCs in prose and often *defang*
them -- hxxp://, 1.2.3[.]4, evil[.]com -- so a click doesn't arm them. This adapter
strips the HTML to visible text (BeautifulSoup), refangs those forms, and extracts
URLs, IPv4s, file hashes, and domains.

Bare domains are taken only when they were *defanged* in the source (or appear as a
URL host / email domain). That is deliberate: on a threat page the intended IOC
domains are defanged, while incidental domains and filenames (static.rust-lang.org,
install.sh) are not -- so defang-gating the bare-domain case keeps the noise out.
Text content only, not tag attributes: defanged IOCs live in prose, not live hrefs.
"""

from __future__ import annotations

import re

from bs4 import BeautifulSoup

from ingestion.adapters import read_source
from ingestion.record import Indicator

# --- Refang: undo common defanging so the extraction regexes see real IOCs. ---
_DOT_MARK = r"(?:\[\.\]|\(\.\)|\[dot\]|\(dot\))"
_DEFANG_SUBS = (
    (re.compile(r"hxxp", re.IGNORECASE), "http"),  # hxxp/hXXp -> http (covers hxxps)
    (re.compile(r"\[://\]"), "://"),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(_DOT_MARK, re.IGNORECASE), "."),
)
# A host token defanged with a dot-marker, e.g. bad[.]example or evil(dot)example.
_DEFANGED_HOST_RE = re.compile(rf"[a-z0-9-]+(?:{_DOT_MARK}[a-z0-9-]+)+", re.IGNORECASE)

# --- Extraction patterns (run on the refanged text). ---
_URL_RE = re.compile(r"""https?://[^\s"'<>)\]}|]+""", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b")
_EMAIL_RE = re.compile(r"[a-z0-9._%+-]+@([a-z0-9.-]+\.[a-z]{2,24})", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}", re.IGNORECASE)
_URL_TRAILING = ".,;:!?)\"']}>"


def _refang(text: str) -> str:
    for pat, repl in _DEFANG_SUBS:
        text = pat.sub(repl, text)
    return text


def _host_of(url: str) -> str:
    """Best-effort host of a URL: drop scheme, path/query/fragment, userinfo, and port."""
    rest = url.split("://", 1)[-1]
    host = re.split(r"[/?#]", rest, maxsplit=1)[0]
    host = host.rsplit("@", 1)[-1]
    return host.split(":", 1)[0]


class ScrapeAdapter:
    name = "scrape"

    def parse(self, source: str) -> list[Indicator]:
        page_text = BeautifulSoup(read_source(source), "html.parser").get_text(" ")

        found: dict[tuple[str, str], Indicator] = {}

        def add(indicator: str, type_: str) -> None:
            ind = Indicator(indicator=indicator, type=type_, source=self.name, source_ref=source)
            found.setdefault(ind.key, ind)

        # Defanged bare hosts, matched on the *original* text so only intentionally
        # defanged domains are picked up (a plain filename like install.sh is not).
        for token in _DEFANGED_HOST_RE.findall(page_text):
            host = _refang(token).lower()
            if _DOMAIN_RE.fullmatch(host):
                add(host, "domain")

        text = _refang(page_text)
        for digest in _HASH_RE.findall(text):
            add(digest.lower(), "file_hash")
        for match in _URL_RE.finditer(text):
            url = match.group(0).rstrip(_URL_TRAILING)
            add(url, "url")
            host = _host_of(url).lower()
            if _IPV4_RE.fullmatch(host):
                add(host, "ip_address")
            elif _DOMAIN_RE.fullmatch(host):
                add(host, "domain")
        for ip in _IPV4_RE.findall(text):
            add(ip, "ip_address")
        for domain in _EMAIL_RE.findall(text):
            add(domain.lower(), "domain")

        return list(found.values())
