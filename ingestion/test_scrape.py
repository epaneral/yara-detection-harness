"""Unit tests for the scraped-source adapter (HTML -> defang-refang -> IOCs).

Scope: the committed fixture's exact IOC set, the refang behaviour for each
defanged form, and the defang-gated bare-domain rule. Inline HTML is written to
tmp_path and parsed by local path, so the tests stay fully offline.
"""

from pathlib import Path

from ingestion.adapters.scrape import ScrapeAdapter

FIXTURE = Path(__file__).parent / "fixtures" / "scrape.html"


def _pairs(records):
    return {(r.type, r.indicator) for r in records}


def _write(tmp_path, html):
    page = tmp_path / "page.html"
    page.write_text(html, encoding="utf-8")
    return str(page)


def test_name_is_scrape():
    assert ScrapeAdapter().name == "scrape"


def test_fixture_yields_exact_eight_iocs():
    recs = ScrapeAdapter().parse(str(FIXTURE))
    assert _pairs(recs) == {
        ("url", "http://192.0.2.10:8080/gate.php"),
        ("url", "https://bad.example/stage2.bin"),
        ("ip_address", "192.0.2.10"),
        ("ip_address", "192.0.2.44"),
        ("domain", "bad.example"),
        ("domain", "evil.example"),
        ("domain", "sink.example"),
        ("file_hash", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"),
    }


def test_fixture_sets_source_and_source_ref():
    recs = ScrapeAdapter().parse(str(FIXTURE))
    assert recs
    for rec in recs:
        assert rec.source == "scrape"
        assert rec.source_ref == str(FIXTURE)


def test_fixture_excludes_non_iocs():
    indicators = {r.indicator for r in ScrapeAdapter().parse(str(FIXTURE))}
    assert "static.rust-lang.org" not in indicators
    assert "install.sh" not in indicators


def test_refang_url_and_its_domain(tmp_path):
    source = _write(tmp_path, "<p>beacon to hxxp://evil[.]example/x</p>")
    pairs = _pairs(ScrapeAdapter().parse(source))
    assert ("url", "http://evil.example/x") in pairs
    assert ("domain", "evil.example") in pairs


def test_refang_defanged_ip(tmp_path):
    source = _write(tmp_path, "<p>C2 IP: 192.0.2[.]44</p>")
    pairs = _pairs(ScrapeAdapter().parse(source))
    assert ("ip_address", "192.0.2.44") in pairs


def test_refang_dot_word_domain(tmp_path):
    source = _write(tmp_path, "<p>domain bad(dot)example</p>")
    pairs = _pairs(ScrapeAdapter().parse(source))
    assert ("domain", "bad.example") in pairs


def test_non_defanged_filename_and_domain_are_ignored(tmp_path):
    source = _write(tmp_path, "<p>see notes.txt and example.org</p>")
    indicators = {r.indicator for r in ScrapeAdapter().parse(source)}
    assert "notes.txt" not in indicators
    assert "example.org" not in indicators


def test_url_host_that_is_ip_adds_ip_address(tmp_path):
    source = _write(tmp_path, "<p>callback hxxp://192.0.2.10:8080/gate.php</p>")
    pairs = _pairs(ScrapeAdapter().parse(source))
    assert ("url", "http://192.0.2.10:8080/gate.php") in pairs
    assert ("ip_address", "192.0.2.10") in pairs


def test_email_domain_is_extracted(tmp_path):
    source = _write(tmp_path, "<p>exfil to a@mail[.]example</p>")
    pairs = _pairs(ScrapeAdapter().parse(source))
    assert ("domain", "mail.example") in pairs


def test_page_with_no_iocs_returns_empty(tmp_path):
    source = _write(tmp_path, "<p>nothing here</p>")
    assert ScrapeAdapter().parse(source) == []


def test_hash_is_lowercased_and_typed_as_file_hash(tmp_path):
    digest = "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F"
    source = _write(tmp_path, f"<p>SHA-256: {digest}</p>")
    pairs = _pairs(ScrapeAdapter().parse(source))
    assert ("file_hash", digest.lower()) in pairs
