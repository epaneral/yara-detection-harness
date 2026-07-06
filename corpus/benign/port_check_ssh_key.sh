#!/bin/bash
# Legitimate deploy health check: probe the app port via bash's /dev/tcp, then pull
# uptime over ssh with an identity file. "ssh -i" contains the rule's interactive-shell
# atom as a substring -- the fullword gate on Shell_Reverse_TCP_Bash is what keeps this
# a near-miss instead of a hit.
host=192.0.2.6
if timeout 1 bash -c "echo > /dev/tcp/$host/8443" 2>/dev/null; then
  ssh -i ~/.ssh/deploy_key ops@"$host" uptime
else
  echo "app port 8443 on $host is unreachable"
fi
