#!/bin/bash
# Legitimate health check: probe whether a TCP port is open via bash's /dev/tcp,
# then report. Shares the reverse shell's signature feature (/dev/tcp) but spawns
# no interactive shell, so it is a near-miss for Shell_Reverse_TCP_Bash, not a hit.
host=192.0.2.5
port=5432
if timeout 1 bash -c "echo > /dev/tcp/$host/$port" 2>/dev/null; then
  echo "port $port on $host is reachable"
else
  echo "port $port on $host is closed"
fi
