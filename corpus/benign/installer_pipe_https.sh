#!/bin/sh
# Legitimate toolchain installer: fetch an install script over https from a NAMED host and
# pipe it to a shell (no-space pipe). Shares the dropper's fetch-into-shell shape but pulls
# from a named host, not a raw IP -- the raw-IP source is what Shell_Pipe_To_Shell_From_IP
# gates on, so this is a near-miss, not a hit.
wget -qO- https://get.example.org/install.sh|sh
