#!/bin/sh
# Legitimate toolchain installer (rustup-style): curl|sh, but https + named host + TLS pinning.
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.example.org | sh
