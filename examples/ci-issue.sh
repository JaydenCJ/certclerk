#!/usr/bin/env bash
# The CI pattern: a pipeline step asks the CA for a 15-minute deploy
# certificate for the bot's key, then connects with plain OpenSSH.
# The policy pins ci-bot to one principal, one source network, and one
# forced command — a leaked cert is near-useless and dies in minutes.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

BIN="$WORKDIR/certclerk"
export CERTCLERK_DIR="$WORKDIR/ca"
(cd "$ROOT" && go build -o "$BIN" ./cmd/certclerk)
cd "$WORKDIR"

"$BIN" init >/dev/null
cp "$ROOT/examples/policy.json" ca/policy.json

# The bot's public key (in CI this already exists as a deploy credential).
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMDwkYmKPONYlvXDFs/LnxwI9UBXvhDjiIS73vCyMLZn ci-bot" > ci-bot.pub

echo "== mint the short-lived deploy certificate"
"$BIN" issue --user ci-bot --key ci-bot.pub
"$BIN" inspect ci-bot-cert.pub

echo
echo "== what the pipeline would run next (not executed here):"
echo "   ssh -i ci-bot -o CertificateFile=ci-bot-cert.pub deploy@app-01.example.test"
echo
echo "Note the certificate's critical options: sshd itself enforces the"
echo "source network and the forced command — no server-side scripts."
