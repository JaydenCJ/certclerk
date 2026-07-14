#!/usr/bin/env bash
# The full certclerk lifecycle in one script: stand up a CA, install a
# policy, issue a short-lived certificate, verify it, revoke it, export
# the KRL, and prove the audit chain notices tampering. Self-contained:
# builds from the repo, works entirely in a temp directory.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

BIN="$WORKDIR/certclerk"
export CERTCLERK_DIR="$WORKDIR/ca"
(cd "$ROOT" && go build -o "$BIN" ./cmd/certclerk)
cd "$WORKDIR"

echo "== 1. create the CA and install the example policy"
"$BIN" init
cp "$ROOT/examples/policy.json" ca/policy.json
"$BIN" policy

echo
echo "== 2. issue alice a 30-minute certificate"
# A fixed demo key; in real life this is the user's own id_ed25519.pub.
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMDwkYmKPONYlvXDFs/LnxwI9UBXvhDjiIS73vCyMLZn alice@laptop" > alice.pub
"$BIN" issue --user alice --key alice.pub --ttl 30m
"$BIN" inspect alice-cert.pub

echo
echo "== 3. the policy says no to anything it does not cover"
"$BIN" issue --user alice --key alice.pub --principals root || echo "(denied, exit $?)"

echo
echo "== 4. verify, revoke, verify again"
"$BIN" verify alice-cert.pub
"$BIN" revoke --serial 1 --reason "laptop stolen"
"$BIN" verify alice-cert.pub || echo "(refused, exit $?)"

echo
echo "== 5. export the KRL for sshd's RevokedKeys"
"$BIN" krl --out revoked.krl

echo
echo "== 6. the audit log is a tamper-evident chain"
"$BIN" audit
"$BIN" audit --verify
sed -i.bak 's/"user":"alice"/"user":"mallory"/' ca/audit.log
"$BIN" audit --verify || echo "(tampering detected, exit $?)"
mv ca/audit.log.bak ca/audit.log

echo
echo "lifecycle demo complete"
