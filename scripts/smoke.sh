#!/usr/bin/env bash
# End-to-end smoke test for certclerk: builds the binary, stands up a
# real CA in a temp dir, walks the whole lifecycle (init -> policy ->
# issue -> verify -> revoke -> KRL -> audit), and asserts on real CLI
# output and exit codes. No network, idempotent, finishes in seconds.
# If ssh-keygen is installed, the issued certificate and exported KRL
# are additionally cross-checked against OpenSSH itself.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

fail() {
  echo "SMOKE FAIL: $*" >&2
  exit 1
}

BIN="$WORKDIR/certclerk"
export CERTCLERK_DIR="$WORKDIR/ca"

echo "1. build"
(cd "$ROOT" && go build -o "$BIN" ./cmd/certclerk) || fail "go build failed"

echo "2. version matches manifest"
"$BIN" --version | grep -qx "certclerk 0.1.0" || fail "--version mismatch"

echo "3. init a CA"
cd "$WORKDIR"
"$BIN" init | grep >/dev/null "CA fingerprint: SHA256:" || fail "init did not print a fingerprint"
[ -f ca/ca.key ] && [ -f ca/ca.pub ] && [ -f ca/policy.json ] || fail "CA state files missing"
if "$BIN" init >/dev/null 2>&1; then
  fail "re-init should refuse to overwrite the CA"
fi

echo "4. install a policy and read it back"
cat > ca/policy.json <<'EOF'
{
  "version": 1,
  "defaults": {"max_ttl": "8h", "extensions": ["permit-pty"]},
  "users": {
    "alice":  {"principals": ["alice", "deploy"], "max_ttl": "1h"},
    "ci-bot": {"principals": ["deploy"], "max_ttl": "15m", "extensions": [],
               "source_address": ["10.0.0.0/8"], "force_command": "/usr/local/bin/deploy"}
  }
}
EOF
"$BIN" policy | grep >/dev/null "alice .*principals=alice,deploy max_ttl=1h" || fail "policy summary wrong"
"$BIN" policy --user ci-bot | grep >/dev/null "source_address: 10.0.0.0/8" || fail "effective rule wrong"

echo "5. issue a short-lived certificate"
# A fixed, valid ed25519 public key — no ssh-keygen needed to run this script.
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMDwkYmKPONYlvXDFs/LnxwI9UBXvhDjiIS73vCyMLZn alice@laptop" > alice.pub
OUT="$("$BIN" issue --user alice --key alice.pub --ttl 30m)"
echo "$OUT" | grep >/dev/null "issued serial 1 to alice: principals alice,deploy, valid 30m" || fail "issue output wrong: $OUT"
[ -f alice-cert.pub ] || fail "certificate file not written"
grep -q "^ssh-ed25519-cert-v01@openssh.com " alice-cert.pub || fail "cert line malformed"

echo "6. inspect explains the certificate"
"$BIN" inspect alice-cert.pub | grep >/dev/null 'Key ID: "alice@certclerk-1"' || fail "inspect key id missing"
"$BIN" inspect alice-cert.pub | grep >/dev/null "Principals: alice,deploy" || fail "inspect principals missing"
"$BIN" inspect --format json alice-cert.pub | grep >/dev/null '"serial": 1' || fail "inspect json missing serial"

echo "7. verify: fresh OK, far future expired (exit 1)"
"$BIN" verify alice-cert.pub | grep >/dev/null "^OK: serial 1" || fail "fresh cert should verify"
if "$BIN" verify --at 2033-01-01T00:00:00Z alice-cert.pub >/dev/null 2>&1; then
  fail "expired cert should not verify"
fi

echo "8. policy denials exit 1"
if "$BIN" issue --user alice --key alice.pub --principals root >/dev/null 2>&1; then
  fail "disallowed principal should be denied"
fi
if "$BIN" issue --user alice --key alice.pub --ttl 2h >/dev/null 2>&1; then
  fail "over-cap ttl should be denied"
fi
if "$BIN" issue --user mallory --key alice.pub >/dev/null 2>&1; then
  fail "unknown user should be denied"
fi

echo "9. revoke, then verify reports it"
"$BIN" revoke --serial 1 --reason "laptop stolen" | grep >/dev/null "revoked serial 1" || fail "revoke output wrong"
# (|| true keeps pipefail from eating grep's verdict — verify exits 1 here.)
("$BIN" verify alice-cert.pub 2>&1 || true) | grep >/dev/null "revoked" || fail "verify should report revocation"
if "$BIN" revoke --serial 1 >/dev/null 2>&1; then
  fail "double revocation should fail"
fi

echo "10. export a binary KRL"
"$BIN" krl --out revoked.krl | grep >/dev/null "1 revocation," || fail "krl output wrong"
[ "$(head -c 6 revoked.krl)" = "SSHKRL" ] || fail "KRL magic missing"

echo "11. audit log is complete and chain-verified"
"$BIN" audit | grep >/dev/null '#2 .*issue .*user=alice serial=1' || fail "audit missing the issuance"
"$BIN" audit | grep >/dev/null '#3 .*revoke.*reason="laptop stolen"' || fail "audit missing the revocation"
"$BIN" audit --verify | grep >/dev/null "audit ok: 3 entries, chain intact" || fail "audit chain broken"

echo "12. tampering with the audit log is detected (exit 1)"
sed -i.bak 's/"user":"alice"/"user":"mallory"/' ca/audit.log
if "$BIN" audit --verify >/dev/null 2>&1; then
  fail "tampered audit log should not verify"
fi
mv ca/audit.log.bak ca/audit.log
"$BIN" audit --verify >/dev/null || fail "restored audit log should verify"

echo "13. usage errors exit 2"
set +e
"$BIN" frobnicate >/dev/null 2>&1
[ $? -eq 2 ] || fail "unknown command should exit 2"
"$BIN" revoke >/dev/null 2>&1
[ $? -eq 2 ] || fail "revoke without a target should exit 2"
"$BIN" verify --at yesterday alice-cert.pub >/dev/null 2>&1
[ $? -eq 2 ] || fail "bad --at should exit 2"
set -e

if command -v ssh-keygen >/dev/null 2>&1; then
  echo "14. cross-check against OpenSSH's own tooling"
  ssh-keygen -L -f alice-cert.pub | grep >/dev/null "alice@certclerk-1" || fail "ssh-keygen cannot read our certificate"
  ssh-keygen -Qf revoked.krl alice-cert.pub | grep >/dev/null "REVOKED" || fail "ssh-keygen does not honor our KRL"
else
  echo "14. ssh-keygen not installed; skipping the OpenSSH cross-check"
fi

echo "SMOKE OK"
