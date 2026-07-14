# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-13

### Added

- From-scratch, stdlib-only implementation of the OpenSSH certificate
  format (PROTOCOL.certkeys): marshal, sign (ed25519), parse, and
  verify `*-cert-v01@openssh.com` blobs, with sorted critical options
  and extensions, nested valued-option encoding, and support for
  certifying ed25519, RSA, ECDSA, DSA, and sk-* user keys.
- `init` — one-command CA: ed25519 keypair (PKCS#8 PEM, mode 0600),
  a deny-by-default `policy.json`, a persisted serial counter, and the
  audit log's genesis entry.
- `issue` — short-lived user certificates gated by a principal policy:
  per-user principal allowlists (with an explicit-only `*` wildcard),
  TTL caps with defaults inheritance, extension sets, source-address
  pins, and forced commands; `--backdate` (default 60s) absorbs host
  clock skew, and policy denials exit 1 without burning a serial.
- Strict policy parsing: unknown JSON fields, invalid CIDRs, malformed
  principals, and bad TTLs are hard errors at `Open` time, not at
  first use.
- `revoke` by serial (validated against the audit log) or by key ID,
  and `krl` exporting the revocation list in OpenSSH's binary KRL
  format (PROTOCOL.krl) for sshd's `RevokedKeys` — verified against
  `ssh-keygen -Qf` when available.
- Hash-chained, append-only JSONL audit log covering init, issue, and
  revoke; `audit --verify` detects rewritten, deleted, reordered, and
  mislinked entries and names the first bad one.
- `verify` (signature + validity window + revocation, with `--at` for
  point-in-time checks), `inspect` (text or stable JSON, works on
  foreign certificates), `policy` (effective-rule view), and `setup`
  (copy-paste sshd_config snippet).
- Documented exit codes (0 ok / 1 denied-invalid-broken / 2 usage /
  3 runtime) and CA-directory resolution via `--dir`, `CERTCLERK_DIR`,
  or `./.certclerk`.
- Runnable examples (`examples/`) and a policy reference
  (`docs/policy.md`).
- 90 deterministic offline tests (unit + in-process CLI integration
  against real temp-dir CAs, including a golden wire-format pin) and
  `scripts/smoke.sh`.

[0.1.0]: https://github.com/JaydenCJ/certclerk/releases/tag/v0.1.0
