# Contributing to certclerk

Issues, discussions and pull requests are all welcome.

## Getting started

You need Go ≥1.22; nothing else — the tool and its tests are pure
standard library and never touch the network.

```bash
git clone https://github.com/JaydenCJ/certclerk && cd certclerk
go build ./...
go test ./...
bash scripts/smoke.sh
```

`scripts/smoke.sh` builds the binary, stands up a real CA in a temp
dir, and walks the whole lifecycle — init, policy, issue, verify,
revoke, KRL export, audit-chain tampering — asserting on real CLI
output and exit codes; it must finish by printing `SMOKE OK`. If
`ssh-keygen` is installed it also cross-checks the issued certificate
and the KRL against OpenSSH itself.

## Before you open a pull request

1. `gofmt -l .` reports nothing (formatting is enforced).
2. `go vet ./...` passes with no findings.
3. `go test ./...` passes (90 deterministic tests, no network).
4. `bash scripts/smoke.sh` prints `SMOKE OK`.
5. Add tests for behavior changes; keep logic in pure, unit-testable
   modules (wire, sshcert, policy, krl, and audit verification never
   touch the filesystem — only the ca package and the CLI do).

## Ground rules

- Keep dependencies at zero; adding one needs strong justification in
  the PR.
- No network calls, ever, and no telemetry — certclerk only reads and
  writes the CA directory and the files you point it at.
- Wire formats are contracts: a change to certificate or KRL bytes
  needs a PROTOCOL.certkeys / PROTOCOL.krl citation and an update to
  the golden-bytes test.
- Policy changes must stay deny-by-default; a request the policy does
  not explicitly cover is refused.
- Code comments and doc comments are written in English.

## Reporting bugs

Include the output of `certclerk version`, the full command you ran,
and — for certificate or KRL problems — the output of
`certclerk inspect --format json` on the artifact plus, if available,
what `ssh-keygen -L` says about the same file. Never attach `ca.key`.

## Security

Please do not open public issues for security problems; use GitHub's
private vulnerability reporting on this repository instead.
