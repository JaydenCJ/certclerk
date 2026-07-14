# certclerk examples

Runnable, self-contained demos. Both scripts build certclerk from this
repository, work in a temp directory, and touch nothing outside it.

| File | What it shows |
|---|---|
| `policy.json` | a realistic starter policy: a human with two principals, a pinned-down CI bot, and a break-glass wildcard operator |
| `lifecycle.sh` | the full story end to end: init → policy → issue → verify → revoke → KRL → tamper-evident audit |
| `ci-issue.sh` | the pattern for CI: mint a 15-minute deploy certificate for a bot key, ready for `ssh -o CertificateFile=...` |

```bash
bash examples/lifecycle.sh
bash examples/ci-issue.sh
```

Both finish in seconds and print what they are doing at every step.
For wiring the CA into your hosts (sshd_config), run `certclerk setup`
after `init` — it prints the exact snippet with your CA's public key.
