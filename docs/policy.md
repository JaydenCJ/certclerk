# policy.json reference

The policy is the CA's authorization brain: `certclerk issue` signs
nothing the policy does not explicitly allow. It lives at
`<ca-dir>/policy.json`, is validated strictly on every CA open
(unknown fields are hard errors — a typoed `max_tll` must never
silently widen access), and is deny-by-default: a user who is not
listed gets nothing.

## Document shape

```json
{
  "version": 1,
  "defaults": {
    "max_ttl": "8h",
    "extensions": ["permit-pty"]
  },
  "users": {
    "alice": {
      "principals": ["alice", "deploy"],
      "max_ttl": "1h"
    },
    "ci-bot": {
      "principals": ["deploy"],
      "max_ttl": "15m",
      "extensions": [],
      "source_address": ["10.0.0.0/8"],
      "force_command": "/usr/local/bin/deploy"
    }
  }
}
```

`defaults` supplies every field except `principals` (principals are
always granted per user, never globally). A user rule overrides a
default field by setting it; an *absent* field inherits, while an
explicitly empty one (`"extensions": []`) means "none".

## Fields

| Key | Applies to | Effect |
|---|---|---|
| `version` | document | must be `1` |
| `principals` | user | SSH principals the user may hold; requests must be a subset. `"*"` allows any *explicitly requested* principal but never expands an empty request |
| `max_ttl` | user, defaults | hard cap on certificate lifetime (`90s`, `30m`, `2h30m`, `7d`); requests of `--ttl 0`/omitted get the full cap; fallback is `8h` |
| `extensions` | user, defaults | OpenSSH extensions stamped into the cert (e.g. `permit-pty`, `permit-agent-forwarding`); `[]` = none |
| `source_address` | user, defaults | CIDRs / bare IPs written as the `source-address` critical option — sshd then refuses the cert from anywhere else |
| `force_command` | user, defaults | written as the `force-command` critical option — sshd runs only this command |

## Semantics worth knowing

- **Requests default to the rule.** `certclerk issue --user alice`
  with no `--principals` grants every principal the rule names (sorted);
  with no `--ttl` it grants the full `max_ttl`.
- **Denials are cheap and clean.** A denied issuance exits 1, burns no
  serial, and writes no audit entry — the audit log records what the CA
  *did*, not what it refused.
- **Critical options are enforcement, not decoration.** `source_address`
  and `force_command` end up in the certificate's critical options,
  which sshd enforces; a cert pinned to `10.0.0.0/8` is useless when
  stolen and replayed from elsewhere.
- **Validation is fail-fast.** Every subcommand that opens the CA
  re-validates the policy; a broken document stops `issue`, `verify`,
  `krl` — everything — with the offending user and field named.

## Checking your work

```bash
certclerk policy                 # summary of all users
certclerk policy --user ci-bot   # the effective (merged) rule for one user
```
