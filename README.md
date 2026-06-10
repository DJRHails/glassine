# glassine

Transparent [sops](https://github.com/getsops/sops)-backed encryption for git.

Glassine is the translucent archival paper used to protect valuable documents.
This tool keeps sops envelopes in your git history while your working tree
holds plaintext: **opaque to the remote, transparent to anyone holding a key.**

```text
              ┌────────── repository / GitHub ──────────┐
              │   sops envelopes (AES-256-GCM + MAC)    │
              └─────────────────────────────────────────┘
                   ▲ clean (encrypt)      │ smudge (decrypt)
                   │ git add / status     ▼ checkout / clone
              ┌────────── working tree ─────────────────┐
              │   plaintext you edit, grep, and source  │
              └─────────────────────────────────────────┘
```

Like [transcrypt](https://github.com/elasticdog/transcrypt), but with sops
underneath: per-host SSH keys instead of one shared password, real recipient
management, revocation that doesn't orphan history, and a maintained crypto
engine — glassine itself contains **zero cryptographic decisions**.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/DJRHails/glassine/main/glassine \
  -o ~/.local/bin/glassine && chmod +x ~/.local/bin/glassine
```

Requires `git` and [`sops`](https://github.com/getsops/sops) ≥ 3.10
(`brew install sops`).

## Quickstart

In any repository:

```bash
glassine init                 # wires filters + merge driver; creates .sops.yaml
                              # with this host's ~/.ssh/id_ed25519.pub
glassine protect 'secrets/**' # choose what to protect (writes .gitattributes;
                              # encrypts any already-tracked matches)
```

Then just work: files under `secrets/` are plaintext in your tree and
envelopes in every commit. `git diff` shows plaintext, merges happen in
plaintext. Hosts decrypt with their own `~/.ssh/id_ed25519` — no extra key
material (sops auto-discovers it; override with
`SOPS_AGE_SSH_PRIVATE_KEY_FILE`).

On a fresh clone, `glassine init` decrypts the working tree in place.
Keyless clones simply see envelopes — they round-trip safely and can never
corrupt or leak anything.

## Sharing and revoking access

```bash
glassine allow github:alice              # every SSH key on alice's GitHub account
glassine allow ~/.ssh/id_ed25519.pub     # a key file
glassine allow 'ssh-ed25519 AAAA… ci'    # a literal key
glassine revoke alice                    # forward-only; rotates data keys
```

`allow` and `revoke` edit `.sops.yaml` and immediately re-encrypt managed
files with fresh data keys (`sops rotate` semantics), so access changes take
effect in the next commit. `revoke` refuses to remove the last recipient.

Revocation is forward-only, like every client-side encryption scheme: the
revoked key keeps the history it could already read, loses everything after
the rotation. Surviving hosts keep **full** history — unlike a transcrypt
rekey, nothing is orphaned. If you revoke because of compromise, rotate the
secret *values* too.

Scope (`.gitattributes`, via `protect`) decides **which** files are
encrypted; `.sops.yaml` (via `allow`/`revoke`) decides **who** can read them.
glassine generates a single catch-all creation rule, and only ever auto-edits
a `.sops.yaml` carrying its `managed by glassine` marker — hand-written
policies are left alone (you get path-scoped recipients back, at the cost of
editing recipients manually).

## Commands

| Command | Purpose |
|---|---|
| `init` | configure filters + merge driver; bootstrap `.sops.yaml`; decrypt any still-encrypted worktree files |
| `protect <glob>…` | protect paths: write `.gitattributes` lines, encrypt already-tracked matches |
| `allow <recipient>…` | add recipients (literal key, `.pub` file, or `github:user`) and rotate |
| `revoke <pattern>` | remove matching recipients and rotate (keeps ≥1 recipient) |
| `status` | list managed files and their index state |
| `check` | fail if any staged managed file is unencrypted — use as a pre-commit hook |
| `rotate [files…]` | force re-encryption with fresh data keys under current `.sops.yaml` |
| `uninstall` | remove filter config from the repository |

`clean` / `smudge` / `textconv` / `merge` are internal hooks invoked by git.

## Merging

Encrypted files merge **in plaintext**: the merge driver decrypts base, ours,
and theirs, runs git's standard three-way merge, and re-encrypts clean
results. Conflicts surface as ordinary plaintext conflict markers in your
working tree; resolve and `git add` as usual (the add re-encrypts).

## How it works

git requires `clean` to be a **pure function** — the same plaintext must
yield byte-identical output, or every `git status` re-dirties the file. sops
output is deliberately randomised (fresh data key, IVs, MAC). glassine
reconciles the two by memoising against the index: if the staged envelope
decrypts to exactly the incoming plaintext, it is re-emitted unchanged.
Ciphertext changes **iff** plaintext changes.

This is also why transcrypt can never modernise its crypto: its determinism
comes from the cipher itself (HMAC-derived salts), freezing the scheme.
glassine gets determinism above the crypto layer, so the engine can evolve.

Safety properties:

- `filter.glassine.required=true` — a failing encrypt **aborts** the
  operation; git can never silently stage plaintext
- already-encrypted input passes through `clean` untouched — keyless
  checkouts round-trip envelopes losslessly
- `glassine check` catches the classic footgun where `.gitattributes`
  references a filter that isn't configured, so plaintext slips through

## Limitations

- A revoked-but-formerly-authorized host retains access to old history
  (inherent to all client-side schemes — rotate the secret values on
  compromise).
- `rotate` and `clean`'s comparison need a decryption identity; run them from
  an authorized host.
- Passphrase-protected SSH keys are unsupported by sops' age integration
  (ssh-agent can't perform X25519); use a passphrase-less per-host key or
  `SOPS_AGE_SSH_PRIVATE_KEY_CMD`.
- Merging encrypted files needs a decryption identity; keyless hosts fall
  back to ciphertext-level conflicts.
- Remote-side diffs of secrets are opaque churn (every real change mints a
  fresh data key). Local diffs are plaintext via textconv.

## License

MIT
