# glassine

Transparent [sops](https://github.com/getsops/sops)-backed encryption for git.

glassine is a single bash script (`glassine`, v0.9.0) that wires git's
clean/smudge/diff/merge hooks to sops, so selected files are stored as sops
envelopes in every commit while your working tree holds plaintext. It exists
to replace transcrypt's one shared password with per-host SSH keys and real
recipient management. **Status: active** — in day-to-day use on the author's
own repositories, with releases through October 2026; it has had no external
security review.

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

## Key takeaways

- **Plaintext never gets staged by accident while the filter is configured.**
  `init` sets `filter.glassine.required`, so a failed encrypt aborts the git
  operation. That abort comes from git's own semantics and has no dedicated
  test. `glassine check` catches the case where the filter isn't configured
  (scenario 7). [confidence: ~85%; see [How it works](#how-it-works) and
  [Verification](#verification-and-provenance)]
- **Every command and git workflow listed here has an integration test.** That
  covers clone, merge, rebase, stash, cherry-pick, worktrees, allow/revoke and
  per-path grants: 52 scenarios in `test/run.sh`, run in CI on Ubuntu and
  macOS. [confidence: ~90% that it behaves as described on those platforms;
  untested elsewhere; see [Verification](#verification-and-provenance)]
- **The security rests on sops and age, not on glassine.** glassine chooses
  no ciphers and derives no keys. Its own job is the git plumbing and
  recipient bookkeeping, and that has not been externally reviewed.
  [confidence: ~85%; see [What the design rests on](#what-the-design-rests-on)]
- **Revocation is forward-only.** A revoked key still reads the history it
  could already read. Rotate the secret values after a compromise.
  [confidence: ~95%, inherent to client-side encryption; see
  [Sharing and revoking access](#sharing-and-revoking-access)]
- **Main known gaps:** `git archive` on a keyed host exports plaintext,
  symlinks are never encrypted, passphrase-protected SSH keys don't work, and
  a merge that changes `.sops.yaml` leaves recipient drift until you run
  `rotate`. See [Limitations](#limitations) and [Merging](#merging).
- **Built for dotfiles-sized repos.** On the largest repo in the commit
  history (525 envelopes), `init` takes seconds, but filters still run one
  process per file on `git status`. [confidence: ~70% on the numbers, from
  small benches on one machine; see [Performance](#performance)]

Confidence tags are an assessment of the evidence in this repo (sample sizes,
seeds, intervals), added in a 2026-10 README audit; they are not new
measurements.

## What the design rests on

Two decisions carry the project. If either is wrong, nothing else matters:

1. **Determinism by memoisation, not by cipher.** git needs `clean` to be a
   pure function. glassine gets that by re-emitting the staged envelope when
   it decrypts to the same plaintext, rather than by using a deterministic
   cipher. This is what lets sops change underneath it
   ([How it works](#how-it-works)). Integration test 2 checks it ("unchanged
   plaintext never re-encrypts").
2. **Delegating all cryptography to sops (age recipients from SSH keys).**
   Confidentiality comes down to sops's AES-256-GCM envelopes and age's
   handling of SSH keys. glassine's own risk is in plumbing: staging
   plaintext, picking the wrong recipients, or leaking through a git path
   that skips filters. The [Limitations](#limitations) list covers the known
   ones.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/DJRHails/glassine/main/glassine \
  -o ~/.local/bin/glassine && chmod +x ~/.local/bin/glassine
```

Requires `git` ≥ 2.25 and [`sops`](https://github.com/getsops/sops) ≥ 3.10
(`brew install sops`). `perl`, where present, speeds up `glassine init` on a
fresh clone; without it init behaves the same, only slower.

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
plaintext. Hosts decrypt with their own SSH keys — no extra key material.
sops probes `~/.ssh/id_ed25519` and `~/.ssh/id_rsa` itself; for keys under
any other name (`id_github`, `id_work`, …) glassine scans `~/.ssh` for the
pair matching the envelope's recipients and pins the winner as
`git config glassine.identity` (override with
`SOPS_AGE_SSH_PRIVATE_KEY_FILE`).

On a fresh clone, `glassine init` decrypts the working tree in place — only
the envelopes one of your keys can open; the rest are left as they are and
listed, never re-smudged for nothing. Keyless clones simply see envelopes —
they round-trip safely and can never corrupt or leak anything.

## Sharing and revoking access

```bash
glassine allow github:alice              # every SSH key on alice's GitHub account
glassine allow ~/.ssh/id_ed25519.pub     # a key file
glassine allow 'ssh-ed25519 AAAA… ci'    # a literal key
glassine revoke alice                    # forward-only; rotates data keys

glassine allow --path 'infra/**' github:bob   # bob reads infra/** only
glassine revoke --path 'infra/**' bob         # …and loses just that again
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
encrypted; `.sops.yaml` (via `allow`/`revoke`) decides **who** can read them
— repo-wide by default, per path with `--path`. A scoped grant creates a
creation rule for that glob ahead of the repo-wide catch-all (sops takes the
first match), seeded with the catch-all's recipients so it only ever widens
access; global `allow`s propagate into every scoped rule, and `check`/
`rotate` verify each envelope against the rule that actually covers it. On
overlapping globs the oldest rule wins. glassine only ever auto-edits a
`.sops.yaml` carrying its `managed by glassine` marker — hand-written
policies are left alone.

## Commands

| Command | Purpose |
|---|---|
| `init` | configure filters + merge driver; bootstrap `.sops.yaml`; decrypt any still-encrypted worktree files |
| `protect <glob>…` | protect paths: write `.gitattributes` lines, encrypt already-tracked matches |
| `allow [--path <glob>] <recipient>…` | add recipients (literal key, `.pub` file, or `github:user`) and rotate; `--path` scopes them to one glob |
| `revoke [--path <glob>] <pattern>` | remove matching recipients and rotate (every rule keeps ≥1 recipient); `--path` scopes the removal |
| `status` | list managed files and their index state |
| `check` | fail if any staged managed file is unencrypted — use as a pre-commit hook |
| `rotate [files…]` | force re-encryption with fresh data keys under current `.sops.yaml` |
| `uninstall` | remove filter config from the repository |

`clean` / `smudge` / `textconv` / `merge` are internal hooks invoked by git.

## Merging

Encrypted files merge **in plaintext**: the merge driver decrypts base, ours,
and theirs, runs git's standard three-way merge, and re-encrypts clean
results. Conflicts surface as ordinary plaintext conflict markers in your
working tree; resolve and `git add` as usual (the add re-encrypts). Rebase,
cherry-pick, revert, and stash all ride the same machinery and work.

One caveat: if a merge brings in a **`.sops.yaml` change** (someone ran
`allow`/`revoke` on the other branch), merged envelopes are re-encrypted
under the *pre-merge* policy — a newly-allowed key silently can't read, a
newly-revoked one still can. `glassine check` detects this **recipient
drift**; fix it with `glassine rotate` and commit. Running `check` as a
pre-commit hook closes the gap entirely.

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
  references a filter that isn't configured, so plaintext slips through —
  and flags recipient drift (envelopes whose key set no longer matches
  `.sops.yaml`, e.g. after a merge)
- empty files pass through unencrypted (sops refuses empty input, and there
  is nothing to protect); `check` and `status` treat them accordingly
- `git worktree add` works — secrets decrypt in new worktrees (filters are
  plain config, unlike transcrypt's per-worktree crypt directory)

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
- **`git archive` exports plaintext on a keyed host** (smudge is applied to
  archive contents; keyless hosts get ciphertext). Don't tarball a checkout
  to share it.
- **Symlinks are never encrypted** — git bypasses filters for them; the link
  target is stored raw.
- Filters spawn one process per file: a mass-`touch` of ~100 secrets costs
  ~10s on the next `git status`. Fine at dotfiles scale; a long-running
  filter-process protocol is the known fix if it ever matters.
- Remote-side diffs of secrets are opaque churn (every real change mints a
  fresh data key). Local diffs are plaintext via textconv.
- **No external security review.** The integration suite checks behaviour,
  not adversarial robustness. There is no fuzzing and no audit of the
  git-plumbing paths.
- **Platforms and version floors are untested.** CI covers Ubuntu and macOS
  with sops 3.13.1 only. Windows is not in CI. The `git` ≥ 2.25 and
  `sops` ≥ 3.10 minimums above are stated requirements: the script does not
  check them and CI does not run at those versions.

## Verification and provenance

What has been checked, and how:

- **Integration suite** (`test/run.sh`, 52 numbered scenarios): each one
  builds throwaway repos and fresh ed25519 keys in a temp dir and drives real
  `git` + `sops`. Scenarios 21–27 replay git workflows that tend to break
  crypt filters: stash, rebase, cherry-pick/revert, merge-induced recipient
  drift, `git worktree add`, `git archive`, and symlinks. Scenarios 26–27 pin
  the documented `archive` and symlink behaviour.
- **CI** (`.github/workflows/test.yml`): runs on every push to `main` and
  every PR, on `ubuntu-latest` and `macos-latest` with a checksum-verified
  sops v3.13.1, plus `shellcheck -x` on Linux.
- **This audit:** all 52 tests passed locally with git 2.43 and sops 3.13.3,
  and `shellcheck -x glassine test/run.sh` was clean.
- **Real use:** the commit history records `init` benchmarks on a
  525-envelope clone of one of the author's repositories. That is the
  evidence for use beyond the test suite. No usage statistics exist.

How it was built: version 0.1.0, the plaintext merge driver and a
20-scenario suite all landed on the first day (June 2026). Since then the
changes have been feature additions (per-path recipients, the `~/.ssh` key
scan), bug fixes that mostly came with a new numbered scenario, and
performance work with a small bench in each commit message (below).

### Performance

<!-- data-source: commit messages for #15, #16, #17, #18, #19 -->

All numbers come from commit messages. Each was measured on one machine,
usually over about 3 repetitions (#18 states none), so read them as orders of
magnitude:

| Change | Shape | Before → after |
|---|---|---|
| #15 one checkout for all stale envelopes | 150 envelopes, keyed `init` | 16.0 s → 2.4 s |
| #16 skip envelopes no local key opens | 525 unopenable envelopes | 17.1–19.1 s → 0.64–0.68 s |
| #17 parallel in-place decrypt | 525 envelopes, keyed `init` | 18.0 / 19.4 s → 4.9–5.3 s |
| #18 attribute pathspec for managed listing | 16k-file repo, per call | ~0.93 s → ~12 ms |
| #19 perl long-running checkout filter | 525 envelopes | removes a step measured at ~2.5 s of a ~4.4 s `init`; no after-timing recorded |

The ~100 ms-per-file filter cost behind the "~10 s per ~100 touched secrets"
figure in [Limitations](#limitations) comes from the commit that added
recipient-drift detection (`c0b956f`). It is an estimate, not a recorded
bench.

## Running the tests

```bash
# requires git, sops, ssh-keygen (and shellcheck for the lint step)
env -u SOPS_AGE_SSH_PRIVATE_KEY_FILE bash test/run.sh   # prints "all 52 tests passed"
shellcheck -x glassine test/run.sh
```

The suite isolates itself from your global git config, but not from your
environment. If `SOPS_AGE_SSH_PRIVATE_KEY_FILE` is exported, it overrides
`glassine.identity` (which is documented behaviour) and scenario 31 fails.
Hence the `env -u`.

## License

MIT
