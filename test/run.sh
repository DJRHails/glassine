#!/usr/bin/env bash
#
# Integration tests for glassine. Creates throwaway repos and SSH keys under
# a temp dir; requires git, sops, and ssh-keygen.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
export PATH="$ROOT:$PATH"

# Isolate from the developer's global git config (hooks, templates, signing).
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null

WORK=$(mktemp -d "${TMPDIR:-/tmp}/glassine-test.XXXXXX")
trap 'rm -rf -- "${WORK:?}"' EXIT

PASS=0
ok() {
  PASS=$((PASS + 1))
  printf 'ok %d - %s\n' "$PASS" "$1"
}
fail() {
  printf 'FAIL - %s\n' "$1" >&2
  exit 1
}

as_host() { # <host> <cmd...>
  local host=$1
  shift
  SOPS_AGE_SSH_PRIVATE_KEY_FILE="$WORK/keys/$host" "$@"
}

git_q() { git "$@" >/dev/null 2>&1; }

# --- fixtures ---------------------------------------------------------------

mkdir -p "$WORK/keys"
for h in hosta hostb; do
  ssh-keygen -t ed25519 -N '' -C "dh@$h" -f "$WORK/keys/$h" -q
done

ORIGIN="$WORK/origin"
mkdir -p "$ORIGIN"
cd "$ORIGIN"
git_q init
git config user.name test && git config user.email test@example.invalid

cat >.sops.yaml <<EOF
creation_rules:
  - path_regex: secrets/.*
    key_groups:
      - age:
          - '$(cut -d' ' -f1-2 "$WORK/keys/hosta.pub")'
          - '$(cut -d' ' -f1-2 "$WORK/keys/hostb.pub")'
EOF
echo 'secrets/** filter=glassine diff=glassine merge=binary' >.gitattributes
glassine init >/dev/null 2>&1

mkdir secrets
cat >secrets/creds.yaml <<'EOF'
github_token: ghp_demo123
anthropic_key: sk-ant-demo456
EOF

# --- 1: staging encrypts, worktree stays plaintext ---------------------------

as_host hosta git add .
git cat-file blob :secrets/creds.yaml | grep -q 'ENC\[AES256_GCM' ||
  fail 'staged blob is not a sops envelope'
grep -q 'ghp_demo123' secrets/creds.yaml ||
  fail 'worktree lost its plaintext'
as_host hosta git commit -qm 'add secrets'
ok 'git add stages an envelope; worktree stays plaintext'

# --- 2: determinism — unchanged plaintext never re-encrypts ------------------

BLOB_BEFORE=$(git rev-parse :secrets/creds.yaml)
touch secrets/creds.yaml
[ -z "$(as_host hosta git status --porcelain)" ] ||
  fail 'touch dirtied the file (clean is not memoised)'
cat >secrets/creds.yaml <<'EOF'
github_token: ghp_demo123
anthropic_key: sk-ant-demo456
EOF
as_host hosta git add secrets/creds.yaml
[ "$(git rev-parse :secrets/creds.yaml)" = "$BLOB_BEFORE" ] ||
  fail 're-adding identical plaintext produced a new blob'
ok 'unchanged plaintext re-emits the staged envelope byte-for-byte'

# --- 3: textconv — diffs display plaintext -----------------------------------

sed -i.bak 's/ghp_demo123/ghp_demo999/' secrets/creds.yaml && rm secrets/creds.yaml.bak
as_host hosta git diff secrets/creds.yaml | grep -q 'ghp_demo999' ||
  fail 'git diff did not show plaintext change'
as_host hosta git checkout -- secrets/creds.yaml
grep -q 'ghp_demo123' secrets/creds.yaml ||
  fail 'checkout did not restore plaintext'
ok 'git diff shows plaintext; checkout restores via smudge'

# --- 4: keyless clone — ciphertext round-trips safely -------------------------

KEYLESS="$WORK/clone-keyless"
git_q clone "$ORIGIN" "$KEYLESS"
(
  cd "$KEYLESS"
  git config user.name test && git config user.email test@example.invalid
  grep -q 'ENC\[AES256_GCM' secrets/creds.yaml ||
    fail 'keyless clone does not see ciphertext'
  SOPS_AGE_SSH_PRIVATE_KEY_FILE="$WORK/keys/missing" glassine init >/dev/null 2>&1
  touch secrets/creds.yaml
  [ -z "$(SOPS_AGE_SSH_PRIVATE_KEY_FILE=$WORK/keys/missing git status --porcelain)" ] ||
    fail 'envelope did not round-trip cleanly on a keyless host'
)
ok 'keyless clone sees ciphertext and round-trips it unchanged'

# --- 5: keyed clone — init decrypts the worktree ------------------------------

KEYED="$WORK/clone-keyed"
git_q clone "$ORIGIN" "$KEYED"
(
  cd "$KEYED"
  git config user.name test && git config user.email test@example.invalid
  as_host hostb glassine init >/dev/null
  grep -q 'ghp_demo123' secrets/creds.yaml ||
    fail 'init did not decrypt the worktree on a keyed clone'
)
ok 'keyed clone decrypts on init (hostb key)'

# --- 6: revocation — rotate is forward-only -----------------------------------

cd "$ORIGIN"
cat >.sops.yaml <<EOF
creation_rules:
  - path_regex: secrets/.*
    key_groups:
      - age:
          - '$(cut -d' ' -f1-2 "$WORK/keys/hosta.pub")'
EOF
as_host hosta glassine rotate >/dev/null
[ "$(git rev-parse :secrets/creds.yaml)" != "$BLOB_BEFORE" ] ||
  fail 'rotate did not produce a new envelope'
git cat-file blob :secrets/creds.yaml >"$WORK/new.enc"
[ "$(grep -c 'recipient:' "$WORK/new.enc")" = '1' ] ||
  fail 'rotated envelope still lists revoked recipient'
as_host hosta git commit -qm 'revoke hostb'

if as_host hostb sops decrypt --filename-override secrets/creds.yaml "$WORK/new.enc" >/dev/null 2>&1; then
  fail 'revoked host can still decrypt the rotated envelope'
fi
as_host hosta sops decrypt --filename-override secrets/creds.yaml "$WORK/new.enc" >/dev/null 2>&1 ||
  fail 'surviving host cannot decrypt the rotated envelope'
git show 'HEAD~1:secrets/creds.yaml' >"$WORK/old.enc"
as_host hostb sops decrypt --filename-override secrets/creds.yaml "$WORK/old.enc" >/dev/null 2>&1 ||
  fail 'revoked host lost access to history it was a recipient of'
ok 'rotate: revoked host loses new versions, keeps old; survivor keeps all'

# --- 7: check — catches silently-unfiltered plaintext --------------------------

BARE="$WORK/unfiltered"
mkdir -p "$BARE"
(
  cd "$BARE"
  git_q init
  git config user.name test && git config user.email test@example.invalid
  echo 'secrets/** filter=glassine diff=glassine' >.gitattributes
  mkdir secrets && echo 'token: oops-plaintext' >secrets/leak.yaml
  git add . 2>/dev/null # no filter configured: git stages plaintext silently
  if glassine check >/dev/null 2>&1; then
    fail 'check passed despite staged plaintext'
  fi
)
cd "$ORIGIN"
as_host hosta glassine check ||
  fail 'check failed on a fully-encrypted repo'
ok 'check flags unfiltered plaintext and passes clean repos'

printf '\nall %d tests passed\n' "$PASS"
