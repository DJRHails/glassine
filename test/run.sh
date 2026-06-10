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

# --- 8: init bootstraps .sops.yaml; protect scopes; catch-all encrypts --------

HOME2="$WORK/home2"
mkdir -p "$HOME2/.ssh"
ssh-keygen -t ed25519 -N '' -C 'dh@auto' -f "$HOME2/.ssh/id_ed25519" -q
AUTO="$WORK/auto"
mkdir -p "$AUTO"
(
  cd "$AUTO"
  git_q init
  git config user.name test && git config user.email test@example.invalid
  HOME=$HOME2 glassine init >/dev/null
  grep -q 'managed by glassine' .sops.yaml ||
    fail 'init did not bootstrap a managed .sops.yaml'
  grep -qF "$(cut -d' ' -f2 "$HOME2/.ssh/id_ed25519.pub")" .sops.yaml ||
    fail "bootstrapped .sops.yaml is missing the host's key"
  HOME=$HOME2 glassine protect 'secrets/**' >/dev/null
  grep -qF 'secrets/** filter=glassine diff=glassine merge=glassine' .gitattributes ||
    fail 'protect did not write the .gitattributes line'
  mkdir secrets && echo 'tok: abc' >secrets/a.yaml
  HOME=$HOME2 git add .
  git cat-file blob :secrets/a.yaml | grep -q 'ENC\[AES256_GCM' ||
    fail 'catch-all creation rule did not encrypt'
  HOME=$HOME2 git commit -qm base
)
ok 'init bootstraps .sops.yaml; protect scopes; catch-all rule encrypts'

# --- 9: protect re-encrypts already-tracked plaintext --------------------------

(
  cd "$AUTO"
  echo 'TOKEN=plain-oops' >app.env
  HOME=$HOME2 git add app.env && HOME=$HOME2 git commit -qm 'plaintext env'
  HOME=$HOME2 glassine protect 'app.env' >/dev/null 2>&1
  git cat-file blob :app.env | grep -q 'sops_mac=ENC\[' ||
    fail 'protect did not re-encrypt tracked plaintext'
  HOME=$HOME2 git commit -qm 'encrypt app.env'
)
ok 'protect re-encrypts already-tracked plaintext files'

# --- 10: allow adds a recipient and grants access -------------------------------

ssh-keygen -t ed25519 -N '' -C 'dh@hostc' -f "$WORK/keys/hostc" -q
(
  cd "$AUTO"
  HOME=$HOME2 glassine allow "$WORK/keys/hostc.pub" >/dev/null
  grep -qF "$(cut -d' ' -f2 "$WORK/keys/hostc.pub")" .sops.yaml ||
    fail 'allow did not record the new recipient'
  git cat-file blob :secrets/a.yaml >"$WORK/granted.enc"
  as_host hostc sops decrypt --filename-override secrets/a.yaml "$WORK/granted.enc" >/dev/null 2>&1 ||
    fail 'new recipient cannot decrypt after allow'
  HOME=$HOME2 git commit -qm 'allow hostc'
)
ok 'allow records recipient and auto-rotates to grant access'

# --- 11: revoke removes access; refuses to remove the last recipient -----------

(
  cd "$AUTO"
  HOME=$HOME2 glassine revoke hostc >/dev/null 2>&1
  grep -qF "$(cut -d' ' -f2 "$WORK/keys/hostc.pub")" .sops.yaml &&
    fail 'revoke left the recipient in .sops.yaml'
  git cat-file blob :secrets/a.yaml >"$WORK/revoked.enc"
  if as_host hostc sops decrypt --filename-override secrets/a.yaml "$WORK/revoked.enc" >/dev/null 2>&1; then
    fail 'revoked recipient can still decrypt'
  fi
  if HOME=$HOME2 glassine revoke 'ssh-ed25519' >/dev/null 2>&1; then
    fail 'revoke removed the last recipient'
  fi
  HOME=$HOME2 git commit -qm 'revoke hostc'
)
ok 'revoke removes access and protects the last recipient'

# --- 12: merge driver — clean three-way merge in plaintext ----------------------
# Every git call that can trigger filters needs the test identity (HOME):
# clean's memoisation must decrypt the staged envelope to prove equality.

g2() { HOME=$HOME2 git "$@"; }

(
  cd "$AUTO"
  printf 'a: 1\nc1: x\nc2: x\nc3: x\nb: 1\n' >secrets/m.yaml
  g2 add secrets/m.yaml && g2 commit -qm 'merge base'
  g2 checkout -q -b side
  printf 'a: 2\nc1: x\nc2: x\nc3: x\nb: 1\n' >secrets/m.yaml
  g2 add secrets/m.yaml && g2 commit -qm 'side: a=2'
  g2 checkout -q -
  printf 'a: 1\nc1: x\nc2: x\nc3: x\nb: 2\n' >secrets/m.yaml
  g2 add secrets/m.yaml && g2 commit -qm 'main: b=2'
  g2 merge -q side -m merged 2>/dev/null ||
    fail 'non-overlapping merge conflicted'
  grep -q 'a: 2' secrets/m.yaml || fail 'merge lost the side change'
  grep -q 'b: 2' secrets/m.yaml || fail 'merge lost the main change'
  git cat-file blob HEAD:secrets/m.yaml | grep -q 'ENC\[AES256_GCM' ||
    fail 'merged blob is not encrypted'
)
ok 'merge driver: clean 3-way merge in plaintext, re-encrypted result'

# --- 13: merge driver — conflicts surface as plaintext markers ------------------

(
  cd "$AUTO"
  g2 checkout -q -b side2
  printf 'a: 9\nc1: x\nc2: x\nc3: x\nb: 2\n' >secrets/m.yaml
  g2 add secrets/m.yaml && g2 commit -qm 'side2: a=9'
  g2 checkout -q -
  printf 'a: 7\nc1: x\nc2: x\nc3: x\nb: 2\n' >secrets/m.yaml
  g2 add secrets/m.yaml && g2 commit -qm 'main: a=7'
  if g2 merge -q side2 -m conflict 2>/dev/null; then
    fail 'overlapping merge did not conflict'
  fi
  grep -q '^<<<<<<<' secrets/m.yaml || fail 'conflict markers missing'
  grep -q 'a: 9' secrets/m.yaml || fail 'theirs side missing from conflict'
  grep -q 'a: 7' secrets/m.yaml || fail 'ours side missing from conflict'
  printf 'a: 8\nc1: x\nc2: x\nc3: x\nb: 2\n' >secrets/m.yaml
  g2 add secrets/m.yaml && g2 commit -qm resolved
  git cat-file blob HEAD:secrets/m.yaml | grep -q 'ENC\[AES256_GCM' ||
    fail 'resolved blob is not encrypted'
)
ok 'merge driver: conflicts are plaintext; resolution re-encrypts'

# --- 14: allow github:user — hermetic via a curl stub ---------------------------

for h in hostd hoste; do
  ssh-keygen -t ed25519 -N '' -C "dh@$h" -f "$WORK/keys/$h" -q
done
mkdir -p "$WORK/stub"
cat >"$WORK/stub/curl" <<EOF
#!/usr/bin/env bash
# Stub of github.com/<user>.keys: two usable keys plus one unsupported type.
cat '$WORK/keys/hostd.pub' '$WORK/keys/hoste.pub'
echo 'ecdsa-sha2-nistp256 AAAAunsupported ignored'
EOF
chmod +x "$WORK/stub/curl"
(
  cd "$AUTO"
  PATH="$WORK/stub:$PATH" HOME=$HOME2 glassine allow github:fakeuser >/dev/null
  [ "$(grep -c 'github:fakeuser' .sops.yaml)" = '2' ] ||
    fail 'allow github: did not record exactly the two supported keys'
  git cat-file blob :secrets/a.yaml >"$WORK/gh.enc"
  as_host hostd sops decrypt --filename-override secrets/a.yaml "$WORK/gh.enc" >/dev/null 2>&1 ||
    fail 'github-imported key cannot decrypt after allow'
  BLOB_T14=$(git rev-parse :secrets/a.yaml)
  PATH="$WORK/stub:$PATH" HOME=$HOME2 glassine allow github:fakeuser >/dev/null 2>&1
  [ "$(grep -c 'github:fakeuser' .sops.yaml)" = '2' ] ||
    fail 'duplicate allow added recipients again'
  [ "$(git rev-parse :secrets/a.yaml)" = "$BLOB_T14" ] ||
    fail 'no-op allow still rotated the envelopes'
  HOME=$HOME2 git commit -qm 'allow github:fakeuser'
)
ok 'allow github:user imports supported keys, dedupes, skips no-op rotation'

# --- 15: binary files round-trip ------------------------------------------------

(
  cd "$AUTO"
  head -c 1024 /dev/urandom >secrets/blob.bin
  cp secrets/blob.bin "$WORK/blob.orig"
  HOME=$HOME2 git add secrets/blob.bin
  git cat-file blob :secrets/blob.bin | grep -q 'ENC\[AES256_GCM' ||
    fail 'binary file was not encrypted'
  HOME=$HOME2 git commit -qm 'binary secret'
  rm secrets/blob.bin
  HOME=$HOME2 git checkout -- secrets/blob.bin
  cmp -s secrets/blob.bin "$WORK/blob.orig" ||
    fail 'binary did not round-trip bit-for-bit'
)
ok 'binary secrets encrypt and round-trip bit-for-bit'

# --- 16: filenames with spaces ---------------------------------------------------

(
  cd "$AUTO"
  echo 'k: v' >'secrets/my secret.yaml'
  HOME=$HOME2 git add 'secrets/my secret.yaml'
  git cat-file blob ':secrets/my secret.yaml' | grep -q 'ENC\[AES256_GCM' ||
    fail 'space-named file was not encrypted'
  HOME=$HOME2 git commit -qm 'space name'
  HOME=$HOME2 glassine rotate 'secrets/my secret.yaml' >/dev/null ||
    fail 'rotate failed on space-named file'
  rm 'secrets/my secret.yaml'
  HOME=$HOME2 git checkout -- 'secrets/my secret.yaml'
  grep -q 'k: v' 'secrets/my secret.yaml' ||
    fail 'space-named file did not round-trip'
  HOME=$HOME2 git commit -qam 'rotate space name'
)
ok 'filenames with spaces survive clean/smudge/rotate'

# --- 17: empty files pass through ------------------------------------------------

(
  cd "$AUTO"
  : >secrets/empty.yaml
  HOME=$HOME2 git add secrets/empty.yaml ||
    fail 'adding an empty file failed'
  [ -z "$(git cat-file blob :secrets/empty.yaml)" ] ||
    fail 'empty file gained content in the index'
  HOME=$HOME2 git commit -qm 'empty file'
  touch secrets/empty.yaml
  [ -z "$(HOME=$HOME2 git status --porcelain secrets/empty.yaml)" ] ||
    fail 'empty file does not round-trip cleanly'
  HOME=$HOME2 glassine check >/dev/null 2>&1 ||
    fail 'check flagged an empty file as plaintext'
)
ok 'empty files pass through and do not trip check'

# --- 18: revoke with no match fails loudly ---------------------------------------

(
  cd "$AUTO"
  if HOME=$HOME2 glassine revoke 'no-such-recipient-zzz' >/dev/null 2>&1; then
    fail 'revoke succeeded with no matching recipient'
  fi
)
ok 'revoke with no matching recipient fails'

# --- 19: status reports index states ----------------------------------------------

(
  cd "$AUTO"
  HOME=$HOME2 glassine status >"$WORK/status.out"
  grep -Eq '^encrypted +secrets/a.yaml' "$WORK/status.out" ||
    fail 'status missing encrypted row'
  grep -Eq '^empty +secrets/empty.yaml' "$WORK/status.out" ||
    fail 'status missing empty row'
)
(
  cd "$BARE"
  glassine status | grep -Eq '^PLAINTEXT +secrets/leak.yaml' ||
    fail 'status did not flag staged plaintext'
)
ok 'status labels encrypted, empty, and PLAINTEXT files'

# --- 20: uninstall stops smudging; re-init recovers --------------------------------

(
  cd "$AUTO"
  HOME=$HOME2 glassine uninstall 2>/dev/null
  rm secrets/a.yaml
  git checkout -- secrets/a.yaml
  grep -q 'ENC\[AES256_GCM' secrets/a.yaml ||
    fail 'uninstall did not stop decryption on checkout'
  HOME=$HOME2 glassine init >/dev/null
  grep -q 'tok: abc' secrets/a.yaml ||
    fail 're-init did not restore plaintext'
)
ok 'uninstall stops smudging; re-init decrypts again'

printf '\nall %d tests passed\n' "$PASS"
