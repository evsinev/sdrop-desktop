#!/bin/sh
# Builds the public tree from HEAD: only the allow-listed paths (code, packaging, public docs),
# never the internal design notes, plans and reviews. Fails if the tree mentions anything
# internal. Commits it on branch `public` (its own history). Usage: publish.sh "<message>"
# Then: git push origin public:main (and tags on `public`).
set -eu
MSG=$1
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
[ -z "$(git status --porcelain)" ] || { echo "commit or stash first" >&2; exit 1; }
PUBLIC=".github .gitignore Cargo.toml Cargo.lock deny.toml LICENSE-APACHE LICENSE-MIT README.md SPEC.md app core packaging scripts/package-macos.sh scripts/package-linux.sh scripts/probe-bundle.sh scripts/publish.sh"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
export GIT_INDEX_FILE="$TMP/index"
# shellcheck disable=SC2086
git ls-tree -r HEAD -- $PUBLIC | git update-index --index-info
TREE=$(git write-tree)
unset GIT_INDEX_FILE
# Internal names, paths and the service address stay out (the API header and the HKDF label
# of the public format are fine).
if git grep -I -n -i -E 'pnedev|/Users/|esinev|vedger|sdrop-dioxus|handoff|box\.ts|worker' "$TREE" -- . ':!scripts/publish.sh'; then
  echo "internal references in the public tree" >&2
  exit 1
fi
if git grep -I -n -E 'secret-drop' "$TREE" -- . ':!scripts/publish.sh' | grep -v -E 'x-secret-drop|X-Secret-Drop|secret-drop v1'; then
  echo "internal references in the public tree" >&2
  exit 1
fi
PARENT=$(git rev-parse -q --verify refs/heads/public || true)
if [ -n "$PARENT" ] && [ "$(git rev-parse "$PARENT^{tree}")" = "$TREE" ]; then
  echo "public is up to date: $PARENT"
  exit 0
fi
if [ -n "$PARENT" ]; then
  COMMIT=$(git commit-tree "$TREE" -p "$PARENT" -m "$MSG")
else
  COMMIT=$(git commit-tree "$TREE" -m "$MSG")
fi
git update-ref refs/heads/public "$COMMIT"
echo "public → $COMMIT"
