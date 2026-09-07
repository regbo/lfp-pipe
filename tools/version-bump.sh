#!/usr/bin/env bash
set -euo pipefail

level="${usage_level:-patch}"
case "$level" in
  patch|minor|major) ;;
  *) echo "level must be patch, minor, or major" >&2; exit 2 ;;
esac
if [ -n "$(git status --porcelain)" ]; then
  echo "refusing to release a dirty worktree" >&2
  exit 1
fi

current="$(git tag --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname | head -n 1)"
current="${current:-v0.0.0}"
version="${current#v}"
major="${version%%.*}"
remainder="${version#*.}"
minor="${remainder%%.*}"
patch="${remainder#*.}"
case "$level" in
  major) major=$((major + 1)); minor=0; patch=0 ;;
  minor) minor=$((minor + 1)); patch=0 ;;
  patch) patch=$((patch + 1)) ;;
esac
next="v${major}.${minor}.${patch}"
next_version="${next#v}"
if git rev-parse --verify --quiet "refs/tags/$next" >/dev/null; then
  echo "tag already exists: $next" >&2
  exit 1
fi

repo_root="$(git rev-parse --show-toplevel)"
manifest="$repo_root/Cargo.toml"
manifest_temp="$(mktemp "${manifest}.XXXXXX")"
awk -v next_version="$next_version" '
  /^\[/ { section = $0 }
  section == "[workspace.package]" && /^version = "[^"]+"$/ {
    print "version = \"" next_version "\""
    updated = 1
    next
  }
  { print }
  END { if (!updated) exit 1 }
' "$manifest" > "$manifest_temp"
mv "$manifest_temp" "$manifest"

cargo metadata --format-version 1 >/dev/null

release_parent="$repo_root/dist/local-release"
release_root="$release_parent/$next"
case "$release_root" in
  "$release_parent"/*) ;;
  *) echo "release output escaped its expected parent" >&2; exit 1 ;;
esac
rm -rf -- "$release_root"
mkdir -p "$release_root"

assets=()
if [ "$(uname -s)" = "Linux" ] && [ "$(uname -m)" = "x86_64" ]; then
  target="x86_64-unknown-linux-gnu"
  cargo test --workspace --release --locked --target "$target"
  cargo build --workspace --release --locked --target "$target"
  for binary in lfp-pipe-ingress lfp-pipe-client; do
    reported_version="$("target/$target/release/$binary" --version)"
    case "$reported_version" in
      *" $next_version") ;;
      *) echo "$binary reported '$reported_version'; expected $next_version" >&2; exit 1 ;;
    esac
  done
  archive="lfp-pipe-$next-$target"
  mkdir -p "$release_root/$archive/bin"
  cp "target/$target/release/lfp-pipe-ingress" "target/$target/release/lfp-pipe-client" "$release_root/$archive/bin/"
  tar -C "$release_root" -czf "$release_root/$archive.tar.gz" "$archive"
  rm -rf -- "$release_root/$archive"
  assets+=("$release_root/$archive.tar.gz")
fi

git add -- Cargo.toml Cargo.lock
git commit -m "Release $next"
git tag -a "$next" -m "Release $next"
echo "created the $next release commit and tag from $current with ${#assets[@]} local asset(s)"
if [ "${usage_push:-false}" = "true" ]; then
  head="$(git rev-parse HEAD)"
  base="$(git rev-parse HEAD^)"
  remote_main="$(git ls-remote origin refs/heads/main | awk '{print $1}')"
  if [ "$base" != "$remote_main" ]; then
    echo "origin/main must point to the release commit's parent $base before publishing $next" >&2
    exit 1
  fi
  git push origin "$head:refs/heads/main"
  git push origin "$next"
  gh release create "$next" "${assets[@]}" --draft --verify-tag --generate-notes --title "$next"
  gh release edit "$next" --draft=false
  echo "published $next; GitHub Actions will build only missing release targets"
else
  echo "local assets: $release_root"
  echo "publish with: mise run version:bump $level --push"
fi
