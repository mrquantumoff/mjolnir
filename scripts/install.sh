#!/usr/bin/env bash
# Install a mjolnir release binary on Linux (x86_64 or aarch64).
#
# Downloads with the GitHub CLI when it is logged in, otherwise through the
# GitHub API with a personal access token from GH_TOKEN or GITHUB_TOKEN. The
# token needs read access to the repository's contents. The archive is checked
# against the release's SHA256SUMS before anything is installed.
#
# usage: scripts/install.sh
#   MJOLNIR_VERSION      release tag to install, e.g. v0.1.0 (default: latest)
#   MJOLNIR_INSTALL_DIR  where the binary goes (default: ~/.local/bin)
#   MJOLNIR_REPO         owner/name to download from (default: mrquantumoff/mjolnir)
set -euo pipefail

repo="${MJOLNIR_REPO:-mrquantumoff/mjolnir}"
version="${MJOLNIR_VERSION:-latest}"
install_dir="${MJOLNIR_INSTALL_DIR:-$HOME/.local/bin}"
token="${GH_TOKEN:-${GITHUB_TOKEN:-}}"

die() { echo "install: $*" >&2; exit 1; }

[ "$(uname -s)" = Linux ] || die "this script installs Linux builds; use scripts/install.ps1 on Windows"
case "$(uname -m)" in
  x86_64 | amd64) arch=x86_64 ;;
  aarch64 | arm64) arch=aarch64 ;;
  *) die "no build for architecture $(uname -m)" ;;
esac
asset="mjolnir-$arch-unknown-linux-gnu.tar.gz"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Prints the API download URL of asset $2 from release JSON $1. The API lists
# each asset's "url" before its "name", so the last asset URL seen when the
# name matches belongs to that asset.
asset_url() {
  printf '%s' "$1" | tr ',{}' '\n\n\n' | sed 's/": *"/":"/' | awk -v want="\"name\":\"$2\"" '
    /"url":"https:\/\/api\.github\.com\/repos\/.*\/releases\/assets\/[0-9]+"/ {
      url = $0; sub(/.*"url":"/, "", url); sub(/".*/, "", url)
    }
    index($0, want) { print url; found = 1; exit }
    END { exit !found }'
}

download_with_gh() {
  local tag=()
  [ "$version" = latest ] || tag=("$version")
  gh release download "${tag[@]}" --repo "$repo" --dir "$tmp" \
    --pattern "$asset" --pattern SHA256SUMS ||
    die "gh could not download $asset from $repo ($version)"
}

# curl with the token's Authorization header. The header goes in as a curl
# config on stdin, written by the printf builtin, so the token never appears
# in a process's arguments, where other users could read it.
curl_with_token() {
  printf 'header = "Authorization: Bearer %s"\n' "$token" |
    curl --config - -fsSL -H "X-GitHub-Api-Version: 2022-11-28" "$@"
}

download_with_token() {
  local api="https://api.github.com/repos/$repo/releases" release url name
  if [ "$version" = latest ]; then url="$api/latest"; else url="$api/tags/$version"; fi
  release="$(curl_with_token -H "Accept: application/vnd.github+json" "$url")" ||
    die "no release $version in $repo, or the token cannot read it"
  for name in "$asset" SHA256SUMS; do
    url="$(asset_url "$release" "$name")" || die "release $version has no $name"
    curl_with_token -H "Accept: application/octet-stream" -o "$tmp/$name" "$url" ||
      die "downloading $name failed"
  done
}

if command -v gh >/dev/null && gh auth token >/dev/null 2>&1; then
  download_with_gh
elif [ -n "$token" ]; then
  command -v curl >/dev/null || die "curl is required when downloading with a token"
  download_with_token
else
  die "log in with 'gh auth login', or set GH_TOKEN to a personal access token"
fi

(cd "$tmp" && grep -F "  $asset" SHA256SUMS | sha256sum -c --quiet -) ||
  die "checksum mismatch for $asset"
tar -xzf "$tmp/$asset" -C "$tmp" mjolnir
mkdir -p "$install_dir"
install -m 755 "$tmp/mjolnir" "$install_dir/mjolnir"

echo "installed $("$install_dir/mjolnir" --version) to $install_dir/mjolnir"
case ":$PATH:" in
  *":$install_dir:"*) ;;
  *) echo "note: $install_dir is not on PATH" ;;
esac
