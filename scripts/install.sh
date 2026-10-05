#!/usr/bin/env bash
# Install a mjolnir release binary on Linux or macOS (x86_64 or aarch64).
#
# Downloads from the release's public URLs, so it needs no GitHub login or
# token. If openssl is on PATH, the release's SHA256SUMS must carry a valid
# signature by the release key below; without openssl only the checksum is
# checked. The archive is checked against SHA256SUMS, and the binary must
# report the version of the release's tag, before anything is installed.
#
# usage: scripts/install.sh
#   MJOLNIR_VERSION      release tag to install, e.g. v0.1.0 (default: latest)
#   MJOLNIR_INSTALL_DIR  where the binary goes (default: ~/.local/bin)
#   MJOLNIR_REPO         owner/name to download from (default: mrquantumoff/mjolnir)
#   MJOLNIR_RELEASE_KEY  the release key of MJOLNIR_REPO, if that is not the default
set -euo pipefail

repo="${MJOLNIR_REPO:-mrquantumoff/mjolnir}"
version="${MJOLNIR_VERSION:-latest}"
install_dir="${MJOLNIR_INSTALL_DIR:-$HOME/.local/bin}"
# Base64 of the SubjectPublicKeyInfo DER of the ECDSA P-256 key that signs
# SHA256SUMS; the same string as RELEASE_KEY in src/update.rs.
release_key="MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfCWNtshHxuxy4XyVXfa/O62yS79tJXqzlChtlVlBGHkHoF470qqwhXnhR/tVxC2a6H/M7miFldxmAlr8R/G1BA=="
if [ "$repo" != mrquantumoff/mjolnir ] && [ -n "${MJOLNIR_RELEASE_KEY:-}" ]; then
  release_key="$MJOLNIR_RELEASE_KEY"
fi

die() { echo "install: $*" >&2; exit 1; }

# Succeeds if $1.sig is a signature of $1 by $release_key.
verify_signature() {
  {
    echo "-----BEGIN PUBLIC KEY-----"
    echo "$release_key" | fold -w 64
    echo "-----END PUBLIC KEY-----"
  } > "$1.pem"
  openssl dgst -sha256 -verify "$1.pem" -signature "$1.sig" "$1" >/dev/null 2>&1
}

# Dies unless the binary $1 reports the version of tag $2.
check_version() {
  local got
  got="$("$1" --version 2>/dev/null)" || die "the release's binary does not run"
  [ "$got" = "mjolnir ${2#v}" ] ||
    die "the release's binary reports version ${got#mjolnir }, not ${2#v}"
}

case "$(uname -s)" in
  Linux) os=unknown-linux-gnu ;;
  Darwin) os=apple-darwin ;;
  *) die "no build for $(uname -s); use scripts/install.ps1 on Windows" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=x86_64 ;;
  aarch64 | arm64) arch=aarch64 ;;
  *) die "no build for architecture $(uname -m)" ;;
esac
asset="mjolnir-$arch-$os.tar.gz"
# macOS ships shasum, and may lack sha256sum.
if command -v sha256sum >/dev/null; then sha256=(sha256sum); else sha256=(shasum -a 256); fi

command -v curl >/dev/null || die "curl is required"
# Every file comes from the tag `latest` redirects to, so they cannot come
# from different releases, and the binary's version can be checked against it.
if [ "$version" = latest ]; then
  latest="$(curl -fsSLI --proto '=https' --retry 2 -o /dev/null -w '%{url_effective}' \
    "https://github.com/$repo/releases/latest")" || die "cannot find the latest release of $repo"
  case "$latest" in
    */releases/tag/?*) version="${latest##*/releases/tag/}" ;;
    *) die "$repo has no latest release" ;;
  esac
fi
base="https://github.com/$repo/releases/download/$version"

tmp="$(mktemp -d)"
staged="$install_dir/mjolnir.new"
trap 'rm -rf "$tmp"; rm -f "$staged"' EXIT

for name in SHA256SUMS SHA256SUMS.sig "$asset"; do
  curl -fsSL --proto '=https' --retry 2 -o "$tmp/$name" "$base/$name" ||
    die "cannot download $name from $repo ($version)"
done

if command -v openssl >/dev/null; then
  verify_signature "$tmp/SHA256SUMS" ||
    die "SHA256SUMS does not match its signature SHA256SUMS.sig"
else
  echo "install: warning: openssl not found; checking only the checksum, not the release signature" >&2
fi

(cd "$tmp" && grep -F "  $asset" SHA256SUMS | "${sha256[@]}" -c --status -) ||
  die "checksum mismatch for $asset"
tar -xzf "$tmp/$asset" -C "$tmp" mjolnir
mkdir -p "$install_dir"
# Staged beside its destination rather than in the temp directory, which
# may be mounted noexec.
install -m 755 "$tmp/mjolnir" "$staged"
check_version "$staged" "$version"
mv -f "$staged" "$install_dir/mjolnir"

echo "installed $("$install_dir/mjolnir" --version) to $install_dir/mjolnir"
case ":$PATH:" in
  *":$install_dir:"*) ;;
  *) echo "note: $install_dir is not on PATH" ;;
esac
