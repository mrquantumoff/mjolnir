# Installing, updating, and releasing

## What the install scripts check

Each release holds a `SHA256SUMS` file and `SHA256SUMS.sig`, an ECDSA P-256
signature of it. The release's public key is written into both scripts and
into the binary. The scripts check the signature first and refuse the
release if it is missing or does not verify, then check the archive against
its `SHA256SUMS` line. They resolve `latest` through GitHub's
`releases/latest` redirect and download every file from that tag. The new
binary is staged in the install directory and moved into place only after
its `--version` reports the tag's version, so an older signed release served
under a newer tag is refused and leaves the installed binary as it was.
`install.ps1` verifies with .NET and always checks
the signature. `install.sh` verifies with `openssl`; on a system without
`openssl` it prints a warning and checks only the checksum, which guards
against a corrupt download but not against a swapped release. Releases up
to v0.2.0 carry no signature, so the scripts refuse to install them.

Both scripts read `MJOLNIR_VERSION` to install a specific tag instead of
the latest, and `MJOLNIR_INSTALL_DIR` to install somewhere else.
`MJOLNIR_REPO` downloads from a fork instead, and `MJOLNIR_RELEASE_KEY` then
replaces the release key with the fork's; the scripts ignore it for the
default repository. From a checkout, run either script directly;
`install.ps1` also takes `-Version`, `-InstallDir`, and `-Repo`.

## Updating

`mjolnir update` replaces the running binary with the latest release, and
`mjolnir update --check` only reports whether one exists. It reads the
latest tag from GitHub's `releases/latest` redirect and downloads
`SHA256SUMS` and `SHA256SUMS.sig` from the public release URLs with the
system's `curl`. It refuses the release unless `SHA256SUMS.sig` is a valid
signature of `SHA256SUMS` by the release key built into the binary. Then it
downloads this platform's archive, refuses it if it does not match its
`SHA256SUMS` line, unpacks it with the system's `tar`, and swaps the new
binary in only after its `--version` reports the tag's version, so an
older signed release served under a newer tag is refused. Windows 10 and
later ship both tools; on Windows the old binary is moved to
`mjolnir.exe.old` and deleted on the next run. It never downgrades, and it
refuses on platforms that have
no release build. A running Windows service keeps the old binary until it
restarts, so restart the service after `mjolnir update`, which needs an
elevated terminal when mjolnir lives under Program Files.

`MJOLNIR_RELEASES_URL` points it at a fork or mirror with the same layout.
A mirror of the official releases needs nothing else. A fork that signs its
own releases also sets `MJOLNIR_RELEASE_KEY` to its public key, in the
format of `RELEASE_KEY` in [`src/update.rs`](../src/update.rs). The binary
ignores `MJOLNIR_RELEASE_KEY` unless `MJOLNIR_RELEASES_URL` is set.

The updater is the `self-update` Cargo feature, on by default. Packagers who
ship mjolnir through a package manager should build without it, which
removes the `update` command:

```sh
cargo build --release --no-default-features
```

## CI

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) builds release
binaries for `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
`x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc`, `aarch64-apple-darwin`,
and `x86_64-apple-darwin`. It runs the tests on x86_64 Linux, x86_64
Windows, and Apple silicon macOS (on APFS). The other targets cross-compile,
the aarch64 Linux and Windows ones on x86_64 runners and Intel macOS on the
Apple silicon runner, so their tests do not run. It runs only for tags that start with
`v`, or when started by hand from the Actions tab, which builds without
publishing anything. Every action it uses is pinned to a commit SHA, and
the toolchain to an exact Rust release.

[`.github/workflows/audit.yml`](../.github/workflows/audit.yml) runs
[cargo-deny](https://github.com/EmbarkStudios/cargo-deny) with
[`deny.toml`](../deny.toml). It fails on a dependency with a known
vulnerability or an unsound advisory, an unmaintained direct dependency, a
license outside the allow-list, or a source other than crates.io. It runs
on pushes to `master`, on pull requests, and weekly, since advisories
appear without any change here. The release job waits for it, so a tag with
a flagged dependency publishes nothing.

Pushing a `v` tag builds and publishes a release from that tag:

```sh
git tag v0.3.0
git push origin v0.3.0
```

The release holds `mjolnir-<target>.tar.gz` for Linux and macOS,
`mjolnir-<target>.zip` for Windows, a `SHA256SUMS` file covering them, and
`SHA256SUMS.sig`, which is the layout the install scripts and
`mjolnir update` expect.

The release job signs `SHA256SUMS` with the ECDSA P-256 private key in the
repository secret `RELEASE_SIGNING_KEY`, a PEM file such as
`openssl ecparam -name prime256v1 -genkey -noout` writes. It writes the key
to a file only the runner's user can read, signs, and deletes the file.
Then it checks the signature against the public key in
[`scripts/install.sh`](../scripts/install.sh), so a secret that does not match
the key users have fails the release. Without the secret the job fails and
nothing is published. The public key appears in `scripts/install.sh`,
`scripts/install.ps1`, and `RELEASE_KEY` in [`src/update.rs`](../src/update.rs),
and a unit test fails if the three differ. To rotate the key, generate a new
one, put its base64 SubjectPublicKeyInfo DER
(`openssl pkey -in key.pem -pubout -outform DER | openssl base64 -A`) in all
three places, and
replace the secret. Binaries released before the rotation trust only the old
key, so `mjolnir update` refuses later releases until reinstalled with the
scripts.
