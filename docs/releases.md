# Binding distribution

Source, CI, and local packaging live in this repository. Publishing registry
packages and platform artifacts is a separate release step; no public release
is implied by local tests.

| Consumer | Distribution | Consumer requirement |
| --- | --- | --- |
| Rust | crates.io packages | Rust toolchain |
| Python | `xconn-core` ABI3 wheels on PyPI | Matching supported wheel |
| Go | `github.com/xconnio/xconn-core/bindings/go` plus native SDK | Cgo toolchain and matching SDK |
| Dart / Flutter | `xconn_core` plus platform native library | Native asset integration |
| Browser JS / TS | `@xconnio/core` on npm with WASM | Browser WebSocket and WASM support |

## Native SDK

Native SDK `v0.1.5` is prepared for the shared attachment and stream-broker APIs.
After the service branch merges, publish its SDK tag, then tag the Go module
`bindings/go/v0.1.5`. Application dependency updates must wait for both releases.
See the [connectivity runtime release order](connectivity-runtime.md#integration-findings-and-release-order).


[`scripts/package-native.py`](../scripts/package-native.py) stages or archives
headers, the shared or static Rust library, pkg-config metadata, checksums, and
build provenance. Archives support native Linux/macOS builds, Windows amd64 GNU
builds, and an Android ARM64 cross-build. Linux, macOS and Windows GNU static SDK
staging is also available. See [native installation](native-install.md).
Build outputs belong in release artifacts, not Git source history.

The `Native SDK release` workflow builds and checks nine archives across Linux, macOS,
Windows and Android, then creates the GitHub Release after every matrix job passes. It runs
on tags named `vVERSION`; the tag must match `bindings/ffi/Cargo.toml`. It can
also be dispatched manually with an existing tag. Both paths check out the tag,
so the manifest's source revision identifies the released code.

Merge the release workflow and intended source changes before creating a tag.
Android ARM64 is prepared for native SDK `v0.1.1`; create that tag on the
reviewed commit after merging. Do not replace the existing `v0.1.0` tag or
release assets. This changes the internal FFI package version; the published
Rust libraries remain at `0.1.0`.
No extra publishing token is needed: only the final job receives the repository
`GITHUB_TOKEN` with release-write permission. Existing releases/assets are not
overwritten; a failed upload may require removing an incomplete draft before
retrying. The archives include WebRTC with the workspace's pinned SCTP fix.
The workflow calls `ci/check-native-release.sh` to check the tag/host,
`ci/test-native-sdk.sh` to exercise extracted SDKs, and
`ci/publish-native-sdk.sh` to verify checksums and create the release. The smoke
test can also run locally with an archive directory as its argument.
Android uses `ci/build-android-sdk.sh` with the pinned NDK and
`ci/test-android-sdk.sh` for ELF/API linking checks. Android binaries are not
executed on the Linux runner. Windows uses the GNU toolchain and `ci/test-windows-sdk.sh` to compile and run
C and Go consumers against both SDK variants. Publication waits for all platform jobs.
See [native installation](native-install.md) for the platform matrix and limits.

Native SDK `v0.1.2` adds the macOS ARM64 static archive and the Go installer.
After merging, release SDK `v0.1.2`, then tag the Go module `bindings/go/v0.1.2`.
The single shell installer downloads from the SDK tag without building a helper
or depending on a Go module release. The Go module tag is only needed for
`go get`. Linux installer checks can also use existing SDK 0.1.1 before tagging.
Native SDK checks build a standalone Go consumer through the installed static SDK.

Go modules in this repository use tags such as `bindings/go/v0.1.2`. Installing
the Go module alone does not install the native SDK. The installer runs first
and configures ordinary Go builds to select the static archive through pkg-config.

## Python

Maturin builds the PyO3 extension and Python package together. Wheels target the
CPython 3.10+ stable ABI. Platform wheels must be built and validated on the
supported target or repaired using the appropriate platform tooling before
publication. Consumers of a compatible wheel do not need Rust or a separate SDK.
The package imports as `xconn_core` and has no required Python runtime dependency.

Use `uv build bindings/python --out-dir target/python-dist` for local source and
wheel builds. `uv` builds the wheel from the source archive, checking that the
workspace crates and pinned SCTP dependency survive source packaging.
The manually dispatched `Python release artifacts` workflow calls
`ci/build-python-release.sh` on Linux x86-64/ARM64 in manylinux 2.28 containers
and on macOS ARM64. It repairs Linux wheels, checks metadata with `uvx twine`,
tests native crypto from the installed wheel, and uploads artifacts only.
It neither publishes to PyPI nor creates a GitHub release.

After reviewing the artifacts, combine all wheels with one copy of the source
archive, check them with `uvx twine check`, and publish with `uv publish` using
PyPI credentials. Do not upload an unrepaired local `linux_x86_64` wheel.
The optional Cap'n Proto serializer must be installed separately; its GitHub
URL is not included in PyPI dependency metadata.

## Dart and Flutter

Dart uses the shared C ABI through FFI. Local tests can set `XCONN_LIBRARY` to an
explicit native library. Flutter platform packaging needs to deliver and load
that library for each supported target; this repository does not yet automate
all platform distributions. Python and Dart expose clients only.

## Browser package

The npm package includes compiled JS, TypeScript declarations, and WASM. Its
browser networking uses native WebSocket APIs; it does not load the native C ABI.
Build and test the full package and the reduced WASM variants before release.
