#!/bin/sh
# Download, verify and install the static SDK used by Go builds.
set -eu
umask 022

fail() {
  echo "$*" >&2
  exit 1
}

version=0.1.5
case "${1:-}" in
  '')
    ;;
  --version)
    [ "$#" -eq 2 ] || fail 'Usage: install-xconn-sdk.sh [--version VERSION]'
    version=$2
    ;;
  --help|-h)
    echo 'Usage: install-xconn-sdk.sh [--version VERSION]'
    exit 0
    ;;
  *)
    fail 'Usage: install-xconn-sdk.sh [--version VERSION]'
    ;;
esac

if ! printf '%s\n' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  fail 'Invalid SDK version.'
fi

for tool in go cc pkg-config curl tar; do
  if ! command -v "$tool" >/dev/null; then
    fail "Install $tool before running this installer."
  fi
done

case "$(uname -s)/$(uname -m)" in
  Linux/x86_64)
    target=x86_64-unknown-linux-gnu
    ;;
  Linux/aarch64|Linux/arm64)
    target=aarch64-unknown-linux-gnu
    ;;
  Darwin/arm64)
    target=aarch64-apple-darwin
    ;;
  *)
    fail 'Supported hosts: Linux amd64/arm64 and macOS arm64.'
    ;;
esac

prefix=/usr/local
if [ "$(uname -s)" = Darwin ] && [ -d /opt/homebrew ]; then
  prefix=/opt/homebrew
fi

temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
trap 'exit 1' HUP INT TERM

# Download the archive and its published checksum.
name=xconn-native-$version-$target-static
base=https://github.com/xconnio/xconn-core/releases/download/v$version
curl -fLsS -o "$temporary/sdk.tar.gz" "$base/$name.tar.gz"
curl -fLsS -o "$temporary/checksum" "$base/$name.tar.gz.sha256"

expected=$(awk 'NR == 1 {print $1}' "$temporary/checksum")
if command -v sha256sum >/dev/null; then
  actual=$(sha256sum "$temporary/sdk.tar.gz" | awk '{print $1}')
else
  actual=$(shasum -a 256 "$temporary/sdk.tar.gz" | awk '{print $1}')
fi

if [ "$actual" != "$expected" ]; then
  fail 'SDK archive SHA-256 mismatch.'
fi

# Verify paths and file types before extracting the trusted release archive.
tar -tzf "$temporary/sdk.tar.gz" > "$temporary/entries"
if ! awk -v root="$name" '
  $0 != root && index($0, root "/") != 1 {exit 1}
  /(^|\/)\.\.(\/|$)/ {exit 1}
' "$temporary/entries"; then
  fail 'Unsafe SDK archive path.'
fi

tar -tvzf "$temporary/sdk.tar.gz" > "$temporary/types"
if ! awk 'substr($0, 1, 1) !~ /[-d]/ {exit 1}' "$temporary/types"; then
  fail 'SDK archives must not contain links or special files.'
fi

tar -xzf "$temporary/sdk.tar.gz" --no-same-owner -C "$temporary"
sdk=$temporary/$name

if ! grep -Eq '^#define XC_ABI_VERSION 1[[:space:]]*$' "$sdk/include/xconn.h"; then
  fail 'Unsupported XConn ABI.'
fi

if [ ! -f "$sdk/lib/libxconn_ffi.a" ]; then
  fail 'Static library missing.'
fi

if [ "$(pkg-config --modversion "$sdk/lib/pkgconfig/xconn-static.pc")" != "$version" ]; then
  fail 'SDK version does not match the request.'
fi

# Install verified files and point pkg-config at this version.
needs_sudo=false
for location in "$prefix/lib/xconn" "$prefix/lib/pkgconfig"; do
  probe=$location
  while [ ! -e "$probe" ]; do
    probe=$(dirname "$probe")
  done
  if [ ! -w "$probe" ] && [ "$(id -u)" -ne 0 ]; then
    needs_sudo=true
  fi
done

run() {
  if [ "$needs_sudo" = true ]; then
    sudo "$@"
  else
    "$@"
  fi
}

if [ "$needs_sudo" = true ]; then
  echo "Installing into $prefix requires administrator privileges." >&2
fi

destination=$prefix/lib/xconn/$version/$target-static
pkgconfig=$prefix/lib/pkgconfig
run mkdir -p "$destination" "$pkgconfig"
run cp -R "$sdk/." "$destination/"

sed "s|^prefix=.*|prefix=$destination|" "$sdk/lib/pkgconfig/xconn-static.pc" > "$temporary/xconn.pc"
run install -m 644 "$temporary/xconn.pc" "$pkgconfig/xconn.pc"
run install -m 644 "$temporary/xconn.pc" "$pkgconfig/xconn-static.pc"

echo "Installed static XConn SDK $version for $target in $prefix."
echo 'Ready for go get and go build. After switching SDK versions, relink with go build -a.'
