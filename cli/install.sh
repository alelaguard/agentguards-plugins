#!/bin/sh
# AgentGuards installer for macOS and Linux.
#
#   curl -fsSL https://agentguards.co/install.sh | sh
#
# Downloads the `agentguards` binary for this machine from the latest GitHub
# release, refuses it unless its SHA-256 matches the release's SHA256SUMS,
# installs it to ~/.agentguards/bin, then runs `agentguards install`, which signs
# you in through your browser and protects every coding agent it finds.
#
# Pass installer options after `sh -s --`, e.g. for CI:
#   curl -fsSL https://agentguards.co/install.sh | sh -s -- --yes --key "$AGENTGUARDS_API_KEY"
#
# AGENTGUARDS_DOWNLOAD_BASE overrides where binaries come from (used by tests).
set -eu

REPO="alelaguard/agentguards-plugins"
BASE="${AGENTGUARDS_DOWNLOAD_BASE:-https://github.com/$REPO/releases/latest/download}"
BIN_DIR="${AGENTGUARDS_BIN_DIR:-$HOME/.agentguards/bin}"

fail() { printf 'AgentGuards installer: %s\n' "$1" >&2; exit 1; }

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) fail "unsupported system $(uname -s). On Windows, run in PowerShell: irm https://agentguards.co/install.ps1 | iex" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) fail "unsupported CPU $(uname -m)" ;;
esac
asset="agentguards_${os}_${arch}"

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL --retry 2 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q -O "$2" "$1"; }
else
  fail "needs curl or wget"
fi

if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
  fail "needs sha256sum or shasum to verify the download"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "Downloading the AgentGuards installer for $os/$arch..."
fetch "$BASE/$asset" "$tmp/$asset" || fail "download failed: $BASE/$asset"
fetch "$BASE/SHA256SUMS" "$tmp/SHA256SUMS" || fail "download failed: $BASE/SHA256SUMS"

expected="$(awk -v f="$asset" '$2 == f || $2 == "*"f {print $1}' "$tmp/SHA256SUMS")"
[ -n "$expected" ] || fail "no checksum for $asset in SHA256SUMS"
actual="$(sha256 "$tmp/$asset")"
[ "$expected" = "$actual" ] || fail "checksum mismatch for $asset — refusing to run it"

mkdir -p "$BIN_DIR"
chmod 755 "$tmp/$asset"
mv "$tmp/$asset" "$BIN_DIR/agentguards"
echo "Installed $BIN_DIR/agentguards"
# Clean up now: the `exec` below replaces this shell, so the EXIT trap never runs.
rm -rf "$tmp"
trap - EXIT INT TERM

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) echo "(To run it later: add $BIN_DIR to your PATH, or use $BIN_DIR/agentguards)" ;;
esac
echo

# Under `curl | sh` our stdin is this script, not the keyboard — hand the
# installer the terminal so it can ask before changing anything.
if (exec </dev/tty) 2>/dev/null; then
  exec "$BIN_DIR/agentguards" install "$@" </dev/tty
fi
exec "$BIN_DIR/agentguards" install "$@"
