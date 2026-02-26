#!/usr/bin/env bash
set -eo pipefail

echo "Installing symb..."

BASE_DIR="${XDG_CONFIG_HOME:-$HOME}"
SYMB_DIR="${SYMB_DIR:-"$BASE_DIR/.symb"}"
SYMB_BIN_DIR="$SYMB_DIR/bin"
SYMB_CLI_DIR="$SYMB_DIR/cli"

ARCHIVE_URL="${SYMB_ARCHIVE_URL:-"https://codeload.github.com/symbioticfi/cli/tar.gz/refs/heads/main"}"

for cmd in curl tar node; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "Missing required command: $cmd" >&2; exit 1; }
done

NODE_MAJOR="$(node -p "process.versions.node.split('.')[0]")"
if [[ ! "$NODE_MAJOR" =~ ^[0-9]+$ ]]; then
  echo "Failed to detect Node.js version. Node.js >= 20 is required." >&2
  exit 1
fi
if [ "$NODE_MAJOR" -lt 20 ]; then
  echo "Node.js >= 20 is required. Detected: $(node -v)" >&2
  exit 1
fi

# Create the symb bin directory and ensure pnpm is available (via corepack if needed).
mkdir -p "$SYMB_BIN_DIR"

PNPM="pnpm"
if ! command -v pnpm >/dev/null 2>&1; then
  echo "pnpm not found; enabling via corepack..."
  command -v corepack >/dev/null 2>&1 || { echo "corepack not found. Install pnpm and retry." >&2; exit 1; }
  corepack enable --install-directory "$SYMB_BIN_DIR"
  PNPM="$SYMB_BIN_DIR/pnpm"
fi

echo "Downloading symbioticfi/cli@main..."
rm -rf "$SYMB_CLI_DIR"
mkdir -p "$SYMB_CLI_DIR"
curl -sSf -L "$ARCHIVE_URL" | tar -xz -C "$SYMB_CLI_DIR" --strip-components=1

echo "Installing dependencies..."
(cd "$SYMB_CLI_DIR" && "$PNPM" install --frozen-lockfile)

echo "Building..."
(cd "$SYMB_CLI_DIR" && "$PNPM" build)

# Link executable into the bin directory.
chmod +x "$SYMB_CLI_DIR/dist/index.js"
ln -sf "$SYMB_CLI_DIR/dist/index.js" "$SYMB_BIN_DIR/symb"

case $SHELL in
*/zsh)
  PROFILE="${ZDOTDIR-"$HOME"}/.zshenv"
  PREF_SHELL=zsh
  ;;
*/bash)
  PROFILE="$HOME/.bashrc"
  PREF_SHELL=bash
  ;;
*/fish)
  PROFILE="$HOME/.config/fish/config.fish"
  PREF_SHELL=fish
  ;;
*/ash)
  PROFILE="$HOME/.profile"
  PREF_SHELL=ash
  ;;
*)
  echo "symb: could not detect shell, manually add ${SYMB_BIN_DIR} to your PATH."
  exit 1
esac

if [[ ":$PATH:" != *":${SYMB_BIN_DIR}:"* ]]; then
  if [[ "$PREF_SHELL" == "fish" ]]; then
    echo >>"$PROFILE" && echo "fish_add_path -a \"$SYMB_BIN_DIR\"" >>"$PROFILE"
  else
    echo >>"$PROFILE" && echo "export PATH=\"\\$PATH:$SYMB_BIN_DIR\"" >>"$PROFILE"
  fi
fi

if [[ "$OSTYPE" =~ ^darwin ]] && [[ ! -f /usr/local/opt/libusb/lib/libusb-1.0.0.dylib ]] && [[ ! -f /opt/homebrew/opt/libusb/lib/libusb-1.0.0.dylib ]]; then
  echo && echo "warning: libusb not found. You may need to install it manually on MacOS via Homebrew (brew install libusb)."
fi

echo
echo "Detected your preferred shell is $PREF_SHELL and added symb to PATH."
echo "Run 'source $PROFILE' or start a new terminal session to use symb."
echo "Then, simply run 'symb --help'."
