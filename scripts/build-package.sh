#!/usr/bin/env bash
# ==============================================================================
# SnitchGuard - Unified Native Packaging & Build Script (Neutralinojs + Go Daemon)
# Author: Suhail Akhtar (https://suhail.top)
# License: MIT
# ==============================================================================

set -e

echo "=================================================================="
echo " SnitchGuard - Building Unified Native Application Bundle"
echo " Author: Suhail Akhtar (https://suhail.top)"
echo " Target: Neutralinojs Desktop Client + Elevated Go Daemon"
echo "=================================================================="

# 1. Clean previous build artifacts
echo "[1/4] Cleaning build artifacts..."
rm -rf dist bin/snitchguard-daemon bin/snitchguard-*

# 2. Build Vite/React UI bundle
echo "[2/4] Compiling React frontend with Vite..."
npm run build

# 3. Compile Go Daemon Binary
echo "[3/4] Compiling elevated Go Firewall Daemon (SNI + Socket Resolver)..."
mkdir -p bin
cd daemon
go build -v -ldflags="-s -w" -o ../bin/snitchguard-daemon .
cd ..
chmod +x bin/snitchguard-daemon
echo "  -> Created: bin/snitchguard-daemon"

# 4. Package with Neutralino CLI
echo "[4/4] Packaging unified desktop binaries with Neutralinojs..."
mkdir -p dist/js
cp public/js/neutralino.js dist/js/neutralino.js 2>/dev/null || true

if command -v neu >/dev/null 2>&1; then
    neu update || true
    neu build --release
    echo "  -> Neutralino build generated in bin/"
else
    echo "  -> neu CLI not found globally. Trying npx @neutralinojs/neu..."
    npx @neutralinojs/neu update || true
    npx @neutralinojs/neu build --release || true
fi

# 5. Create Standalone Run Wrapper
cat << 'EOF' > bin/run-snitchguard.sh
#!/usr/bin/env bash
# SnitchGuard Unified Native Launcher
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
PARENT_DIR="$(dirname "$DIR")"

echo "==> Launching SnitchGuard Host Application Firewall..."

# Start elevated Go daemon in background if not already active
if ! lsof -i:9095 >/dev/null 2>&1; then
    echo "==> Starting elevated Go daemon (ws://127.0.0.1:9095)..."
    if [ "$EUID" -ne 0 ]; then
        echo "Note: Running with sudo for raw kernel socket interception..."
        sudo "$DIR/snitchguard-daemon" --ws-port=9095 --proxy-port=9096 --rules="$PARENT_DIR/firewall_rules.json" &
        DAEMON_PID=$!
    else
        "$DIR/snitchguard-daemon" --ws-port=9095 --proxy-port=9096 --rules="$PARENT_DIR/firewall_rules.json" &
        DAEMON_PID=$!
    fi
    sleep 0.5
fi

# Launch Neutralino binary
echo "==> Launching Neutralino native window..."
cd "$PARENT_DIR"
if [ -f "$DIR/snitchguard-linux_x64" ]; then
    "$DIR/snitchguard-linux_x64"
elif [ -f "$DIR/snitchguard-mac_x64" ]; then
    "$DIR/snitchguard-mac_x64"
elif [ -f "$DIR/snitchguard-mac_arm64" ]; then
    "$DIR/snitchguard-mac_arm64"
else
    npx @neutralinojs/neu run
fi

# Cleanup on window exit
if [ -n "$DAEMON_PID" ]; then
    echo "==> Stopping Go daemon..."
    kill $DAEMON_PID 2>/dev/null || true
fi
EOF

chmod +x bin/run-snitchguard.sh

echo "=================================================================="
echo " BUILD SUCCESSFUL!"
echo " Everything packaged into a unified native application."
echo " To run natively: ./bin/run-snitchguard.sh (or 'make run-native')"
echo "=================================================================="
