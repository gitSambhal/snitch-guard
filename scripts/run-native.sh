#!/usr/bin/env bash
# ==============================================================================
# SnitchGuard - Single-Command Native Launcher
# Author: Suhail Akhtar (https://suhail.top)
# License: MIT
# ==============================================================================

set -e

# Compile daemon if missing
if [ ! -f "bin/snitchguard-daemon" ]; then
    echo "==> Daemon binary missing. Compiling Go daemon..."
    mkdir -p bin
    cd daemon && go build -o ../bin/snitchguard-daemon . && cd ..
    chmod +x bin/snitchguard-daemon
fi

# Build UI if dist is missing
if [ ! -d "dist" ]; then
    echo "==> UI dist missing. Compiling React bundle..."
    npm run build
fi

# Run the packaged launcher
if [ -f "bin/run-snitchguard.sh" ]; then
    ./bin/run-snitchguard.sh
else
    # Fallback direct runner
    echo "==> Starting Go Daemon..."
    ./bin/snitchguard-daemon --ws-port=9095 --proxy-port=9096 &
    DAEMON_PID=$!

    echo "==> Starting Neutralino desktop UI..."
    npx @neutralinojs/neu run || true

    kill $DAEMON_PID 2>/dev/null || true
fi
