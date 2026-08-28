# SnitchGuard - Host Application Firewall Makefile
# Author: Suhail Akhtar (https://suhail.top)

.PHONY: all build build-daemon build-ui package run-native run-daemon ui test clean help

all: package

help:
	@echo "SnitchGuard - Unified Build & Packaging Targets:"
	@echo "  make package       - Build UI + Go daemon + package into single Neutralino native app"
	@echo "  make run-native    - Run the unified native app (auto-starts Go daemon + Neutralino window)"
	@echo "  make build-daemon  - Compile Go daemon binary (SNI parser + socket resolver)"
	@echo "  make build-ui      - Compile React frontend (Vite -> dist/)"
	@echo "  make run-daemon    - Run elevated Go daemon standalone (sudo)"
	@echo "  make ui            - Run Neutralino desktop dev mode (neu run)"
	@echo "  make test          - Run Go daemon test suite"
	@echo "  make clean         - Clean all built artifacts"

build: build-ui build-daemon

build-daemon:
	@echo "==> Building elevated Go daemon..."
	@mkdir -p bin
	cd daemon && go build -ldflags="-s -w" -o ../bin/snitchguard-daemon .
	@chmod +x bin/snitchguard-daemon
	@echo "==> Built bin/snitchguard-daemon successfully."

build-ui:
	@echo "==> Building frontend assets with Vite..."
	npm run build

package:
	@echo "==> Packaging SnitchGuard into unified native desktop application..."
	bash ./scripts/build-package.sh

run-native:
	@echo "==> Starting SnitchGuard unified native application..."
	bash ./scripts/run-native.sh

run-daemon: build-daemon
	@echo "==> Running SnitchGuard elevated daemon..."
	sudo ./bin/snitchguard-daemon --ws-port=9095 --proxy-port=9096 --rules=firewall_rules.json

ui:
	@echo "==> Starting Neutralino desktop client..."
	@if command -v neu >/dev/null 2>&1; then \
		neu run; \
	else \
		npx @neutralinojs/neu run; \
	fi

test:
	cd daemon && go test -v ./...

clean:
	rm -rf bin/ dist/ firewall_rules.json
