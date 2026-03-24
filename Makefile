# stng Makefile
# Build and test commands for language-aware string extraction
# Compatible with both GNU make and BSD make

BINARY = stng
OUT_DIR = out

# For sccache, set RUSTC_WRAPPER=sccache in your environment

.PHONY: all build debug release check-cargo install test test-unit lint fmt clean ci help

# Default target
all: build

help: ## Show this help
	@echo "stng Makefile"
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build       - Build in debug mode (default)"
	@echo "  debug       - Build in debug mode"
	@echo "  release     - Build in release mode"
	@echo "  install     - Build release and install to PATH"
	@echo "  test        - Run all tests (unit + integration)"
	@echo "  test-unit   - Run only unit tests (skip integration tests)"
	@echo "  fmt         - Format all code with rustfmt"
	@echo "  lint        - Run code formatting and linting checks"
	@echo "  ci          - Run all CI checks (test + lint)"
	@echo "  clean       - Clean all build artifacts"

build: debug ## Build in debug mode (default)

debug: ## Build in debug mode
	@echo "Building $(BINARY) (debug mode)..."
	cargo build
	@echo "✓ Debug build successful"

check-cargo: ## Verify cargo is installed
	@command -v cargo >/dev/null 2>&1 || { \
		echo "Error: cargo not found. Install Rust via:"; \
		case "$$(uname -s)" in \
			Darwin)  echo "  brew install rust   # or: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh" ;; \
			FreeBSD) echo "  pkg install rust" ;; \
			OpenBSD) echo "  pkg_add rust" ;; \
			NetBSD)  echo "  pkgin install rust   # or: pkg_add rust" ;; \
			SunOS)   echo "  pkgin install rust" ;; \
			Linux) \
				if command -v apt-get >/dev/null 2>&1; then \
					echo "  apt-get install cargo   # or: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"; \
				elif command -v dnf >/dev/null 2>&1; then \
					echo "  dnf install cargo   # or: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"; \
				elif command -v pacman >/dev/null 2>&1; then \
					echo "  pacman -S rust   # or: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"; \
				elif command -v apk >/dev/null 2>&1; then \
					echo "  apk add cargo   # or: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"; \
				else \
					echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"; \
				fi ;; \
			*) echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh" ;; \
		esac; \
		exit 1; \
	}

release: check-cargo $(OUT_DIR) ## Build in release mode
	@echo "Building $(BINARY) (release mode)..."
	cargo build --release
	cp target/release/$(BINARY) $(OUT_DIR)/
	@if [ "$$(uname)" = "Darwin" ]; then codesign -s - -f $(OUT_DIR)/$(BINARY); fi
	@echo "✓ Release binary: $(OUT_DIR)/$(BINARY)"

install: release ## Install binary to first writeable location
	@if echo "$$PATH" | tr ':' '\n' | grep -qx "$$HOME/.cargo/bin" && [ -d "$$HOME/.cargo/bin" ]; then \
		cp $(OUT_DIR)/$(BINARY) "$$HOME/.cargo/bin/$(BINARY)"; \
		echo "✓ Installed to $$HOME/.cargo/bin/$(BINARY)"; \
	elif [ -d "$$HOME/bin" ] && [ -w "$$HOME/bin" ]; then \
		cp $(OUT_DIR)/$(BINARY) "$$HOME/bin/$(BINARY)"; \
		echo "✓ Installed to $$HOME/bin/$(BINARY)"; \
	elif [ -d "$$HOME/.local/bin" ] && [ -w "$$HOME/.local/bin" ]; then \
		cp $(OUT_DIR)/$(BINARY) "$$HOME/.local/bin/$(BINARY)"; \
		echo "✓ Installed to $$HOME/.local/bin/$(BINARY)"; \
	elif [ -w /usr/local/bin ]; then \
		cp $(OUT_DIR)/$(BINARY) /usr/local/bin/$(BINARY); \
		echo "✓ Installed to /usr/local/bin/$(BINARY)"; \
	else \
		mkdir -p "$$HOME/.cargo/bin"; \
		cp $(OUT_DIR)/$(BINARY) "$$HOME/.cargo/bin/$(BINARY)"; \
		echo "✓ Installed to $$HOME/.cargo/bin/$(BINARY)"; \
	fi

test: ## Run all tests (unit + integration)
	@echo "Running all tests..."
	@cargo build --quiet
	@if command -v cargo-nextest >/dev/null 2>&1; then \
		cargo nextest run --workspace; \
	else \
		cargo test --workspace; \
	fi
	@echo ""
	@echo "✓ All tests passed"

test-unit: ## Run only unit tests (skip integration tests)
	@echo "Running unit tests only..."
	@if command -v cargo-nextest >/dev/null 2>&1; then \
		cargo nextest run --lib; \
	else \
		cargo test --lib; \
	fi
	@echo ""
	@echo "✓ Unit tests passed"

fmt: ## Format all code with rustfmt
	@echo "Formatting code..."
	@cargo fmt --all
	@echo "✓ Code formatted"

lint: ## Run code formatting and linting checks
	@echo "Checking formatting..."
	@cargo fmt --all --check
	@echo "✓ Formatting passed"
	@echo ""
	@echo "Running clippy with workspace lints..."
	@cargo clippy --workspace --all-targets --all-features
	@echo "✓ Clippy passed"
	@echo ""
	@echo "Checking for unused dependencies..."
	@cargo machete --with-metadata || echo "Note: cargo-machete not installed, skipping dependency check"
	@echo ""
	@echo "✓ All lints passed"

ci: test lint ## Run all CI checks (test + lint)
	@echo "✓ All CI checks passed"

clean: ## Clean all build artifacts
	@echo "Cleaning build artifacts..."
	cargo clean
	rm -rf $(OUT_DIR)
	@echo "✓ Clean complete"

$(OUT_DIR):
	mkdir -p $(OUT_DIR)
