# stng Makefile
# Build and test commands for language-aware string extraction
# Compatible with both GNU make and BSD make

BINARY = stng
# Cargo package name, read from Cargo.toml for `cut-release`'s `-p`.
PACKAGE := $(shell awk -F'"' '/^name = /{print $$2; exit}' Cargo.toml)
OUT_DIR = out

# For sccache, set RUSTC_WRAPPER=sccache in your environment

.PHONY: all build debug release check-cargo install install-precommit test test-unit lint fix fmt clean ci deny help bench-path bench-build sampled-benchmark heap-build heap-benchmark cut-release

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
	@echo "  install-precommit - Install git pre-commit hook (test + lint + override check)"
	@echo "  test        - Run all tests (unit + integration)"
	@echo "  test-unit   - Run only unit tests (skip integration tests)"
	@echo "  fmt         - Format all code with rustfmt"
	@echo "  fix         - Auto-fix clippy lints, then format with rustfmt"
	@echo "  lint        - Run code formatting and linting checks"
	@echo "  ci          - Run all CI checks (test + lint)"
	@echo "  deny        - Check advisories, licences and dependency sources"
	@echo "  clean       - Clean all build artifacts"
	@echo "  sampled-benchmark BENCH_PATH=... - CPU profile with samply"
	@echo "  heap-benchmark BENCH_PATH=...    - Heap profile with jemalloc"

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

install-precommit: ## Install the git pre-commit hook
	@hooks_dir="$$(git rev-parse --git-path hooks)"; \
	mkdir -p "$$hooks_dir"; \
	cp scripts/pre-commit "$$hooks_dir/pre-commit"; \
	chmod +x "$$hooks_dir/pre-commit"; \
	echo "✓ Pre-commit hook installed to $$hooks_dir/pre-commit"

test: ## Run all tests (unit + integration)
	@echo "Running all tests..."
	@if command -v cargo-nextest >/dev/null 2>&1; then \
		cargo nextest run --workspace --locked && \
		cargo test --doc --locked; \
	else \
		cargo test --workspace --locked; \
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

fix: ## Auto-fix clippy lints, then format with rustfmt
	@echo "Applying clippy fixes..."
	@cargo clippy --fix --workspace --all-targets --all-features --allow-dirty --allow-staged
	@cargo fmt --all
	@echo "✓ Fixes applied"

lint: ## Run code formatting and linting checks
	@echo "Checking formatting..."
	@cargo fmt --all --check
	@echo "✓ Formatting passed"
	@echo ""
	@echo "Running clippy with workspace lints..."
	@cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
	@cargo clippy --locked --no-default-features --lib -- -D warnings
	@RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --quiet
	@echo "✓ Clippy passed"
	@echo ""
	@echo "Checking for unused dependencies..."
	@if command -v cargo-machete >/dev/null 2>&1; then \
		cargo machete --with-metadata; \
	else \
		echo "Note: cargo-machete not installed, skipping dependency check"; \
	fi
	@echo ""
	@echo "✓ All lints passed"

deny: ## Check advisories, licences and dependency sources (deny.toml)
	@cargo deny --locked check

ci: test lint ## Run all CI checks (test + lint)
	@echo "✓ All CI checks passed"

# Set the version in Cargo.toml, Cargo.lock and a tag together, verify the
# build CI will run, then commit and tag. Pushing stays manual.
cut-release: ## Bump version + lockfile, verify, commit and tag (VERSION=x.y.z)
	@test -n "$(VERSION)" || { echo "usage: make cut-release VERSION=x.y.z" >&2; exit 1; }
	@printf '%s\n' "$(VERSION)" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$$' \
		|| { echo "VERSION must look like 1.2.3 (got '$(VERSION)')" >&2; exit 1; }
	@test -z "$$(git status --porcelain)" \
		|| { echo "working tree is dirty — the tag must capture exactly what was tested:" >&2; \
		     git status --short >&2; exit 1; }
	@if git rev-parse -q --verify "refs/tags/v$(VERSION)" >/dev/null; then \
		echo "tag v$(VERSION) already exists" >&2; exit 1; fi
	@# Rewrite only the first `version =`, which is the one in [package].
	@awk -v v="$(VERSION)" 'BEGIN{d=0} /^version = "/ && !d {print "version = \"" v "\""; d=1; next} {print}' \
		Cargo.toml > Cargo.toml.tmp && mv Cargo.toml.tmp Cargo.toml
	cargo update -p $(PACKAGE) --offline
	@# The exact gate release.yml applies, minus the hour of linking.
	cargo check --locked --all-targets
	git add Cargo.toml Cargo.lock
	git commit -m "v$(VERSION)"
	git tag -a "v$(VERSION)" -m "$(BINARY) $(VERSION)"
	@echo
	@echo "tagged v$(VERSION). to release:"
	@echo "    git push origin $$(git rev-parse --abbrev-ref HEAD) && git push origin v$(VERSION)"

clean: ## Clean all build artifacts
	@echo "Cleaning build artifacts..."
	cargo clean
	rm -rf $(OUT_DIR)
	@echo "✓ Clean complete"

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

# ----- profiling ----------------------------------------------------------
# CPU and heap profiles of one run over BENCH_PATH (a file or directory):
#
#     make sampled-benchmark BENCH_PATH=~/corpus
#     make heap-benchmark BENCH_PATH=~/corpus
#
# Build scripts that spawn their own `make` (tikv-jemalloc-sys) fail on GNU
# make's inherited jobserver flags, so cargo runs without them.
BENCH_CARGO = env -u MAKEFLAGS -u MAKELEVEL -u MFLAGS cargo
CARGO_TARGET ?= $(if $(CARGO_TARGET_DIR),$(CARGO_TARGET_DIR),target)

bench-path:
	@test -n "$(BENCH_PATH)" || { echo "usage: make $(MAKECMDGOALS) BENCH_PATH=<file or directory>" >&2; exit 1; }
	@test -e "$(BENCH_PATH)" || { echo "error: BENCH_PATH not found: $(BENCH_PATH)" >&2; exit 1; }

bench-build: $(OUT_DIR) ## Build benchmark binary (profiling profile, release + debug syms)
	$(BENCH_CARGO) build --profile profiling
	cp $(CARGO_TARGET)/profiling/$(BINARY) $(OUT_DIR)/$(BINARY).bench
	@if [ "$$(uname)" = "Darwin" ]; then codesign -s - -f $(OUT_DIR)/$(BINARY).bench; fi
	@echo "✓ Benchmark binary: $(OUT_DIR)/$(BINARY).bench"

sampled-benchmark: bench-path bench-build ## CPU profile with samply (BENCH_PATH=...)
	@command -v samply >/dev/null 2>&1 || { echo "Error: samply not installed. Run: cargo install samply"; exit 1; }
	samply record --save-only -o $(OUT_DIR)/bench.profile.json.gz -- \
		$(OUT_DIR)/$(BINARY).bench --json $(BENCH_PATH) \
		>$(OUT_DIR)/bench.out 2>$(OUT_DIR)/bench.err
	@echo "✓ Profile: $(OUT_DIR)/bench.profile.json.gz  Logs: $(OUT_DIR)/bench.err"

heap-build: $(OUT_DIR) ## Build with jemalloc heap profiling support
	$(BENCH_CARGO) build --profile profiling --features jemalloc-prof
	cp $(CARGO_TARGET)/profiling/$(BINARY) $(OUT_DIR)/$(BINARY).heap
	@if [ "$$(uname)" = "Darwin" ]; then codesign -s - -f $(OUT_DIR)/$(BINARY).heap; fi
	@echo "✓ Heap-profiling binary: $(OUT_DIR)/$(BINARY).heap"

heap-benchmark: bench-path heap-build ## Heap profile with jemalloc (BENCH_PATH=...)
	@rm -rf $(OUT_DIR)/heap && mkdir -p $(OUT_DIR)/heap
	_RJEM_MALLOC_CONF="prof:true,prof_active:true,prof_final:true,lg_prof_interval:28,prof_prefix:$(OUT_DIR)/heap/jeprof" \
		$(OUT_DIR)/$(BINARY).heap --json $(BENCH_PATH) \
		>$(OUT_DIR)/bench.out 2>$(OUT_DIR)/bench.err
	@echo "✓ Heap profiles: $(OUT_DIR)/heap/jeprof.*.heap"
	@echo "  Analyze with: jeprof --text $(OUT_DIR)/$(BINARY).heap $(OUT_DIR)/heap/jeprof.*.heap"
