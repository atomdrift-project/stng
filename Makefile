# stng Makefile
# Build and test commands for language-aware string extraction
# Compatible with both GNU make and BSD make

BINARY = stng
OUT_DIR = out

# For sccache, set RUSTC_WRAPPER=sccache in your environment

.PHONY: all build debug release check-cargo install install-precommit test test-unit lint fix fmt clean ci help bench-build sampled-benchmark heap-build heap-benchmark tuna tuna-once

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

install-precommit: ## Install the git pre-commit hook
	@hooks_dir="$$(git rev-parse --git-path hooks)"; \
	mkdir -p "$$hooks_dir"; \
	cp scripts/pre-commit "$$hooks_dir/pre-commit"; \
	chmod +x "$$hooks_dir/pre-commit"; \
	echo "✓ Pre-commit hook installed to $$hooks_dir/pre-commit"

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
	@cargo clippy --workspace --all-targets --all-features
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

ci: test lint ## Run all CI checks (test + lint)
	@echo "✓ All CI checks passed"

clean: ## Clean all build artifacts
	@echo "Cleaning build artifacts..."
	cargo clean
	rm -rf $(OUT_DIR)
	@echo "✓ Clean complete"

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

# ----- cleave-tuna integration --------------------------------------------
# Standardized targets that cleave-tuna drives. The naming mirrors cleave/litmus
# so one tuna binary can tune all three repos. See ../cleave-tuna/README.md.
#
# Scrub GNU make's jobserver from cargo's environment. Without this, build
# scripts that spawn their own `make` (e.g. tikv-jemalloc-sys) inherit a
# malformed MAKEFLAGS and fail with "No rule to make target '-j'".
TUNA_CARGO = env -u MAKEFLAGS -u MAKELEVEL -u MFLAGS cargo

# Honor CARGO_TARGET_DIR if set (cleave-tuna sets it to share the cargo
# cache across worktrees). Falls back to the cargo default `target` otherwise.
CARGO_TARGET ?= $(if $(CARGO_TARGET_DIR),$(CARGO_TARGET_DIR),target)

TUNA_DATASET    ?= 600MB
BENCHMARK_ROOT  ?= $(HOME)/data/benchmark
TUNA_BENCH_PATH ?= $(BENCHMARK_ROOT)/$(TUNA_DATASET)

bench-build: $(OUT_DIR) ## Build benchmark binary (profiling profile, release + debug syms)
	$(TUNA_CARGO) build --profile profiling
	cp $(CARGO_TARGET)/profiling/$(BINARY) $(OUT_DIR)/$(BINARY).bench
	@if [ "$$(uname)" = "Darwin" ]; then codesign -s - -f $(OUT_DIR)/$(BINARY).bench; fi
	@echo "✓ Benchmark binary: $(OUT_DIR)/$(BINARY).bench"

sampled-benchmark: bench-build ## Benchmark with samply CPU profiling
	@command -v samply >/dev/null 2>&1 || { echo "Error: samply not installed. Run: cargo install samply"; exit 1; }
	@[ -e "$(TUNA_BENCH_PATH)" ] || { echo "error: benchmark path not found: $(TUNA_BENCH_PATH)"; exit 1; }
	samply record --save-only -o $(OUT_DIR)/bench.profile.json.gz -- \
		$(OUT_DIR)/$(BINARY).bench --json $(TUNA_BENCH_PATH) \
		>$(OUT_DIR)/bench.out 2>$(OUT_DIR)/bench.err
	@echo "✓ Profile: $(OUT_DIR)/bench.profile.json.gz  Logs: $(OUT_DIR)/bench.err"

heap-build: $(OUT_DIR) ## Build with jemalloc heap profiling support
	$(TUNA_CARGO) build --profile profiling --features jemalloc-prof
	cp $(CARGO_TARGET)/profiling/$(BINARY) $(OUT_DIR)/$(BINARY).heap
	@if [ "$$(uname)" = "Darwin" ]; then codesign -s - -f $(OUT_DIR)/$(BINARY).heap; fi
	@echo "✓ Heap-profiling binary: $(OUT_DIR)/$(BINARY).heap"

heap-benchmark: heap-build ## Benchmark with jemalloc heap profiling
	@[ -e "$(TUNA_BENCH_PATH)" ] || { echo "error: benchmark path not found: $(TUNA_BENCH_PATH)"; exit 1; }
	@rm -rf $(OUT_DIR)/heap && mkdir -p $(OUT_DIR)/heap
	_RJEM_MALLOC_CONF="prof:true,prof_active:true,prof_final:true,lg_prof_interval:28,prof_prefix:$(OUT_DIR)/heap/jeprof" \
		$(OUT_DIR)/$(BINARY).heap --json $(TUNA_BENCH_PATH) \
		>$(OUT_DIR)/bench.out 2>$(OUT_DIR)/bench.err
	@echo "✓ Heap profiles: $(OUT_DIR)/heap/jeprof.*.heap"
	@echo "  Analyze with: jeprof --text $(OUT_DIR)/$(BINARY).heap $(OUT_DIR)/heap/jeprof.*.heap"

# cleave-tuna: LLM-driven CPU+memory autoresearch loop. See ../cleave-tuna/README.md.
TUNA_REPO            ?= ../cleave-tuna
TUNA_BIN             ?= $(TUNA_REPO)/out/cleave-tuna
TUNA_EXPERIMENTS     ?= 6
TUNA_SCREEN_SAMPLES  ?= 1
TUNA_CONFIRM_SAMPLES ?= 2
TUNA_PROVIDER        ?= gemini,codex,claude
TUNA_MODE            ?=
TUNA_INTERVAL        ?= 30

tuna: ## Run cleave-tuna in a loop, alternating memory/cpu; cherry-picks wins (Ctrl-C to stop)
	@test -x $(TUNA_BIN) || { echo "build cleave-tuna first: (cd $(TUNA_REPO) && make build)"; exit 1; }
	@test -z "$$(git status --porcelain)" || { echo "working tree must be clean before starting tuna"; exit 1; }
	@echo "tuna: looping forever, alternating memory/cpu (Ctrl-C to stop). settings: dataset=$(TUNA_DATASET) experiments=$(TUNA_EXPERIMENTS) screen-samples=$(TUNA_SCREEN_SAMPLES) confirm-samples=$(TUNA_CONFIRM_SAMPLES) provider=$(TUNA_PROVIDER)"
	@mode=memory; \
	while true; do \
		echo "tuna: starting cycle in $$mode mode"; \
		$(MAKE) tuna-once TUNA_MODE=$$mode || exit $$?; \
		if [ "$$mode" = "memory" ]; then mode=cpu; else mode=memory; fi; \
		echo "tuna: sleeping $(TUNA_INTERVAL)s before next cycle ($$mode) — Ctrl-C to stop"; \
		sleep $(TUNA_INTERVAL); \
	done

tuna-once: ## One cleave-tuna cycle, then cherry-pick accepted experiments
	@test -x $(TUNA_BIN) || { echo "build cleave-tuna first: (cd $(TUNA_REPO) && make build)"; exit 1; }
	@test -z "$$(git status --porcelain)" || { echo "working tree must be clean before tuna-once"; exit 1; }
	@before=$$(git rev-parse HEAD); \
	$(TUNA_BIN) --source $(CURDIR) --root $(TUNA_REPO) --dataset $(TUNA_DATASET) \
		--name stng \
		--bench-arg --json \
		--deny vendor/ --deny testdata/ --deny media/ \
		--experiments $(TUNA_EXPERIMENTS) \
		--screen-samples $(TUNA_SCREEN_SAMPLES) --confirm-samples $(TUNA_CONFIRM_SAMPLES) \
		--provider $(TUNA_PROVIDER) $(if $(TUNA_MODE),--$(TUNA_MODE),) \
		|| { echo "tuna: cleave-tuna exited non-zero; not cherry-picking"; exit 1; }; \
	branch=$$(git for-each-ref --sort=-committerdate --format='%(refname:short)' 'refs/heads/tuna/*' | head -1); \
	if [ -z "$$branch" ]; then echo "tuna: no tuna/* branch found"; exit 0; fi; \
	ahead=$$(git rev-list --count $$before..$$branch); \
	if [ "$$ahead" = "0" ]; then \
		echo "tuna: no accepted experiments on $$branch — nothing to cherry-pick"; \
		exit 0; \
	fi; \
	echo "tuna: cherry-picking $$ahead commit(s) from $$branch"; \
	git cherry-pick $$branch~$$ahead..$$branch
