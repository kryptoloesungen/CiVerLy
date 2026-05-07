.PHONY: check check-fix format format-check spell lint test test-ci test-docs test-extensive test-dir help

NIX_OR_NOTHING := $(if $(shell command -v nix 2>/dev/null),nix develop --command,)

# ==============================================================================
# Help
# ==============================================================================

help:
	@echo "Available targets:"
	@echo "  lint          Run all checks (ruff check, ruff format --check, codespell, lychee)"
	@echo "  check         Run ruff linter"
	@echo "  check-fix     Run ruff linter and auto-fix issues"
	@echo "  format        Run ruff formatter"
	@echo "  format-check  Check formatting without modifying files"
	@echo "  spell         Run codespell"
	@echo "  check-links   Run lychee to search for dead links"
	@echo "  test          Run sage tests"
	@echo "  test-ci       Run sage tests with all solvers except gurobi, including long tests and docs"
	@echo "  test-docs     Run sage tests on code in the docs"
	@echo "  test-extensive Run all solver combinations with and without --long"
	@echo ""
	@echo "Options:"
	@echo "  SOLVERS='scip glpk'  Enable specific solvers (default: none)"
	@echo "  LONG=1               Enable long tests"
	@echo "  NTHREADS=4           Number of parallel test threads (default: 8, test-ci: 2)"
	@echo "  WARN_LONG=60         Warn about tests slower than this many seconds (default: 180)"
	@echo "  EXIT_FIRST=0         Disable exit on first failure (default: 1)"
	@echo "  LOGFILE=foo.log      Override the default timestamped logfile name"

# ==============================================================================
# Linting
# ==============================================================================

check:
	ruff check $(TEST_DIR)

check-fix:
	ruff check --fix $(TEST_DIR)

format:
	ruff format $(TEST_DIR)

format-check:
	ruff format --check $(TEST_DIR)

spell:
	codespell $(TEST_DIR) docs

check-links:
	git ls-files | grep -v "\.png$$" | xargs lychee --user-agent "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0" --retry-wait-time 1 --max-concurrency 1 --accept "100..=103,200..=299,403"

lint: check format-check spell check-links

# ==============================================================================
# Tests
# ==============================================================================

SAGE              := sage
NTHREADS          := 8
WARN_LONG         := 180
SAGE_FLAGS         = -t --nthreads=$(NTHREADS) --warn-long=$(WARN_LONG) --timeout 0
TEST_DIR          := src/civerly
ALL_OPTIONALS     := scip glpk gurobi cryptominisat cadical espresso
CI_SOLVERS        := scip glpk espresso cadical cryptominisat
CI_SOLVERS_CSV     = $(shell echo "$(CI_SOLVERS)" | tr ' ' ',')
SOLVERS           :=
LONG              :=
EXIT_FIRST        := 1
LOGFILE           := test-$(shell date +%Y-%m-%d_%H-%M-%S).log
TEST_OUT_DIR      := tests-$(shell date +%Y-%m-%d_%H-%M-%S)

DISABLED          = $(filter-out $(SOLVERS),$(ALL_OPTIONALS))
DISABLE_FLAGS     = $(foreach s,$(DISABLED),CIVERLY_DISABLE_$(shell echo $(s) | tr a-z A-Z)=1)
SOLVERS_CSV       = $(shell echo "$(SOLVERS)" | tr ' ' ',')
OPTIONAL_FLAG     = --optional=sage$(if $(SOLVERS_CSV),$(addprefix ,,$(SOLVERS_CSV)),)
LONG_FLAG         = $(if $(filter 1,$(LONG)),--long,)
EXIT_FIRST_FLAG   = $(if $(filter 1,$(EXIT_FIRST)),--exitfirst,)

test:
	$(NIX_OR_NOTHING) env $(DISABLE_FLAGS) $(SAGE) $(SAGE_FLAGS) $(EXIT_FIRST_FLAG) --logfile=$(LOGFILE) $(OPTIONAL_FLAG) $(LONG_FLAG) $(TEST_DIR)

test-ci: SOLVERS = $(CI_SOLVERS)
test-ci: LONG = 1
test-ci: NTHREADS = 2
test-ci: EXIT_FIRST = 1
test-ci:
	$(NIX_OR_NOTHING) env $(DISABLE_FLAGS) $(SAGE) $(SAGE_FLAGS) $(EXIT_FIRST_FLAG) --logfile=$(LOGFILE) $(OPTIONAL_FLAG) $(LONG_FLAG) $(TEST_DIR)
	$(NIX_OR_NOTHING) env $(DISABLE_FLAGS) $(SAGE) $(SAGE_FLAGS) $(EXIT_FIRST_FLAG) --logfile=$(LOGFILE) $(OPTIONAL_FLAG) $(LONG_FLAG) docs

test-docs: SOLVERS = $(CI_SOLVERS)
test-docs:
	$(NIX_OR_NOTHING) env $(DISABLE_FLAGS) $(SAGE) $(SAGE_FLAGS) $(EXIT_FIRST_FLAG) --logfile=$(LOGFILE) $(OPTIONAL_FLAG) $(LONG_FLAG) docs

test-dir:
	mkdir -p $(TEST_OUT_DIR)

test-extensive: EXIT_FIRST = 0
test-extensive: test-dir
	$(NIX_OR_NOTHING) env $(foreach s,$(ALL_OPTIONALS),CIVERLY_DISABLE_$(shell echo $(s) | tr a-z A-Z)=1) \
		$(SAGE) $(SAGE_FLAGS) --logfile=$(TEST_OUT_DIR)/no-solvers.log --optional=sage $(TEST_DIR)
	$(foreach s,$(CI_SOLVERS), \
		$(NIX_OR_NOTHING) env $(foreach d,$(filter-out $(s),$(ALL_OPTIONALS)),CIVERLY_DISABLE_$(shell echo $(d) | tr a-z A-Z)=1) \
		$(SAGE) $(SAGE_FLAGS) --logfile=$(TEST_OUT_DIR)/$(s).log --optional=sage,$(s) $(TEST_DIR) ;)
	$(NIX_OR_NOTHING) env CIVERLY_DISABLE_GUROBI=1 \
		$(SAGE) $(SAGE_FLAGS) --logfile=$(TEST_OUT_DIR)/all-solvers.log --optional=sage,$(CI_SOLVERS_CSV) $(TEST_DIR)
	$(NIX_OR_NOTHING) env $(foreach s,$(ALL_OPTIONALS),CIVERLY_DISABLE_$(shell echo $(s) | tr a-z A-Z)=1) \
		$(SAGE) $(SAGE_FLAGS) --logfile=$(TEST_OUT_DIR)/no-solvers-long.log --optional=sage --long $(TEST_DIR)
	$(foreach s,$(CI_SOLVERS), \
		$(NIX_OR_NOTHING) env $(foreach d,$(filter-out $(s),$(ALL_OPTIONALS)),CIVERLY_DISABLE_$(shell echo $(d) | tr a-z A-Z)=1) \
		$(SAGE) $(SAGE_FLAGS) --logfile=$(TEST_OUT_DIR)/$(s)-long.log --optional=sage,$(s) --long $(TEST_DIR) ;)
	$(NIX_OR_NOTHING) env CIVERLY_DISABLE_GUROBI=1 \
		$(SAGE) $(SAGE_FLAGS) --logfile=$(TEST_OUT_DIR)/all-solvers-long.log --optional=sage,$(CI_SOLVERS_CSV) --long $(TEST_DIR)
