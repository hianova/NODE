SHELL := /bin/sh
UNAME_S := $(shell uname -s)
FLOW_DIR ?= ../FLOW
INFO_DIR ?= ../INFO
BUILD := build
INFO_LIB := $(wildcard $(INFO_DIR)/build/libinfo.a)
ifneq ($(INFO_LIB),)
INFO_HOST_FLAGS := -isystem $(INFO_DIR)/include -isystem $(INFO_DIR)/build -DNODE_HAVE_INFO_CODEC=1
else
INFO_HOST_FLAGS :=
endif
LEAN ?= $(or $(shell command -v lean 2>/dev/null),$(HOME)/.elan/bin/lean)
LEANCHECKER ?= $(or $(shell command -v leanchecker 2>/dev/null),$(HOME)/.elan/bin/leanchecker)
AR ?= ar

ifeq ($(UNAME_S),Darwin)
LLVM_PREFIX ?= /opt/homebrew/opt/llvm/bin
LDFLAGS_STRIP := -Wl,-dead_strip
else
LLVM_PREFIX ?= /usr/bin
LDFLAGS_STRIP := -Wl,--gc-sections
endif
ifneq ($(wildcard $(LLVM_PREFIX)/clang),)
DEFAULT_CC := $(LLVM_PREFIX)/clang
DEFAULT_CXX := $(LLVM_PREFIX)/clang++
DEFAULT_FMT := $(LLVM_PREFIX)/clang-format
DEFAULT_TIDY := $(LLVM_PREFIX)/clang-tidy
else
DEFAULT_CC := clang
DEFAULT_CXX := clang++
DEFAULT_FMT := clang-format
DEFAULT_TIDY := clang-tidy
endif
ifeq ($(origin CC),default)
CC := $(DEFAULT_CC)
endif
ifeq ($(origin CXX),default)
CXX := $(DEFAULT_CXX)
endif
CLANG_FORMAT ?= $(DEFAULT_FMT)
CLANG_TIDY ?= $(DEFAULT_TIDY)

C17_RING0_FLAGS := -std=c17 -O2 -ffreestanding -nostdlib -fno-builtin -fno-stack-protector \
	-fno-jump-tables -mgeneral-regs-only -ffunction-sections -fdata-sections \
	-Wall -Wextra -Werror -Wpedantic -Wconversion -Wundef -Wmissing-prototypes
C17_HOST_FLAGS := -std=c17 -O2 -ffunction-sections -fdata-sections \
	-Wall -Wextra -Werror -Wpedantic -Wconversion -Wundef -Wmissing-prototypes
INC_RING0 := -Iinclude -I$(BUILD) -isystem $(FLOW_DIR)/core -isystem $(FLOW_DIR)/sdk
INC_HOST := -Iinclude -I$(BUILD) -isystem $(FLOW_DIR)/core -isystem $(FLOW_DIR)/sdk $(INFO_HOST_FLAGS)

C_SOURCES := include/node.h src/node_ring0.c src/node_cert.h src/node_net_udp.h src/node_disk_wal.h src/node_cli.c

.PHONY: all clean fmt verify-all verify experiments \
	gate0-lean-theory gate1-lean-schema gate2-ring0-audit gate3-selftest \
	gate4-cli-audit gate5-oracle gate6-sabotage gate7-format gate8-auditor

all: $(BUILD)/libnode.a $(BUILD)/node

$(BUILD)/lean/Node/Sandbox.olean: Node/Sandbox.lean
	@mkdir -p $(dir $@)
	$(LEAN) -DwarningAsError=true --root=. -o $@ $<

$(BUILD)/lean/Node/Dbsp.olean: Node/Dbsp.lean
	@mkdir -p $(dir $@)
	$(LEAN) -DwarningAsError=true --root=. -o $@ $<

$(BUILD)/lean/Node/Consensus.olean: Node/Consensus.lean
	@mkdir -p $(dir $@)
	$(LEAN) -DwarningAsError=true --root=. -o $@ $<

$(BUILD)/lean/Node/Dst.olean: Node/Dst.lean $(BUILD)/lean/Node/Consensus.olean
	@mkdir -p $(dir $@)
	LEAN_PATH=$(BUILD)/lean $(LEAN) -DwarningAsError=true --root=. -o $@ $<

$(BUILD)/lean/Node/Theory.olean: Node/Theory.lean \
		$(BUILD)/lean/Node/Sandbox.olean \
		$(BUILD)/lean/Node/Dbsp.olean \
		$(BUILD)/lean/Node/Consensus.olean \
		$(BUILD)/lean/Node/Dst.olean
	@mkdir -p $(dir $@)
	LEAN_PATH=$(BUILD)/lean $(LEAN) -DwarningAsError=true --root=. -o $@ $<

$(BUILD)/lean/Node.olean: Node.lean
	@mkdir -p $(dir $@)
	LEAN_PATH=$(BUILD)/lean:$(FLOW_DIR)/build/lean $(LEAN) -DwarningAsError=true --root=. -o $@ $<

$(BUILD)/node_schema_abi.h: $(BUILD)/lean/Node.olean
	@mkdir -p $(BUILD)
	LEAN_PATH=$(BUILD)/lean:$(FLOW_DIR)/build/lean $(LEAN) --run Node.lean emit-schema $@

$(BUILD)/node_ring0.o: src/node_ring0.c include/node.h $(BUILD)/node_schema_abi.h
	@mkdir -p $(BUILD)
	$(CC) $(C17_RING0_FLAGS) $(INC_RING0) -c $< -o $@

$(BUILD)/libnode.a: $(BUILD)/node_ring0.o
	$(AR) rcs $@ $<

$(BUILD)/node: $(BUILD)/node_ring0.o src/node_cli.c src/node_cert.h src/node_net_udp.h src/node_disk_wal.h include/node.h $(BUILD)/node_schema_abi.h $(INFO_LIB)
	$(CC) $(C17_HOST_FLAGS) $(INC_HOST) $(LDFLAGS_STRIP) $(BUILD)/node_ring0.o src/node_cli.c $(INFO_LIB) -o $@

gate0-lean-theory: $(BUILD)/lean/Node/Theory.olean
	@echo "[Gate 0] Checking 4 pure-theory pillars via leanchecker and axiom audit..."
	@if grep -qiE '\bsorry\b' Node/Sandbox.lean Node/Dbsp.lean Node/Consensus.lean Node/Dst.lean Node/Theory.lean; then \
		echo "ERROR: sorry found in Node theory modules"; exit 1; \
	fi
	@for m in Node.Sandbox Node.Dbsp Node.Consensus Node.Dst Node.Theory; do \
		LEAN_PATH=$(BUILD)/lean $(LEANCHECKER) $$m || exit 1; \
	done
	@python3 -c 'import pathlib, re; mods=[("Node.Sandbox","Node/Sandbox.lean"),("Node.Dbsp","Node/Dbsp.lean"),("Node.Consensus","Node/Consensus.lean"),("Node.Dst","Node/Dst.lean")]; thms=[f"#print axioms {m}.{n}" for m,p in mods for n in re.findall(r"^theorem\s+(\S+)", pathlib.Path(p).read_text(encoding="utf-8"), re.M)]; assert len(thms)==84, f"Expected 84 theorems, got {len(thms)}"; pathlib.Path("$(BUILD)/node_axioms.in").write_text("import Node.Theory\n" + "\n".join(thms) + "\n", encoding="utf-8")'
	@LEAN_PATH=$(BUILD)/lean $(LEAN) --stdin < $(BUILD)/node_axioms.in > $(BUILD)/node_axioms.txt
	@if grep -qE 'sorryAx|Lean\.ofReduceBool|Lean\.trustCompiler' $(BUILD)/node_axioms.txt; then \
		echo "ERROR: forbidden axiom detected"; exit 1; \
	fi
	@echo "[Gate 0] PASS (Node.Theory 84 theorems, 0 sorryAx, 0 ofReduceBool, 0 trustCompiler)"

gate1-lean-schema: $(BUILD)/node_schema_abi.h
	@echo "[Gate 1] Auditing Node.lean pure schema config and generated ABI header..."
	@if grep -qE '^\s*(theorem|lemma|axiom)\s' Node.lean; then \
		echo "ERROR: theorems/lemmas/axioms not allowed in Node.lean"; exit 1; \
	fi
	LEAN_PATH=$(BUILD)/lean:$(FLOW_DIR)/build/lean $(LEANCHECKER) Node
	@if grep -q 'memcpy' $(BUILD)/node_schema_abi.h; then \
		echo "ERROR: memcpy found in generated ABI header"; exit 1; \
	fi
	@echo "[Gate 1] PASS (256-slot ABI 0 memcpy, leanchecker Node PASS)"

gate2-ring0-audit: $(BUILD)/node_ring0.o $(BUILD)/libnode.a
	@echo "[Gate 2] Auditing Ring-0 freestanding Pure-GPR object..."
	@test -z "$$(nm -u $(BUILD)/node_ring0.o)"
ifeq ($(UNAME_S),Darwin)
	@if otool -tV $(BUILD)/node_ring0.o | grep -qE '\b(udiv|sdiv|fdiv|fmul|fadd|fsub|blr|br)\b|v[0-9]+\.'; then \
		echo "ERROR: Forbidden instruction or vector register in node_ring0.o"; exit 1; \
	fi
else
	@if objdump -d $(BUILD)/node_ring0.o | grep -qE '\b(udiv|sdiv|fdiv|fmul|fadd|fsub|blr|br)\b|%?[xyz]mm[0-9]+|\bv[0-9]+\.'; then \
		echo "ERROR: Forbidden instruction or vector register in node_ring0.o"; exit 1; \
	fi
endif
	@echo '#include "node.h"' | $(CXX) -std=c++20 -x c++ -fsyntax-only -Wall -Wextra -Werror $(INC_RING0) -
	$(CLANG_TIDY) --header-filter='node\.h$$' --checks='clang-analyzer-*,bugprone-*,-bugprone-easily-swappable-parameters' \
		--warnings-as-errors='*' src/node_ring0.c -- -std=c17 $(INC_RING0)
	@echo "[Gate 2] PASS (0 undef symbols, Pure-GPR clean, C++20 clean, clang-tidy 0 warnings)"

gate3-selftest: $(BUILD)/node
	@echo "[Gate 3] Running built-in 18-suite Ring-0 + cert + UDP/Disk selftest..."
	./$(BUILD)/node selftest
	@echo "[Gate 3] PASS"

gate4-cli-audit: $(BUILD)/node
	@echo "[Gate 4] Auditing CLI linkage (0 leanshared, 0 heap allocators)..."
	@if [ "$(UNAME_S)" = "Darwin" ]; then \
		if otool -L $(BUILD)/node | grep -qi 'leanshared'; then echo "ERROR: leanshared linked in $(BUILD)/node"; exit 1; fi; \
	else \
		if ldd $(BUILD)/node | grep -qi 'leanshared'; then echo "ERROR: leanshared linked in $(BUILD)/node"; exit 1; fi; \
	fi
	@if nm -u $(BUILD)/node | grep -qE '[[:space:]]_?(malloc|free|calloc|realloc)([[:space:]@]|$$)'; then \
		echo "ERROR: heap allocator symbol linked in $(BUILD)/node"; exit 1; \
	fi
	@echo "[Gate 4] PASS (build/node clean, size=$$(wc -c < $(BUILD)/node | tr -d ' ') B)"

gate5-oracle: gate0-lean-theory gate1-lean-schema gate4-cli-audit
	@echo "[Gate 5] Running independent pure-Python exact oracle + live Lean cert replay..."
	python3 oracles/verify_node_oracle.py
	@echo "[Gate 5] PASS"

gate6-sabotage: gate1-lean-schema
	@echo "[Gate 6] Running 36-mutant single-fault sabotage gate..."
	python3 tools/node_sabotage_check.py
	@echo "[Gate 6] PASS"

gate7-format:
	@echo "[Gate 7] Verifying clang-format compliance..."
	$(CLANG_FORMAT) --dry-run --Werror $(C_SOURCES)
	@echo "[Gate 7] PASS"

gate8-auditor: $(BUILD)/node $(BUILD)/node_ring0.o
	@echo "[Gate 8] Running ../Auditor LLVM IR CT + Z3 QF_BV + Net MAC replay audit..."
	CC=$(CC) python3 tools/node_auditor_check.py

experiments: $(BUILD)/node
	@echo "[Experiments] Running Layer 1-3 Trinity Benchmarks..."
	python3 experiments/node_trinity_benchmark.py
	@echo "[Experiments] PASS"

verify-all: gate0-lean-theory gate1-lean-schema gate2-ring0-audit gate3-selftest \
	gate4-cli-audit gate5-oracle gate6-sabotage gate7-format gate8-auditor
	@echo "================================================================"
	@echo "NODE v1.0.0 — ALL 9 VERIFICATION GATES PASSED"
	@echo "================================================================"

verify: verify-all

fmt:
	$(CLANG_FORMAT) -i $(C_SOURCES)

clean:
	rm -rf $(BUILD)
