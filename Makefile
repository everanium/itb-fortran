# Makefile -- build the ITB Fortran binding sources + test programs.
#
# Targets:
#   all (default): compile every src/*.f90 module into build/.
#   src:           same as `all`.
#   tests:         compile every tests/test_*.f90 into a standalone
#                  binary under tests/build/, linked against the src
#                  object tree + libitb.so.
#   clean:         remove build/ + tests/build/.
#   help:          list targets.
#
# Variables (override on the command line or env):
#   FC           Fortran compiler        (default: gfortran)
#   FCFLAGS      Compiler-side flags     (default depends on FC)
#   LIBITB_DIR   path to libitb.so dir   (default: ../../dist/linux-amd64)
#   BUILD_DIR    .mod / .o output root   (default: build)
#                When FC=ifx the default flips to build_ifx so each
#                compiler keeps its own .mod cache without collisions.
#
# Compilers known to build cleanly: gfortran (default), ifx (Intel
# oneAPI). Both compile against libitb.so via -I <build_dir> for
# module imports, -L <libitb-dir> -litb for the FFI link, and
# -Wl,-rpath,<libitb-dir> so the runtime loader finds libitb.so
# without LD_LIBRARY_PATH.

# `FC` arrives pre-bound to `f77` via POSIX make's default rules; the
# `?=` form does not override that. Detect the default-binding case
# and replace it with `gfortran` (the project default) unless the
# user has explicitly overridden FC on the command line / env.
ifeq ($(origin FC),default)
  FC = gfortran
endif
LIBITB_DIR  ?= ../../dist/linux-amd64

# Compiler-specific flag sets. Intel ifx uses -module to control
# .mod output dir; gfortran uses -J. Warning + standard switches
# differ between the two so the conventional set is branched here.
ifeq ($(FC),ifx)
  FCFLAGS    ?= -warn all -stand f18 -O2
  BUILD_DIR  ?= build_ifx
  MOD_FLAG    = -module $(BUILD_DIR)
  TEST_MOD    = -module $(TESTS_BUILD)
  # ifx places auto-reallocation temporaries and fixed-shape array
  # locals on the stack by default; with the bench's 16 MiB payload
  # this overflows the default 8 MiB stack on most Linux systems.
  # Force every array temporary to the heap so the bench runs on a
  # pristine ulimit -- only applied to the bench targets, the test
  # binaries operate on small payloads and do not need it.
  BENCH_FCFLAGS = $(FCFLAGS) -heap-arrays 0
else
  FCFLAGS    ?= -Wall -Wextra -Wpedantic -std=f2018 -O2
  BUILD_DIR  ?= build
  MOD_FLAG    = -J $(BUILD_DIR)
  TEST_MOD    = -J $(TESTS_BUILD)
  BENCH_FCFLAGS = $(FCFLAGS)
endif

TESTS_BUILD = tests/build

# Bench-binary build tree (object / .mod cache) and final-binary
# directory. The build tree mirrors gfortran / ifx parallel split so
# the two compilers do not share .mod files; the final binaries land
# under bench/bin/ regardless of compiler since only one compiler's
# bench binaries are needed at any time.
ifeq ($(FC),ifx)
  BENCH_BUILD = bench/build_ifx
else
  BENCH_BUILD = bench/build
endif
BENCH_BIN   = bench/bin
BENCH_MOD   = $(if $(filter ifx,$(FC)),-module $(BENCH_BUILD),-J $(BENCH_BUILD))

LDFLAGS = -L$(LIBITB_DIR) -litb -Wl,-rpath,$(LIBITB_DIR)

# Source-side declaration order. Module dependencies are linear:
# kinds -> sys / strings -> errors -> library / mac / seed -> cipher
# / encryptor -> blob -> streams. The list is in compile order so
# every dependent module has its prerequisite .mod already on disk
# when the compiler reaches it.
SRC_FILES = \
    src/itb_kinds.f90      \
    src/itb_sys.f90        \
    src/itb_strings.f90    \
    src/itb_errors.f90     \
    src/itb_library.f90    \
    src/itb_mac.f90        \
    src/itb_seed.f90       \
    src/itb_cipher.f90     \
    src/itb_encryptor.f90  \
    src/itb_blob.f90       \
    src/itb_streams.f90

SRC_OBJS = $(patsubst src/%.f90,$(BUILD_DIR)/%.o,$(SRC_FILES))

# Test source list discovered at parse time. Each tests/test_*.f90
# produces one tests/build/test_* binary linked against the src
# object tree, the helper module, and libitb.so.
TEST_SRCS = $(wildcard tests/test_*.f90)
TEST_BINS = $(patsubst tests/test_%.f90,$(TESTS_BUILD)/test_%,$(TEST_SRCS))

HELPER_SRC = tests/itb_test_helpers.f90
HELPER_OBJ = $(TESTS_BUILD)/itb_test_helpers.o

.PHONY: all src tests bench bench-clean clean help
all: src
src: $(SRC_OBJS)
tests: src $(HELPER_OBJ) $(TEST_BINS)
bench: src $(BENCH_BIN)/itb-bench-single $(BENCH_BIN)/itb-bench-triple \
              $(BENCH_BIN)/itb-bench-single-stream $(BENCH_BIN)/itb-bench-triple-stream

# Pattern rule: src/%.f90 -> build/%.o + build/%.mod. Module files
# land alongside the object files in $(BUILD_DIR).
$(BUILD_DIR)/%.o: src/%.f90 | $(BUILD_DIR)
	$(FC) $(FCFLAGS) $(MOD_FLAG) -I$(BUILD_DIR) -c $< -o $@

# Source-side dependency hand-coded; let make sequence the build
# correctly without relying on file mtime alone. Each module imports
# the .mod files of its prerequisites and so cannot compile until
# they exist.
$(BUILD_DIR)/itb_sys.o:        $(BUILD_DIR)/itb_kinds.o
$(BUILD_DIR)/itb_strings.o:    $(BUILD_DIR)/itb_kinds.o
$(BUILD_DIR)/itb_errors.o:     $(BUILD_DIR)/itb_kinds.o $(BUILD_DIR)/itb_sys.o $(BUILD_DIR)/itb_strings.o
$(BUILD_DIR)/itb_library.o:    $(BUILD_DIR)/itb_kinds.o $(BUILD_DIR)/itb_sys.o $(BUILD_DIR)/itb_strings.o $(BUILD_DIR)/itb_errors.o
$(BUILD_DIR)/itb_mac.o:        $(BUILD_DIR)/itb_kinds.o $(BUILD_DIR)/itb_sys.o $(BUILD_DIR)/itb_strings.o $(BUILD_DIR)/itb_errors.o
$(BUILD_DIR)/itb_seed.o:       $(BUILD_DIR)/itb_kinds.o $(BUILD_DIR)/itb_sys.o $(BUILD_DIR)/itb_strings.o $(BUILD_DIR)/itb_errors.o
$(BUILD_DIR)/itb_cipher.o:     $(BUILD_DIR)/itb_kinds.o $(BUILD_DIR)/itb_sys.o $(BUILD_DIR)/itb_seed.o $(BUILD_DIR)/itb_mac.o $(BUILD_DIR)/itb_errors.o
$(BUILD_DIR)/itb_encryptor.o:  $(BUILD_DIR)/itb_kinds.o $(BUILD_DIR)/itb_sys.o $(BUILD_DIR)/itb_strings.o $(BUILD_DIR)/itb_errors.o
$(BUILD_DIR)/itb_blob.o:       $(BUILD_DIR)/itb_kinds.o $(BUILD_DIR)/itb_sys.o $(BUILD_DIR)/itb_strings.o $(BUILD_DIR)/itb_errors.o
$(BUILD_DIR)/itb_streams.o:    $(BUILD_DIR)/itb_kinds.o $(BUILD_DIR)/itb_sys.o $(BUILD_DIR)/itb_seed.o $(BUILD_DIR)/itb_mac.o $(BUILD_DIR)/itb_cipher.o $(BUILD_DIR)/itb_errors.o $(BUILD_DIR)/itb_library.o

# Test helper module compiles into tests/build/. It depends only on
# itb_kinds + itb_errors from the src tree.
$(HELPER_OBJ): $(HELPER_SRC) $(BUILD_DIR)/itb_kinds.o $(BUILD_DIR)/itb_errors.o | $(TESTS_BUILD)
	$(FC) $(FCFLAGS) $(TEST_MOD) -I$(BUILD_DIR) -c $< -o $@

# Per-test pattern rule. Each tests/test_*.f90 program depends on the
# full src object tree + the helper module. Linker pulls in libitb.so
# via -litb + the embedded RPATH.
$(TESTS_BUILD)/test_%: tests/test_%.f90 $(SRC_OBJS) $(HELPER_OBJ) | $(TESTS_BUILD)
	$(FC) $(FCFLAGS) $(TEST_MOD) -I$(BUILD_DIR) -I$(TESTS_BUILD) \
	      $< $(SRC_OBJS) $(HELPER_OBJ) -o $@ $(LDFLAGS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(TESTS_BUILD):
	mkdir -p $(TESTS_BUILD)

# ----- Bench binaries -------------------------------------------------

# Bench-side shared module: compiled into $(BENCH_BUILD)/ alongside
# the per-binary .mod / .o artefacts.
$(BENCH_BUILD)/bench_common.o: bench/bench_common.f90 | $(BENCH_BUILD)
	$(FC) $(BENCH_FCFLAGS) $(BENCH_MOD) -I$(BUILD_DIR) -c $< -o $@

# Per-binary main + state module compile in one shot. The state
# module lives in the same source file as the program unit, which is
# legal Fortran but keeps the bench source self-contained.
$(BENCH_BUILD)/bench_single.o: bench/bench_single.f90                                    \
                                $(BENCH_BUILD)/bench_common.o $(SRC_OBJS) | $(BENCH_BUILD)
	$(FC) $(BENCH_FCFLAGS) $(BENCH_MOD) -I$(BUILD_DIR) -I$(BENCH_BUILD) -c $< -o $@

$(BENCH_BUILD)/bench_triple.o: bench/bench_triple.f90                                    \
                                $(BENCH_BUILD)/bench_common.o $(SRC_OBJS) | $(BENCH_BUILD)
	$(FC) $(BENCH_FCFLAGS) $(BENCH_MOD) -I$(BUILD_DIR) -I$(BENCH_BUILD) -c $< -o $@

$(BENCH_BIN)/itb-bench-single: $(BENCH_BUILD)/bench_single.o                              \
                                $(BENCH_BUILD)/bench_common.o $(SRC_OBJS) | $(BENCH_BIN)
	$(FC) $(BENCH_FCFLAGS) $(BENCH_MOD) -I$(BUILD_DIR) -I$(BENCH_BUILD)                 \
	      $(BENCH_BUILD)/bench_single.o $(BENCH_BUILD)/bench_common.o                   \
	      $(SRC_OBJS) -o $@ $(LDFLAGS)

$(BENCH_BIN)/itb-bench-triple: $(BENCH_BUILD)/bench_triple.o                              \
                                $(BENCH_BUILD)/bench_common.o $(SRC_OBJS) | $(BENCH_BIN)
	$(FC) $(BENCH_FCFLAGS) $(BENCH_MOD) -I$(BUILD_DIR) -I$(BENCH_BUILD)                 \
	      $(BENCH_BUILD)/bench_triple.o $(BENCH_BUILD)/bench_common.o                   \
	      $(SRC_OBJS) -o $@ $(LDFLAGS)

# Streaming-AEAD bench binaries. Each compiles its own state +
# in-memory I/O modules in the same source unit, mirroring the plain
# bench_single / bench_triple object pattern.
$(BENCH_BUILD)/bench_single_stream.o: bench/bench_single_stream.f90                        \
                                $(BENCH_BUILD)/bench_common.o $(SRC_OBJS) | $(BENCH_BUILD)
	$(FC) $(BENCH_FCFLAGS) $(BENCH_MOD) -I$(BUILD_DIR) -I$(BENCH_BUILD) -c $< -o $@

$(BENCH_BUILD)/bench_triple_stream.o: bench/bench_triple_stream.f90                        \
                                $(BENCH_BUILD)/bench_common.o $(SRC_OBJS) | $(BENCH_BUILD)
	$(FC) $(BENCH_FCFLAGS) $(BENCH_MOD) -I$(BUILD_DIR) -I$(BENCH_BUILD) -c $< -o $@

$(BENCH_BIN)/itb-bench-single-stream: $(BENCH_BUILD)/bench_single_stream.o                  \
                                $(BENCH_BUILD)/bench_common.o $(SRC_OBJS) | $(BENCH_BIN)
	$(FC) $(BENCH_FCFLAGS) $(BENCH_MOD) -I$(BUILD_DIR) -I$(BENCH_BUILD)                 \
	      $(BENCH_BUILD)/bench_single_stream.o $(BENCH_BUILD)/bench_common.o            \
	      $(SRC_OBJS) -o $@ $(LDFLAGS)

$(BENCH_BIN)/itb-bench-triple-stream: $(BENCH_BUILD)/bench_triple_stream.o                  \
                                $(BENCH_BUILD)/bench_common.o $(SRC_OBJS) | $(BENCH_BIN)
	$(FC) $(BENCH_FCFLAGS) $(BENCH_MOD) -I$(BUILD_DIR) -I$(BENCH_BUILD)                 \
	      $(BENCH_BUILD)/bench_triple_stream.o $(BENCH_BUILD)/bench_common.o            \
	      $(SRC_OBJS) -o $@ $(LDFLAGS)

$(BENCH_BUILD):
	mkdir -p $(BENCH_BUILD)

$(BENCH_BIN):
	mkdir -p $(BENCH_BIN)

bench-clean:
	rm -rf bench/build bench/build_ifx bench/bin

clean:
	rm -rf build build_ifx tests/build

help:
	@echo "Targets:"
	@echo "  all (default) -- compile src/*.f90 into \$$(BUILD_DIR)/."
	@echo "  src           -- same as 'all'."
	@echo "  tests         -- src + every tests/test_*.f90 binary."
	@echo "  bench         -- src + bench/bin/itb-bench-{single,triple}."
	@echo "  bench-clean   -- remove bench/build* + bench/bin/."
	@echo "  clean         -- remove build/ + build_ifx/ + tests/build/."
	@echo "  help          -- this message."
	@echo ""
	@echo "Variables (override via FC=... etc):"
	@echo "  FC          Fortran compiler [default: gfortran; supports ifx]"
	@echo "  FCFLAGS     Compiler flags   [default per-compiler]"
	@echo "  LIBITB_DIR  libitb.so dir    [default: ../../dist/linux-amd64]"
	@echo "  BUILD_DIR   .mod / .o output [default: build or build_ifx]"
