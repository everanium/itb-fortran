# Makefile -- build the ITB Fortran binding sources, test programs,
# bench binaries, and the eitb CLI.
#
# Targets:
#   all (default): compile every src/*.f90 module into build/.
#   src:           same as `all`.
#   tests:         compile every tests/test_*.f90 into a standalone
#                  binary under tests/build/, linked against the src
#                  object tree + libitb.so.
#   bench:         compile bench/bench_{message,stream,stream_one_shot}.f90
#                  into bench/bin/.
#   eitb:          compile the eitb CLI at eitb/eitb.
#   clean:         remove every generated artefact.
#   help:          list targets.
#
# Variables (override on the command line or env):
#   FC           Fortran compiler        (default: gfortran)
#   FCFLAGS      Compiler-side flags     (default below)
#   LIBITB_DIR   path to libitb.so dir   (default: ../../dist/linux-amd64)
#   BUILD_DIR    .mod / .o output root   (default: build)
#
# Fortran module builds are order-sensitive: every `use`d module's
# .mod file must exist before the dependent source compiles, so the
# src-side dependency chain is hand-coded below. Keep it in sync when
# adding modules.

# `FC` arrives pre-bound to `f77` via POSIX make's default rules; the
# `?=` form does not override that. Detect the default-binding case
# and replace it with `gfortran` unless the user has explicitly
# overridden FC on the command line / env.
ifeq ($(origin FC),default)
  FC = gfortran
endif
LIBITB_DIR ?= ../../dist/linux-amd64
FCFLAGS    ?= -std=f2008 -Wall -Wextra -Werror -pedantic -O3 -funroll-loops
BUILD_DIR  ?= build
MOD_FLAG    = -J $(BUILD_DIR)

TESTS_BUILD = tests/build
BENCH_BUILD = bench/build
BENCH_BIN   = bench/bin
EITB_BUILD  = eitb/build

RPATH   = $(abspath $(LIBITB_DIR))
LDFLAGS = -L$(LIBITB_DIR) -litb -Wl,-rpath,$(RPATH)

# Source-side declaration order. Module dependencies are linear:
# status / ffi / opts -> error -> runtime -> pipeline -> stream ->
# itb (root re-export). The list is in compile order so every
# dependent module has its prerequisite .mod already on disk when
# the compiler reaches it.
SRC_FILES = \
    src/itb_status.f90    \
    src/itb_ffi.f90       \
    src/itb_opts.f90      \
    src/itb_error.f90     \
    src/itb_runtime.f90   \
    src/itb_pipeline.f90  \
    src/itb_stream.f90    \
    src/itb.f90

SRC_OBJS = $(patsubst src/%.f90,$(BUILD_DIR)/%.o,$(SRC_FILES))

TEST_SRCS = $(wildcard tests/test_*.f90)
TEST_BINS = $(patsubst tests/test_%.f90,$(TESTS_BUILD)/test_%,$(TEST_SRCS))

HELPER_SRC = tests/itb_test_helpers.f90
HELPER_OBJ = $(TESTS_BUILD)/itb_test_helpers.o

.PHONY: all src tests bench eitb clean help
all: src
src: $(SRC_OBJS)
tests: src $(HELPER_OBJ) $(TEST_BINS)
bench: src $(BENCH_BIN)/bench_message $(BENCH_BIN)/bench_stream \
       $(BENCH_BIN)/bench_stream_one_shot
eitb: src eitb/eitb

# Pattern rule: src/%.f90 -> build/%.o + build/%.mod. Module files
# land alongside the object files in $(BUILD_DIR).
$(BUILD_DIR)/%.o: src/%.f90 | $(BUILD_DIR)
	$(FC) $(FCFLAGS) $(MOD_FLAG) -I$(BUILD_DIR) -c $< -o $@

# Hand-coded module dependencies: each module imports the .mod files
# of its prerequisites and so cannot compile until they exist.
$(BUILD_DIR)/itb_error.o:    $(BUILD_DIR)/itb_status.o $(BUILD_DIR)/itb_ffi.o
$(BUILD_DIR)/itb_runtime.o:  $(BUILD_DIR)/itb_status.o $(BUILD_DIR)/itb_ffi.o $(BUILD_DIR)/itb_error.o
$(BUILD_DIR)/itb_pipeline.o: $(BUILD_DIR)/itb_status.o $(BUILD_DIR)/itb_ffi.o $(BUILD_DIR)/itb_error.o $(BUILD_DIR)/itb_opts.o
$(BUILD_DIR)/itb_stream.o:   $(BUILD_DIR)/itb_status.o $(BUILD_DIR)/itb_ffi.o $(BUILD_DIR)/itb_error.o $(BUILD_DIR)/itb_pipeline.o
$(BUILD_DIR)/itb.o:          $(BUILD_DIR)/itb_status.o $(BUILD_DIR)/itb_error.o $(BUILD_DIR)/itb_opts.o $(BUILD_DIR)/itb_runtime.o $(BUILD_DIR)/itb_pipeline.o $(BUILD_DIR)/itb_stream.o

# Test helper module compiles into tests/build/.
$(HELPER_OBJ): $(HELPER_SRC) $(SRC_OBJS) | $(TESTS_BUILD)
	$(FC) $(FCFLAGS) -J $(TESTS_BUILD) -I$(BUILD_DIR) -c $< -o $@

# Per-test pattern rule. Each tests/test_*.f90 program depends on the
# full src object tree + the helper module. Linker pulls in libitb.so
# via -litb + the embedded RPATH.
$(TESTS_BUILD)/test_%: tests/test_%.f90 $(SRC_OBJS) $(HELPER_OBJ) | $(TESTS_BUILD)
	$(FC) $(FCFLAGS) -J $(TESTS_BUILD) -I$(BUILD_DIR) -I$(TESTS_BUILD) \
	      $< $(SRC_OBJS) $(HELPER_OBJ) -o $@ $(LDFLAGS)

# ----- Bench binaries -------------------------------------------------

$(BENCH_BUILD)/bench_common.o: bench/common.f90 $(SRC_OBJS) | $(BENCH_BUILD)
	$(FC) $(FCFLAGS) -J $(BENCH_BUILD) -I$(BUILD_DIR) -c $< -o $@

$(BENCH_BIN)/bench_%: bench/bench_%.f90 $(BENCH_BUILD)/bench_common.o $(SRC_OBJS) | $(BENCH_BIN)
	$(FC) $(FCFLAGS) -J $(BENCH_BUILD) -I$(BUILD_DIR) -I$(BENCH_BUILD) \
	      $< $(BENCH_BUILD)/bench_common.o $(SRC_OBJS) -o $@ $(LDFLAGS)

# ----- eitb CLI -------------------------------------------------------

eitb/eitb: eitb/eitb.f90 $(SRC_OBJS) | $(EITB_BUILD)
	$(FC) $(FCFLAGS) -J $(EITB_BUILD) -I$(BUILD_DIR) \
	      $< $(SRC_OBJS) -o $@ $(LDFLAGS)

# ----- Directory stamps -----------------------------------------------

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(TESTS_BUILD):
	mkdir -p $(TESTS_BUILD)

$(BENCH_BUILD):
	mkdir -p $(BENCH_BUILD)

$(BENCH_BIN):
	mkdir -p $(BENCH_BIN)

$(EITB_BUILD):
	mkdir -p $(EITB_BUILD)

clean:
	rm -rf $(BUILD_DIR) tests/build bench/build bench/bin eitb/build eitb/eitb

help:
	@echo "Targets:"
	@echo "  all (default) -- compile src/*.f90 into \$$(BUILD_DIR)/."
	@echo "  src           -- same as 'all'."
	@echo "  tests         -- src + every tests/test_*.f90 binary."
	@echo "  bench         -- src + bench/bin/bench_{message,stream,stream_one_shot}."
	@echo "  eitb          -- src + the eitb CLI at eitb/eitb."
	@echo "  clean         -- remove every generated artefact."
	@echo ""
	@echo "Variables (override via FC=... etc):"
	@echo "  FC          Fortran compiler [default: gfortran]"
	@echo "  FCFLAGS     Compiler flags   [default: -std=f2008 -Wall -Wextra -Werror -pedantic -O3 -funroll-loops]"
	@echo "  LIBITB_DIR  libitb.so dir    [default: ../../dist/linux-amd64]"
	@echo "  BUILD_DIR   .mod / .o output [default: build]"
