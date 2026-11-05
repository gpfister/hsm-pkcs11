# ==============================================================================
# libgphsm Makefile
# PKCS#11 v2.40 Shared Library Provider Build Automation
# ==============================================================================

BUILD_DIR ?= build
CMAKE ?= cmake
CTEST ?= ctest

.PHONY: all build test clean debug

all: build

build:
	@mkdir -p $(BUILD_DIR)
	@$(CMAKE) -B $(BUILD_DIR) -S . -DCMAKE_BUILD_TYPE=Release
	@$(CMAKE) --build $(BUILD_DIR)

debug:
	@mkdir -p $(BUILD_DIR)
	@$(CMAKE) -B $(BUILD_DIR) -S . -DCMAKE_BUILD_TYPE=Debug
	@$(CMAKE) --build $(BUILD_DIR)

test: build
	@cd $(BUILD_DIR) && $(CTEST) --output-on-failure

clean:
	@rm -rf $(BUILD_DIR)
