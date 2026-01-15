# Go build parameters
GO := go

# Single polyglot binary - works as both executable AND shared library
TARGET := dist/gosofix
TARGET_H := dist/gosofix.h
SRC_DIR := cmd/main.go
CLI_ENTRY := cmd/cli_wrapper.c

# Intermediate build artifacts
BUILD_DIR := .build
ENTRY_OBJ := $(BUILD_DIR)/cli_entry.o

# Standard build targets
.PHONY: all clean install launch build

all: build

build: $(TARGET)

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR) dist

# Step 1: Compile the C entry point  
$(ENTRY_OBJ): $(CLI_ENTRY) | $(BUILD_DIR)
	@echo "Compiling entry point..."
	gcc -fPIC -c -o $(ENTRY_OBJ) $(CLI_ENTRY)

# Step 2: Build a single polyglot binary using Go c-shared with entry point linked in
$(TARGET): $(ENTRY_OBJ) $(SRC_DIR) $(wildcard pkg/*.go)
	@echo "Building polyglot binary: $(TARGET)"
	@mkdir -p dist
	CGO_LDFLAGS="-Wl,--export-dynamic" \
	$(GO) build -o $(TARGET) -buildmode=c-shared \
		-ldflags="-extldflags '/usr/lib/Scrt1.o $(CURDIR)/$(ENTRY_OBJ) -Wl,--export-dynamic'" \
		$(SRC_DIR)
	@mv dist/gosofix.h $(TARGET_H) 2>/dev/null || true
	@chmod +x $(TARGET)
	@echo ""
	@echo "Built single-file polyglot binary: $(TARGET)"
	@echo "  - Run as CLI:   ./$(TARGET) --version"
	@echo "  - Use as lib:   dlopen(\"./$(TARGET)\", RTLD_NOW)"

launch: build
	$(TARGET) -v 2 tests/libprexs.so_dump_0x79bd580000.so

# Install the tool
install: build
	@echo "Installing $(TARGET) to /usr/local/bin"
	@sudo install -m 755 $(TARGET) /usr/local/bin/gosofix
	@echo "Installing $(TARGET_H) to /usr/local/include"
	@sudo install -m 644 $(TARGET_H) /usr/local/include/gosofix.h

# Clean build artifacts
clean:
	@echo "Cleaning up build artifacts..."
	@rm -rf dist/ $(BUILD_DIR)/
