
GO ?= go
GOSOURCES=$(shell find . -name "*.go")
SRC_DIR ?= .
SRC_FILE ?= cmd/main.go
DIST_DIR ?= dist
TARGET ?= $(DIST_DIR)/gosofix

.PHONY: all baseline test clean force

all: force
	@$(MAKE) --no-print-directory $(TARGET)

force: ;

$(TARGET): $(GOSOURCES)
	@mkdir -p $(DIST_DIR)
	$(GO) build -o $(TARGET) $(SRC_FILE)
	@chmod +x $(TARGET)


tests/generated.so: $(TARGET)
	$(TARGET) -d tests/jiagu_0x6c7640a000.so 0x6c7640a000 tests/generated.so

fix: tests/generated.so

test: fix
	@readelf --all tests/generated.so

clean:
	@rm -rf $(DIST_DIR)

