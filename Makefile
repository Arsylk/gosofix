
GO ?= go
GOSOURCES=$(shell find . -name "*.go")
SRC_DIR ?= .
SRC_FILE ?= cmd/main.go
DIST_DIR ?= dist
TARGET ?= $(DIST_DIR)/gosofix

.PHONY: all test clean

all: $(TARGET)

$(TARGET): $(GOSOURCES)
	@mkdir -p $(DIST_DIR)
	$(GO) build -o $(TARGET) $(SRC_FILE)
	@chmod +x $(TARGET)


test: all
	$(TARGET) tests/libdexprotector.so_dump_0x6ddc6d8000.so 0x6ddc6d8000

clean:
	@rm -rf $(DIST_DIR)

