
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
	$(TARGET) -d tests/saitcza.so_dump_0x76c8436000.so 0x76c8436000 tests/generated.so

fix: tests/generated.so

tests/generated.readelf: fix
	@readelf --all tests/generated.so 2> tests/generated.readelf 1> tests/generated.readelf

test: tests/generated.readelf

baseline:
	@readelf --all tests/saitcza.so

clean:
	@rm -rf $(DIST_DIR)

