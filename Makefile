
GO ?= go
SRC_DIR ?= .
DIST_DIR ?= dist
SRC_FILE ?= cmd/main.go
TARGET ?= $(DIST_DIR)/gosofix

all: $(TARGET)

$(TARGET): $(SRC_FILE)
	@mkdir -p $(DIST_DIR)
	$(GO) build -buildmode c-shared -o $(TARGET) $(SRC_FILE)

clean:
	@rm -rf $(DIST_DIR)

