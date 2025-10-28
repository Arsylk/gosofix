
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
	@echo Running on test elf dumps...
	@rm -rf test/
	@cp -r tests/ test/
	for file in test/*.so; do \
		$(TARGET) -d $$file $$(basename $$file | cut -d'_' -f 2 | sed 's/\.so//'); \
	done

clean:
	@rm -rf $(DIST_DIR)

