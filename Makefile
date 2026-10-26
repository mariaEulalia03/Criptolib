CC ?= gcc
AR ?= ar
CFLAGS ?= -Wall -Wextra -O2 -Iinclude
LDFLAGS ?=

BUILD_DIR = build
SRC_DIR = src
TEST_DIR = tests
INC_DIR = include

SRCS = $(SRC_DIR)/bigint.c $(SRC_DIR)/sha256.c $(SRC_DIR)/ecdsa.c
OBJS = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRCS))
LIB = $(BUILD_DIR)/libcrypt.a
TEST_BIN = $(BUILD_DIR)/test_ecdsa
CLI_BIN = $(BUILD_DIR)/ecdsa_cli

.PHONY: all clean test run cli

all: $(LIB) $(TEST_BIN) $(CLI_BIN)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(LIB): $(OBJS) | $(BUILD_DIR)
	$(AR) rcs $@ $^

$(BUILD_DIR)/test_ecdsa.o: $(TEST_DIR)/test_ecdsa.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(TEST_BIN): $(BUILD_DIR)/test_ecdsa.o $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -L$(BUILD_DIR) -lcrypt $(LDFLAGS) -o $@

$(BUILD_DIR)/cli.o: $(SRC_DIR)/cli.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(CLI_BIN): $(BUILD_DIR)/cli.o $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -L$(BUILD_DIR) -lcrypt $(LDFLAGS) -o $@

test: $(TEST_BIN)

run: $(TEST_BIN)
	./$(TEST_BIN)

cli: $(CLI_BIN)

clean:
	rm -rf $(BUILD_DIR)
