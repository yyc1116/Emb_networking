TARGET := netmon
TEST_TARGET := tests/parser_synthetic

SRC := \
	src/main.c \
	src/capture.c \
	src/parser.c \
	src/logger.c \
	src/rules.c \
	src/scan_detector.c \
	src/gpio_led.c

OBJ := $(SRC:.c=.o)
TEST_SRC := tests/parser_synthetic.c src/parser.c

ifeq ($(origin CC), default)
CC = gcc
endif
CPPFLAGS ?=
CPPFLAGS += -Iinclude
CPPFLAGS += -D_DEFAULT_SOURCE
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic -std=c11
LDFLAGS ?=
LDLIBS += -lpcap
ENABLE_GPIO ?= 0

ifeq ($(ENABLE_GPIO),1)
CPPFLAGS += -DENABLE_GPIO=1
CFLAGS += -pthread
LDFLAGS += -pthread
LDLIBS += -lgpiod
endif

.PHONY: all clean test-parser

all: $(TARGET)

test-parser: $(TEST_TARGET)

$(TARGET): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ) $(LDLIBS)

$(TEST_TARGET): $(TEST_SRC)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(TEST_SRC)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

clean:
	$(RM) $(OBJ) $(TARGET) $(TEST_TARGET)
