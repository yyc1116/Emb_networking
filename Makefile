TARGET := netmon
TEST_TARGET := tests/parser_synthetic
TEST_BUILD_TARGET := test-parser-build
DISPLAY_TEST_TARGET := tests/display_synthetic

SRC := \
	src/main.c \
	src/capture.c \
	src/parser.c \
	src/logger.c \
	src/rules.c \
	src/scan_detector.c \
	src/gpio_led.c \
	src/display.c \
	src/tm1637.c

OBJ := $(SRC:.c=.o)
TEST_SRC := tests/parser_synthetic.c src/parser.c
DISPLAY_TEST_SRC := tests/display_synthetic.c src/display.c src/tm1637.c src/scan_detector.c src/rules.c src/parser.c
DEP := $(OBJ:.o=.d)

ifeq ($(origin CC), default)
CC = gcc
endif
CPPFLAGS ?=
CPPFLAGS += -Iinclude
CPPFLAGS += -D_DEFAULT_SOURCE
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic -std=c11
CFLAGS += -pthread
LDFLAGS ?=
LDFLAGS += -pthread
LDLIBS += -lpcap
ENABLE_GPIO ?= 0

ifeq ($(ENABLE_GPIO),1)
CPPFLAGS += -DENABLE_GPIO=1
LDLIBS += -lgpiod
DISPLAY_TEST_LIBS += -lgpiod
endif

.PHONY: all clean test-parser test-parser-build test-display test-display-build

all: $(TARGET)

test-parser: $(TEST_TARGET)
	./$(TEST_TARGET)

test-parser-build: $(TEST_TARGET)

test-display: $(DISPLAY_TEST_TARGET)
	./$(DISPLAY_TEST_TARGET)

test-display-build: $(DISPLAY_TEST_TARGET)

$(TARGET): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ) $(LDLIBS)

$(TEST_TARGET): $(TEST_SRC) $(wildcard include/*.h)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(TEST_SRC)

$(DISPLAY_TEST_TARGET): $(DISPLAY_TEST_SRC) $(wildcard include/*.h)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wl,--wrap=time -Wl,--wrap=malloc -Wl,--wrap=calloc -o $@ $(DISPLAY_TEST_SRC) $(DISPLAY_TEST_LIBS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c -o $@ $<

-include $(DEP)

clean:
	$(RM) $(OBJ) $(DEP) $(TARGET) $(TEST_TARGET) $(DISPLAY_TEST_TARGET)
