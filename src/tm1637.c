#include "tm1637.h"

#include <stdio.h>
#include <stdlib.h>

#if defined(ENABLE_GPIO)
#include <errno.h>
#include <gpiod.h>
#include <time.h>
#endif

struct Tm1637 {
    Tm1637Bus bus;
    unsigned int brightness;
#if defined(ENABLE_GPIO)
    struct gpiod_chip *chip;
    struct gpiod_line *clk;
    struct gpiod_line *dio;
    bool clk_requested;
    bool dio_requested;
#endif
};

static void delay(Tm1637 *display)
{
    /* Well below the chip's maximum clock rate; only called by the display worker. */
    display->bus.delay_us(display->bus.context, 10U);
}

static bool clk(Tm1637 *display, int value)
{
    if (display->bus.set_clk(display->bus.context, value) != 0) {
        return false;
    }
    delay(display);
    return true;
}

static bool dio(Tm1637 *display, int value)
{
    if (display->bus.set_dio(display->bus.context, value) != 0) {
        return false;
    }
    delay(display);
    return true;
}

static bool start(Tm1637 *display)
{
    return dio(display, 1) && clk(display, 1) && dio(display, 0) && clk(display, 0);
}

static bool stop(Tm1637 *display)
{
    /* Do not short-circuit cleanup: try to release both lines after an error. */
    bool ok = clk(display, 0);
    ok = dio(display, 0) && ok;
    ok = clk(display, 1) && ok;
    ok = dio(display, 1) && ok;
    return ok;
}

static bool write_byte(Tm1637 *display, uint8_t byte)
{
    unsigned int bit;
    int ack;

    for (bit = 0U; bit < 8U; ++bit) {
        if (!dio(display, (byte >> bit) & 1U) || !clk(display, 1) || !clk(display, 0)) {
            return false;
        }
    }
    if (!dio(display, 1) || !clk(display, 1)) {
        return false;
    }
    ack = display->bus.get_dio(display->bus.context);
    return clk(display, 0) && ack == 0;
}

static bool transaction(Tm1637 *display, const uint8_t *bytes, size_t count)
{
    size_t index;
    bool ok = start(display);

    for (index = 0U; ok && index < count; ++index) {
        ok = write_byte(display, bytes[index]);
    }
    return stop(display) && ok;
}

Tm1637 *tm1637_open_bus(const Tm1637Bus *bus, unsigned int brightness)
{
    Tm1637 *display;

    if (bus == NULL || bus->set_clk == NULL || bus->set_dio == NULL ||
        bus->get_dio == NULL || bus->delay_us == NULL || brightness > 7U) {
        return NULL;
    }
    display = calloc(1U, sizeof(*display));
    if (display != NULL) {
        display->bus = *bus;
        display->brightness = brightness;
    }
    return display;
}

#if defined(ENABLE_GPIO)
static int gpio_clk(void *context, int value)
{
    return gpiod_line_set_value(((Tm1637 *)context)->clk, value);
}

static int gpio_dio(void *context, int value)
{
    return gpiod_line_set_value(((Tm1637 *)context)->dio, value);
}

static int gpio_read(void *context)
{
    return gpiod_line_get_value(((Tm1637 *)context)->dio);
}

static void gpio_delay(void *context, unsigned int microseconds)
{
    struct timespec duration = {0, (long)microseconds * 1000L};
    (void)context;
    while (nanosleep(&duration, &duration) != 0 && errno == EINTR) {
    }
}
#endif

Tm1637 *tm1637_open(const char *chip_path, unsigned int clk_line, unsigned int dio_line,
                    unsigned int brightness, char *warning, size_t warning_size)
{
    const char *message = "TM1637 GPIO initialization failed; display disabled";
#if defined(ENABLE_GPIO)
    Tm1637 *display = NULL;
    Tm1637Bus bus = {NULL, gpio_clk, gpio_dio, gpio_read, gpio_delay};

    if (chip_path == NULL || clk_line == dio_line || brightness > 7U) {
        message = "invalid TM1637 configuration; display disabled";
        goto failure;
    }
    display = tm1637_open_bus(&bus, brightness);
    if (display == NULL) {
        message = "failed to allocate TM1637 driver; display disabled";
        goto failure;
    }
    display->bus.context = display;
    display->chip = gpiod_chip_open(chip_path);
    if (display->chip == NULL) {
        goto failure;
    }
    display->clk = gpiod_chip_get_line(display->chip, clk_line);
    display->dio = gpiod_chip_get_line(display->chip, dio_line);
    if (display->clk == NULL || display->dio == NULL) {
        goto failure;
    }
    if (gpiod_line_request_output_flags(display->clk, "netmon-tm1637-clk",
                                         GPIOD_LINE_REQUEST_FLAG_OPEN_DRAIN, 1) != 0) {
        goto failure;
    }
    display->clk_requested = true;
    if (gpiod_line_request_output_flags(display->dio, "netmon-tm1637-dio",
                                         GPIOD_LINE_REQUEST_FLAG_OPEN_DRAIN, 1) != 0) {
        goto failure;
    }
    display->dio_requested = true;
    if (warning != NULL && warning_size > 0U) {
        warning[0] = '\0';
    }
    return display;

failure:
    tm1637_close(display);
#else
    (void)chip_path;
    (void)clk_line;
    (void)dio_line;
    (void)brightness;
    message = "GPIO support was not compiled in; rebuild with ENABLE_GPIO=1 for TM1637";
#endif
    if (warning != NULL && warning_size > 0U) {
        (void)snprintf(warning, warning_size, "%s", message);
    }
    return NULL;
}

void tm1637_encode_number(unsigned int type, uint64_t value, uint8_t segments[4])
{
    static const uint8_t digits[10] = {0x3f, 0x06, 0x5b, 0x4f, 0x66,
                                      0x6d, 0x7d, 0x07, 0x7f, 0x6f};
    value = value > 999U ? 999U : value;
    segments[0] = type >= 1U && type <= 3U ? digits[type] : 0U;
    segments[1] = digits[value / 100U];
    segments[2] = digits[(value / 10U) % 10U];
    segments[3] = digits[value % 10U];
}

bool tm1637_write(Tm1637 *display, const uint8_t segments[4])
{
    uint8_t mode = 0x40U;
    uint8_t bytes[5];
    uint8_t control;
    size_t index;

    if (display == NULL || segments == NULL) {
        return false;
    }
    bytes[0] = 0xc0U;
    for (index = 0U; index < 4U; ++index) {
        bytes[index + 1U] = segments[index] & 0x7fU;
    }
    control = (uint8_t)(0x88U | display->brightness);
    return transaction(display, &mode, 1U) && transaction(display, bytes, 5U) &&
           transaction(display, &control, 1U);
}

bool tm1637_clear(Tm1637 *display)
{
    static const uint8_t blank[4] = {0U, 0U, 0U, 0U};
    uint8_t off = 0x80U;
    bool ok = tm1637_write(display, blank);
    return display != NULL && transaction(display, &off, 1U) && ok;
}

void tm1637_close(Tm1637 *display)
{
    if (display == NULL) {
        return;
    }
#if defined(ENABLE_GPIO)
    if (display->dio_requested) {
        gpiod_line_release(display->dio);
    }
    if (display->clk_requested) {
        gpiod_line_release(display->clk);
    }
    if (display->chip != NULL) {
        gpiod_chip_close(display->chip);
    }
#endif
    free(display);
}
