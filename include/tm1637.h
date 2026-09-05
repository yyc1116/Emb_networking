#ifndef TM1637_H
#define TM1637_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct Tm1637 Tm1637;

/* A released (1) DIO must permit the device to pull it low for ACK. */
typedef struct Tm1637Bus {
    void *context;
    int (*set_clk)(void *context, int value);
    int (*set_dio)(void *context, int value);
    int (*get_dio)(void *context);
    void (*delay_us)(void *context, unsigned int microseconds);
} Tm1637Bus;

Tm1637 *tm1637_open(const char *chip_path, unsigned int clk, unsigned int dio,
                    unsigned int brightness, char *warning, size_t warning_size);
/* Borrowed bus context; useful for testing the actual wire protocol without GPIO. */
Tm1637 *tm1637_open_bus(const Tm1637Bus *bus, unsigned int brightness);
void tm1637_encode_number(unsigned int type, uint64_t value, uint8_t segments[4]);
bool tm1637_write(Tm1637 *display, const uint8_t segments[4]);
bool tm1637_clear(Tm1637 *display);
void tm1637_close(Tm1637 *display);

#endif
