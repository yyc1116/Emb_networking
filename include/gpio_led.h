#ifndef GPIO_LED_H
#define GPIO_LED_H

#include <stdbool.h>
#include <stddef.h>

typedef enum LedAction {
    LED_ACTION_NONE = 0,
    LED_ACTION_SHORT,
    LED_ACTION_LONG,
    LED_ACTION_RAPID
} LedAction;

typedef struct LedController LedController;

LedController *led_controller_create(bool enable_led, const char *chip_path, unsigned int line_number, bool line_number_provided, char *warning_buffer, size_t warning_buffer_size);
bool led_controller_is_available(const LedController *controller);
void led_controller_enqueue(LedController *controller, LedAction action);
void led_controller_destroy(LedController *controller);

#endif
