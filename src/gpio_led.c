#include "gpio_led.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(ENABLE_GPIO)
#include <gpiod.h>
#include <pthread.h>
#include <unistd.h>
#endif

struct LedController {
    bool requested;
    bool available;
#if defined(ENABLE_GPIO)
    /* LED effects run on a worker thread so packet capture never sleeps in the callback. */
    bool running;
    struct gpiod_chip *chip;
    struct gpiod_line *line;
    pthread_t worker;
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    LedAction queue[32];
    size_t queue_head;
    size_t queue_tail;
    size_t queue_count;
#endif
};

static void copy_warning(char *buffer, size_t buffer_size, const char *text)
{
    if (buffer == NULL || buffer_size == 0U) {
        return;
    }

    if (text == NULL) {
        buffer[0] = '\0';
        return;
    }

    strncpy(buffer, text, buffer_size - 1U);
    buffer[buffer_size - 1U] = '\0';
}

#if defined(ENABLE_GPIO)
static void drive_line(struct gpiod_line *line, int value)
{
    if (line != NULL) {
        (void)gpiod_line_set_value(line, value);
    }
}

static void play_pattern(struct gpiod_line *line, LedAction action)
{
    unsigned int i;

    /* Patterns match the project spec: short for ICMP, long for SSH, rapid for scan alert. */
    switch (action) {
    case LED_ACTION_SHORT:
        drive_line(line, 1);
        usleep(100000U);
        drive_line(line, 0);
        break;
    case LED_ACTION_LONG:
        drive_line(line, 1);
        usleep(500000U);
        drive_line(line, 0);
        break;
    case LED_ACTION_RAPID:
        for (i = 0U; i < 3U; ++i) {
            drive_line(line, 1);
            usleep(100000U);
            drive_line(line, 0);
            if (i < 2U) {
                usleep(100000U);
            }
        }
        break;
    default:
        break;
    }
}

static int queue_pop(LedController *controller, LedAction *action)
{
    /* The worker blocks here instead of the capture callback blocking on LED timing. */
    while (controller->queue_count == 0U && controller->running) {
        (void)pthread_cond_wait(&controller->condition, &controller->mutex);
    }

    if (controller->queue_count == 0U) {
        return 0;
    }

    *action = controller->queue[controller->queue_head];
    controller->queue_head = (controller->queue_head + 1U) % (sizeof(controller->queue) / sizeof(controller->queue[0]));
    --controller->queue_count;
    return 1;
}

static void *led_worker_main(void *user_data)
{
    LedController *controller = (LedController *)user_data;
    LedAction action;

    (void)pthread_mutex_lock(&controller->mutex);
    while (controller->running) {
        if (!queue_pop(controller, &action)) {
            continue;
        }
        (void)pthread_mutex_unlock(&controller->mutex);
        play_pattern(controller->line, action);
        (void)pthread_mutex_lock(&controller->mutex);
    }
    (void)pthread_mutex_unlock(&controller->mutex);

    drive_line(controller->line, 0);
    return NULL;
}
#endif

LedController *led_controller_create(bool enable_led, const char *chip_path, unsigned int line_number, bool line_number_provided, char *warning_buffer, size_t warning_buffer_size)
{
    LedController *controller;

    controller = (LedController *)calloc(1U, sizeof(*controller));
    if (controller == NULL) {
        copy_warning(warning_buffer, warning_buffer_size, "failed to allocate LED controller; LED disabled");
        return NULL;
    }

    controller->requested = enable_led;
    controller->available = false;
    copy_warning(warning_buffer, warning_buffer_size, "");

    /* LED is optional by design, so failure downgrades to warning instead of aborting netmon. */
    if (!enable_led) {
        return controller;
    }

    if (!line_number_provided) {
        copy_warning(warning_buffer, warning_buffer_size, "LED requested but --gpio-line was not provided; LED disabled");
        return controller;
    }

#if !defined(ENABLE_GPIO)
    (void)chip_path;
    (void)line_number;
    copy_warning(warning_buffer, warning_buffer_size, "GPIO support was not compiled in; rebuild with ENABLE_GPIO=1 to enable LED output");
    return controller;
#else
    if (chip_path == NULL) {
        copy_warning(warning_buffer, warning_buffer_size, "LED requested but no GPIO chip path was provided; LED disabled");
        return controller;
    }

    controller->chip = gpiod_chip_open(chip_path);
    if (controller->chip == NULL) {
        char message[256];

        (void)snprintf(message, sizeof(message), "failed to open GPIO chip %s; LED disabled", chip_path);
        copy_warning(warning_buffer, warning_buffer_size, message);
        return controller;
    }

    controller->line = gpiod_chip_get_line(controller->chip, (unsigned int)line_number);
    if (controller->line == NULL) {
        copy_warning(warning_buffer, warning_buffer_size, "failed to access requested GPIO line; LED disabled");
        gpiod_chip_close(controller->chip);
        controller->chip = NULL;
        return controller;
    }

    if (gpiod_line_request_output(controller->line, "netmon", 0) != 0) {
        copy_warning(warning_buffer, warning_buffer_size, "failed to request GPIO line for output; LED disabled");
        gpiod_line_release(controller->line);
        gpiod_chip_close(controller->chip);
        controller->chip = NULL;
        controller->line = NULL;
        return controller;
    }

    if (pthread_mutex_init(&controller->mutex, NULL) != 0) {
        copy_warning(warning_buffer, warning_buffer_size, "failed to initialize LED worker; LED disabled");
        if (controller->line != NULL) {
            gpiod_line_release(controller->line);
        }
        if (controller->chip != NULL) {
            gpiod_chip_close(controller->chip);
        }
        controller->line = NULL;
        controller->chip = NULL;
        return controller;
    }

    if (pthread_cond_init(&controller->condition, NULL) != 0) {
        copy_warning(warning_buffer, warning_buffer_size, "failed to initialize LED worker; LED disabled");
        (void)pthread_mutex_destroy(&controller->mutex);
        if (controller->line != NULL) {
            gpiod_line_release(controller->line);
        }
        if (controller->chip != NULL) {
            gpiod_chip_close(controller->chip);
        }
        controller->line = NULL;
        controller->chip = NULL;
        return controller;
    }

    controller->running = true;
    if (pthread_create(&controller->worker, NULL, led_worker_main, controller) != 0) {
        copy_warning(warning_buffer, warning_buffer_size, "failed to start LED worker; LED disabled");
        controller->running = false;
        (void)pthread_cond_destroy(&controller->condition);
        (void)pthread_mutex_destroy(&controller->mutex);
        gpiod_line_release(controller->line);
        gpiod_chip_close(controller->chip);
        controller->line = NULL;
        controller->chip = NULL;
        return controller;
    }

    controller->available = true;
    return controller;
#endif
}

bool led_controller_is_available(const LedController *controller)
{
    return controller != NULL && controller->available;
}

void led_controller_enqueue(LedController *controller, LedAction action)
{
#if defined(ENABLE_GPIO)
    size_t queue_capacity;

    if (controller == NULL || !controller->available || action == LED_ACTION_NONE) {
        return;
    }

    queue_capacity = sizeof(controller->queue) / sizeof(controller->queue[0]);

    /* If the queue is full we silently drop the LED pulse; monitoring matters more than blinking. */
    (void)pthread_mutex_lock(&controller->mutex);
    if (controller->queue_count < queue_capacity) {
        controller->queue[controller->queue_tail] = action;
        controller->queue_tail = (controller->queue_tail + 1U) % queue_capacity;
        ++controller->queue_count;
        (void)pthread_cond_signal(&controller->condition);
    }
    (void)pthread_mutex_unlock(&controller->mutex);
#else
    (void)controller;
    (void)action;
#endif
}

void led_controller_destroy(LedController *controller)
{
    if (controller == NULL) {
        return;
    }

#if defined(ENABLE_GPIO)
    if (controller->available) {
        (void)pthread_mutex_lock(&controller->mutex);
        controller->running = false;
        (void)pthread_cond_signal(&controller->condition);
        (void)pthread_mutex_unlock(&controller->mutex);
        (void)pthread_join(controller->worker, NULL);
        (void)pthread_cond_destroy(&controller->condition);
        (void)pthread_mutex_destroy(&controller->mutex);
    }

    if (controller->line != NULL) {
        drive_line(controller->line, 0);
        gpiod_line_release(controller->line);
    }
    if (controller->chip != NULL) {
        gpiod_chip_close(controller->chip);
    }
#endif

    free(controller);
}
