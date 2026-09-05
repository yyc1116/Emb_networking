#ifndef DISPLAY_H
#define DISPLAY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "rules.h"
#include "scan_detector.h"

typedef struct DisplayController DisplayController;

typedef struct DisplayConfig {
    bool enabled;
    const char *chip_path;
    unsigned int clk_line;
    unsigned int dio_line;
    unsigned int brightness;
} DisplayConfig;

typedef struct DisplayCounts {
    uint64_t icmp;
    uint64_t ssh;
} DisplayCounts;

/* All output callbacks run exclusively on the worker, including open/close.
 * close must also tolerate a partially failed open. Context is borrowed. */
typedef struct DisplayOutput {
    void *context;
    bool (*open)(void *context, char *warning, size_t warning_size);
    bool (*write)(void *context, const uint8_t segments[4]);
    void (*close)(void *context);
} DisplayOutput;

DisplayController *display_controller_create(const DisplayConfig *config, char *warning, size_t warning_size);
DisplayController *display_controller_create_with_output(const DisplayOutput *output, char *warning, size_t warning_size);
bool display_controller_is_available(const DisplayController *controller);
/* Single producer: call these from the capture thread, never from a signal handler. */
void display_controller_record_event(DisplayController *controller, const Event *event);
void display_controller_publish_scan(DisplayController *controller, const ScanDetector *detector);
DisplayCounts display_controller_counts(const DisplayController *controller);
/* Pure rendering function, also used to verify scheduling with controlled time. */
void display_render(const DisplayCounts *counts, const ScanSnapshot *snapshot,
                    uint64_t elapsed_ms, time_t now, uint8_t segments[4]);
/* Stop capture calls before destroying the controller. */
void display_controller_destroy(DisplayController *controller);

#endif
