#include "display.h"
#include "tm1637.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct DisplayController {
    atomic_bool available;
    atomic_bool running;
    atomic_bool snapshot_failed;
    _Atomic uint64_t icmp_count;
    _Atomic uint64_t ssh_count;
    _Atomic(ScanSnapshot *) pending;
    /* The producer owns revision; the worker exclusively owns the active snapshot. */
    uint64_t published_revision;
    pthread_t worker;
    bool started;
    pthread_mutex_t init_mutex;
    pthread_cond_t init_condition;
    bool initialized;
    char init_warning[256];
    DisplayOutput output;
    DisplayConfig config;
    Tm1637 *device;
};

static void copy_warning(char *buffer, size_t size, const char *message)
{
    if (buffer != NULL && size > 0U) {
        (void)snprintf(buffer, size, "%s", message);
    }
}

static bool hardware_open(void *context, char *warning, size_t warning_size)
{
    DisplayController *controller = context;
    controller->device = tm1637_open(controller->config.chip_path,
                                      controller->config.clk_line, controller->config.dio_line,
                                      controller->config.brightness, warning, warning_size);
    return controller->device != NULL;
}

static bool hardware_write(void *context, const uint8_t segments[4])
{
    return tm1637_write(((DisplayController *)context)->device, segments);
}

static void hardware_close(void *context)
{
    DisplayController *controller = context;
    if (controller->device != NULL) {
        (void)tm1637_clear(controller->device);
        tm1637_close(controller->device);
        controller->device = NULL;
    }
}

DisplayCounts display_controller_counts(const DisplayController *controller)
{
    DisplayCounts counts = {0U, 0U};
    if (controller != NULL) {
        counts.icmp = atomic_load(&controller->icmp_count);
        counts.ssh = atomic_load(&controller->ssh_count);
    }
    return counts;
}

void display_render(const DisplayCounts *counts, const ScanSnapshot *snapshot,
                    uint64_t elapsed_ms, time_t now, uint8_t segments[4])
{
    unsigned int type = (unsigned int)((elapsed_ms / 1000U) % 3U) + 1U;
    uint64_t value = type == 1U ? counts->icmp :
                     type == 2U ? counts->ssh : scan_snapshot_max_ports(snapshot, now);
    tm1637_encode_number(type, value, segments);
}

static uint64_t elapsed_ms(struct timespec start, struct timespec now)
{
    int64_t nanoseconds = (int64_t)(now.tv_sec - start.tv_sec) * 1000000000LL +
                          now.tv_nsec - start.tv_nsec;
    return nanoseconds > 0 ? (uint64_t)(nanoseconds / 1000000LL) : 0U;
}

static void *display_worker(void *context)
{
    DisplayController *controller = context;
    ScanSnapshot *active = NULL;
    struct timespec start;
    struct timespec now;
    struct timespec deadline;
    uint8_t previous[4];
    char warning[256] = "";
    bool ready = controller->output.open(controller->output.context, warning, sizeof(warning));

    tm1637_encode_number(1U, 0U, previous);
    if (ready && (!controller->output.write(controller->output.context, previous) ||
                  clock_gettime(CLOCK_MONOTONIC, &start) != 0)) {
        ready = false;
        copy_warning(warning, sizeof(warning), "TM1637 initial write/clock failed; display disabled");
    }
    if (!ready && warning[0] == '\0') {
        copy_warning(warning, sizeof(warning), "display initialization failed; display disabled");
    }
    (void)pthread_mutex_lock(&controller->init_mutex);
    copy_warning(controller->init_warning, sizeof(controller->init_warning), warning);
    atomic_store(&controller->available, ready);
    controller->initialized = true;
    (void)pthread_cond_signal(&controller->init_condition);
    (void)pthread_mutex_unlock(&controller->init_mutex);

    while (ready && atomic_load(&controller->running)) {
        ScanSnapshot *latest;
        DisplayCounts counts;
        uint8_t segments[4];
        int wait_result;
        time_t wall_time;

        if (atomic_load(&controller->snapshot_failed)) {
            (void)fprintf(stderr, "[WARN ] failed to allocate scan snapshot; display disabled\n");
            break;
        }
        latest = atomic_exchange(&controller->pending, NULL);
        if (latest != NULL) {
            scan_snapshot_destroy(active);
            active = latest;
        }
        wall_time = time(NULL);
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || wall_time == (time_t)-1) {
            (void)fprintf(stderr, "[WARN ] display clock failed; display disabled\n");
            break;
        }
        counts = display_controller_counts(controller);
        display_render(&counts, active, elapsed_ms(start, now), wall_time, segments);
        if (memcmp(previous, segments, sizeof(segments)) != 0) {
            if (!controller->output.write(controller->output.context, segments)) {
                (void)fprintf(stderr, "[WARN ] TM1637 transfer/ACK failed; display disabled\n");
                break;
            }
            memcpy(previous, segments, sizeof(previous));
        }
        /* The deadline is based on the sample time, so GPIO transfer time does not
         * accumulate into the one-second page schedule. Never hold a producer lock. */
        deadline = now;
        deadline.tv_nsec += 100000000L;
        if (deadline.tv_nsec >= 1000000000L) {
            ++deadline.tv_sec;
            deadline.tv_nsec -= 1000000000L;
        }
        do {
            wait_result = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL);
        } while (wait_result == EINTR && atomic_load(&controller->running));
        if (wait_result != 0 && wait_result != EINTR) {
            (void)fprintf(stderr, "[WARN ] display timer failed; display disabled\n");
            break;
        }
    }
    atomic_store(&controller->available, false);
    scan_snapshot_destroy(active);
    controller->output.close(controller->output.context);
    return NULL;
}

static DisplayController *allocate_controller(char *warning, size_t warning_size)
{
    DisplayController *controller = calloc(1U, sizeof(*controller));
    copy_warning(warning, warning_size, "");
    if (controller == NULL) {
        copy_warning(warning, warning_size, "failed to allocate display controller; display disabled");
        return NULL;
    }
    atomic_init(&controller->available, false);
    atomic_init(&controller->running, false);
    atomic_init(&controller->snapshot_failed, false);
    atomic_init(&controller->icmp_count, 0U);
    atomic_init(&controller->ssh_count, 0U);
    atomic_init(&controller->pending, NULL);
    return controller;
}

static void start_controller(DisplayController *controller, char *warning, size_t warning_size)
{
    /* Refuse platforms whose atomic operations could put a hidden lock in capture. */
    if (!atomic_is_lock_free(&controller->pending) || !atomic_is_lock_free(&controller->icmp_count) ||
        !atomic_is_lock_free(&controller->available)) {
        copy_warning(warning, warning_size, "display requires lock-free atomics; display disabled");
        return;
    }
    if (pthread_mutex_init(&controller->init_mutex, NULL) != 0) {
        copy_warning(warning, warning_size, "failed to initialize display worker mutex; display disabled");
        return;
    }
    if (pthread_cond_init(&controller->init_condition, NULL) != 0) {
        (void)pthread_mutex_destroy(&controller->init_mutex);
        copy_warning(warning, warning_size, "failed to initialize display worker condition; display disabled");
        return;
    }
    atomic_store(&controller->running, true);
    if (pthread_create(&controller->worker, NULL, display_worker, controller) != 0) {
        atomic_store(&controller->running, false);
        (void)pthread_cond_destroy(&controller->init_condition);
        (void)pthread_mutex_destroy(&controller->init_mutex);
        copy_warning(warning, warning_size, "failed to start display worker; display disabled");
        return;
    }
    controller->started = true;
    /* Only startup waits for initialization, before capture begins. */
    (void)pthread_mutex_lock(&controller->init_mutex);
    while (!controller->initialized) {
        (void)pthread_cond_wait(&controller->init_condition, &controller->init_mutex);
    }
    copy_warning(warning, warning_size, controller->init_warning);
    (void)pthread_mutex_unlock(&controller->init_mutex);
}

DisplayController *display_controller_create(const DisplayConfig *config, char *warning, size_t warning_size)
{
    DisplayController *controller = allocate_controller(warning, warning_size);
    if (controller == NULL || config == NULL || !config->enabled) {
        return controller;
    }
    controller->config = *config;
    controller->output = (DisplayOutput){controller, hardware_open, hardware_write, hardware_close};
    start_controller(controller, warning, warning_size);
    return controller;
}

DisplayController *display_controller_create_with_output(const DisplayOutput *output, char *warning, size_t warning_size)
{
    DisplayController *controller = allocate_controller(warning, warning_size);
    if (controller == NULL) {
        return NULL;
    }
    if (output == NULL || output->open == NULL || output->write == NULL || output->close == NULL) {
        copy_warning(warning, warning_size, "invalid display output; display disabled");
        return controller;
    }
    controller->output = *output;
    start_controller(controller, warning, warning_size);
    return controller;
}

bool display_controller_is_available(const DisplayController *controller)
{
    return controller != NULL && atomic_load(&controller->available) &&
           !atomic_load(&controller->snapshot_failed);
}

void display_controller_record_event(DisplayController *controller, const Event *event)
{
    _Atomic uint64_t *counter = NULL;
    uint64_t value;
    if (!display_controller_is_available(controller) || event == NULL) {
        return;
    }
    if (event->kind == EVENT_KIND_ICMP && event->led_action == LED_ACTION_SHORT) {
        counter = &controller->icmp_count;
    } else if (event->kind == EVENT_KIND_TCP && event->led_action == LED_ACTION_LONG) {
        counter = &controller->ssh_count;
    }
    if (counter != NULL) {
        value = atomic_load(counter);
        if (value != UINT64_MAX) {
            atomic_store(counter, value + 1U);
        }
    }
}

void display_controller_publish_scan(DisplayController *controller, const ScanDetector *detector)
{
    ScanSnapshot *snapshot;
    uint64_t revision;
    if (!display_controller_is_available(controller) || detector == NULL) {
        return;
    }
    revision = scan_detector_revision(detector);
    if (revision == controller->published_revision) {
        return;
    }
    snapshot = scan_detector_snapshot(detector);
    if (snapshot == NULL) {
        atomic_store(&controller->snapshot_failed, true);
        return;
    }
    controller->published_revision = revision;
    /* Exactly one owner receives each pointer. Neither side waits for the other.
     * Replaced pending snapshots are obsolete; the worker's active one is separate. */
    scan_snapshot_destroy(atomic_exchange(&controller->pending, snapshot));
}

void display_controller_destroy(DisplayController *controller)
{
    if (controller == NULL) {
        return;
    }
    atomic_store(&controller->running, false);
    if (controller->started) {
        (void)pthread_join(controller->worker, NULL);
        (void)pthread_cond_destroy(&controller->init_condition);
        (void)pthread_mutex_destroy(&controller->init_mutex);
    }
    scan_snapshot_destroy(atomic_exchange(&controller->pending, NULL));
    free(controller);
}
