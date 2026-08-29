#include "capture.h"
#include "gpio_led.h"
#include "logger.h"
#include "parser.h"
#include "rules.h"
#include "scan_detector.h"

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_LOG_PATH "/var/log/netmon.log"
#define DEFAULT_GPIO_CHIP "/dev/gpiochip0"
#define DEFAULT_SCAN_WINDOW 10U
#define DEFAULT_SCAN_THRESHOLD 20U

typedef struct AppConfig {
    /* Runtime options parsed from CLI. */
    const char *interface_name;
    const char *log_path;
    unsigned int scan_window_seconds;
    size_t scan_threshold;
    bool enable_led;
    const char *gpio_chip;
    bool gpio_line_provided;
    unsigned int gpio_line;
} AppConfig;

typedef struct AppContext {
    /* Shared runtime objects passed into the libpcap callback. */
    Logger *logger;
    LedController *led_controller;
    ScanDetector *scan_detector;
    RulesEngine *rules_engine;
} AppContext;

static volatile sig_atomic_t g_stop_requested = 0;
static CaptureHandle *g_capture_handle = NULL;

static void print_usage(const char *program_name)
{
    (void)fprintf(stderr,
                  "Usage: %s -i <interface> [-l <log_path>] [--scan-window <seconds>] [--scan-threshold <count>] "
                  "[--gpio-chip <path>] [--gpio-line <line>] [--no-led]\n",
                  program_name);
}

static bool parse_unsigned_value(const char *text, unsigned long *value)
{
    char *end_pointer = NULL;

    if (text == NULL || text[0] == '\0') {
        return false;
    }

    errno = 0;
    *value = strtoul(text, &end_pointer, 10);
    if (errno != 0 || end_pointer == NULL || *end_pointer != '\0') {
        return false;
    }

    return true;
}

static bool parse_arguments(int argc, char **argv, AppConfig *config)
{
    int index;

    /* Keep all defaults in one place so CLI parsing only overrides them. */
    config->interface_name = NULL;
    config->log_path = DEFAULT_LOG_PATH;
    config->scan_window_seconds = DEFAULT_SCAN_WINDOW;
    config->scan_threshold = DEFAULT_SCAN_THRESHOLD;
    config->enable_led = true;
    config->gpio_chip = DEFAULT_GPIO_CHIP;
    config->gpio_line_provided = false;
    config->gpio_line = 0U;

    for (index = 1; index < argc; ++index) {
        unsigned long parsed_value;

        if (strcmp(argv[index], "-i") == 0) {
            if (index + 1 >= argc) {
                return false;
            }
            config->interface_name = argv[++index];
            continue;
        }

        if (strcmp(argv[index], "-l") == 0) {
            if (index + 1 >= argc) {
                return false;
            }
            config->log_path = argv[++index];
            continue;
        }

        if (strcmp(argv[index], "--scan-window") == 0) {
            if (index + 1 >= argc || !parse_unsigned_value(argv[index + 1], &parsed_value) || parsed_value == 0UL) {
                return false;
            }
            config->scan_window_seconds = (unsigned int)parsed_value;
            ++index;
            continue;
        }

        if (strcmp(argv[index], "--scan-threshold") == 0) {
            if (index + 1 >= argc || !parse_unsigned_value(argv[index + 1], &parsed_value) || parsed_value == 0UL) {
                return false;
            }
            config->scan_threshold = (size_t)parsed_value;
            ++index;
            continue;
        }

        if (strcmp(argv[index], "--gpio-chip") == 0) {
            if (index + 1 >= argc) {
                return false;
            }
            config->gpio_chip = argv[++index];
            continue;
        }

        if (strcmp(argv[index], "--gpio-line") == 0) {
            if (index + 1 >= argc || !parse_unsigned_value(argv[index + 1], &parsed_value)) {
                return false;
            }
            config->gpio_line = (unsigned int)parsed_value;
            config->gpio_line_provided = true;
            ++index;
            continue;
        }

        if (strcmp(argv[index], "--no-led") == 0) {
            config->enable_led = false;
            continue;
        }

        if (strcmp(argv[index], "-h") == 0 || strcmp(argv[index], "--help") == 0) {
            print_usage(argv[0]);
            exit(EXIT_SUCCESS);
        }

        return false;
    }

    return config->interface_name != NULL;
}

static void handle_signal(int signal_number)
{
    (void)signal_number;
    g_stop_requested = 1;
    /* pcap_loop() is blocking, so the signal handler asks libpcap to exit its loop. */
    if (g_capture_handle != NULL) {
        capture_break(g_capture_handle);
    }
}

static void process_packet(const struct pcap_pkthdr *header, const uint8_t *packet, void *user_data)
{
    AppContext *context = (AppContext *)user_data;
    PacketInfo packet_info;
    Event event;
    ScanAlert scan_alert;

    if (context == NULL || header == NULL || packet == NULL) {
        return;
    }

    /* Parse first, then let rule logic decide whether the packet becomes an event. */
    (void)parse_packet(packet, header->caplen, header->len, &packet_info);

    if (rules_engine_evaluate_packet(context->rules_engine, &packet_info, &event)) {
        logger_emit(context->logger, &event);
        led_controller_enqueue(context->led_controller, event.led_action);
    }

    /* Port-scan alerts are a second decision layer built on top of parsed TCP SYN traffic. */
    if (scan_detector_observe(context->scan_detector, &packet_info, &scan_alert)) {
        rules_make_scan_alert(scan_alert.src_ipv4, scan_alert.unique_ports, scan_alert.window_seconds, &event);
        logger_emit(context->logger, &event);
        led_controller_enqueue(context->led_controller, event.led_action);
    }
}

int main(int argc, char **argv)
{
    AppConfig config;
    AppContext context;
    char error_buffer[256];
    char led_warning[256];
    int loop_result;

    if (!parse_arguments(argc, argv, &config)) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    /* Initialize subsystems in dependency order so cleanup is predictable on failure. */
    context.logger = logger_open(config.log_path, error_buffer, sizeof(error_buffer));
    if (context.logger == NULL) {
        (void)fprintf(stderr, "Failed to initialize logger: %s\n", error_buffer);
        return EXIT_FAILURE;
    }

    context.scan_detector = scan_detector_create(config.scan_window_seconds, config.scan_threshold);
    if (context.scan_detector == NULL) {
        (void)fprintf(stderr, "Failed to initialize scan detector\n");
        logger_close(context.logger);
        return EXIT_FAILURE;
    }

    context.rules_engine = rules_engine_create();
    if (context.rules_engine == NULL) {
        (void)fprintf(stderr, "Failed to initialize rules engine\n");
        scan_detector_destroy(context.scan_detector);
        logger_close(context.logger);
        return EXIT_FAILURE;
    }

    context.led_controller = led_controller_create(config.enable_led,
                                                   config.gpio_chip,
                                                   config.gpio_line,
                                                   config.gpio_line_provided,
                                                   led_warning,
                                                   sizeof(led_warning));
    if (context.led_controller == NULL) {
        (void)fprintf(stderr, "Failed to allocate LED controller\n");
        rules_engine_destroy(context.rules_engine);
        scan_detector_destroy(context.scan_detector);
        logger_close(context.logger);
        return EXIT_FAILURE;
    }

    if (led_warning[0] != '\0') {
        (void)fprintf(stderr, "[WARN ] %s\n", led_warning);
    }

    /* SIGINT/SIGTERM provide a clean Ctrl+C path instead of killing capture mid-call. */
    if (signal(SIGINT, handle_signal) == SIG_ERR || signal(SIGTERM, handle_signal) == SIG_ERR) {
        (void)fprintf(stderr, "Failed to install signal handlers\n");
        led_controller_destroy(context.led_controller);
        rules_engine_destroy(context.rules_engine);
        scan_detector_destroy(context.scan_detector);
        logger_close(context.logger);
        return EXIT_FAILURE;
    }

    g_capture_handle = capture_open(config.interface_name, 65535, 1, 1000, error_buffer, sizeof(error_buffer));
    if (g_capture_handle == NULL) {
        (void)fprintf(stderr, "Failed to open interface %s: %s\n", config.interface_name, error_buffer);
        led_controller_destroy(context.led_controller);
        rules_engine_destroy(context.rules_engine);
        scan_detector_destroy(context.scan_detector);
        logger_close(context.logger);
        return EXIT_FAILURE;
    }

    (void)fprintf(stdout,
                  "netmon listening on %s (log=%s, scan-window=%u, scan-threshold=%zu, led=%s)\n",
                  config.interface_name,
                  config.log_path,
                  config.scan_window_seconds,
                  config.scan_threshold,
                  led_controller_is_available(context.led_controller) ? "enabled" : "disabled");

    /* After this point, almost all work happens inside process_packet(). */
    loop_result = capture_loop(g_capture_handle, process_packet, &context);
    if (loop_result == -1) {
        (void)fprintf(stderr, "pcap loop failed: %s\n", capture_get_error(g_capture_handle));
    } else if (g_stop_requested != 0) {
        (void)fprintf(stdout, "Capture stopped by signal\n");
    }

    capture_close(g_capture_handle);
    g_capture_handle = NULL;
    /* Cleanup runs in reverse order of initialization. */
    led_controller_destroy(context.led_controller);
    rules_engine_destroy(context.rules_engine);
    scan_detector_destroy(context.scan_detector);
    logger_close(context.logger);

    return (loop_result == -1) ? EXIT_FAILURE : EXIT_SUCCESS;
}
