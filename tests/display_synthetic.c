#include "display.h"
#include "tm1637.h"

#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Linker wrappers inject time/allocation failures without production test branches. */
static _Atomic time_t test_time = 1000;
static atomic_bool fail_malloc;
static atomic_bool fail_calloc;
void *__real_malloc(size_t size);
void *__real_calloc(size_t count, size_t size);

time_t __wrap_time(time_t *result)
{
    time_t value = atomic_load(&test_time);
    if (result != NULL) {
        *result = value;
    }
    return value;
}

void *__wrap_malloc(size_t size)
{
    return atomic_exchange(&fail_malloc, false) ? NULL : __real_malloc(size);
}

void *__wrap_calloc(size_t count, size_t size)
{
    return atomic_exchange(&fail_calloc, false) ? NULL : __real_calloc(count, size);
}

typedef struct FakeBus {
    int clk;
    int dio;
    bool active;
    unsigned int bits;
    uint8_t byte;
    uint8_t bytes[128];
    size_t count;
    size_t starts;
    size_t stops;
    size_t nack_at;
    bool io_error;
} FakeBus;

static int bus_clk(void *context, int value)
{
    FakeBus *bus = context;
    if (bus->io_error) {
        return -1;
    }
    if (bus->active && !bus->clk && value) {
        if (bus->bits < 8U) {
            bus->byte |= (uint8_t)(bus->dio << bus->bits);
            ++bus->bits;
        } else {
            assert(bus->dio == 1); /* Host released DIO for the ninth clock. */
            assert(bus->count < sizeof(bus->bytes));
            bus->bytes[bus->count++] = bus->byte;
            bus->bits = 0U;
            bus->byte = 0U;
        }
    }
    bus->clk = value;
    return 0;
}

static int bus_dio(void *context, int value)
{
    FakeBus *bus = context;
    if (bus->io_error) {
        return -1;
    }
    if (bus->clk && bus->dio && !value) {
        bus->active = true;
        bus->bits = 0U;
        bus->byte = 0U;
        ++bus->starts;
    } else if (bus->clk && !bus->dio && value) {
        bus->active = false;
        ++bus->stops;
    }
    bus->dio = value;
    return 0;
}

static int bus_read(void *context)
{
    FakeBus *bus = context;
    assert(bus->clk == 1 && bus->dio == 1);
    return bus->count == bus->nack_at ? 1 : 0;
}

static void bus_delay(void *context, unsigned int microseconds)
{
    (void)context;
    assert(microseconds >= 1U);
}

static void test_protocol(void)
{
    FakeBus fake = {.clk = 1, .dio = 1};
    Tm1637Bus bus = {&fake, bus_clk, bus_dio, bus_read, bus_delay};
    Tm1637 *device = tm1637_open_bus(&bus, 3U);
    uint8_t segments[4];
    static const uint8_t expected[] = {0x40, 0xc0, 0x06, 0x3f, 0x3f, 0x66, 0x8b};

    assert(device != NULL);
    tm1637_encode_number(1U, 4U, segments);
    assert(tm1637_write(device, segments));
    assert(fake.count == sizeof(expected));
    assert(memcmp(fake.bytes, expected, sizeof(expected)) == 0);
    assert(fake.starts == 3U && fake.stops == 3U);
    assert(tm1637_clear(device));
    assert(fake.bytes[fake.count - 1U] == 0x80U);
    assert(fake.bytes[fake.count - 6U] == 0U);
    fake.nack_at = fake.count + 1U;
    assert(!tm1637_write(device, segments));
    assert(!fake.active && fake.clk == 1 && fake.dio == 1);
    fake.io_error = true;
    assert(!tm1637_write(device, segments));
    tm1637_close(device);
    assert(tm1637_open_bus(&bus, 8U) == NULL);
    assert(tm1637_open_bus(NULL, 3U) == NULL);
}

static void expect_digits(const uint8_t segments[4], const char *text)
{
    static const uint8_t digits[10] = {0x3f, 0x06, 0x5b, 0x4f, 0x66, 0x6d, 0x7d, 0x07, 0x7f, 0x6f};
    size_t index;
    for (index = 0U; index < 4U; ++index) {
        assert(segments[index] == digits[(unsigned int)(text[index] - '0')]);
        assert((segments[index] & 0x80U) == 0U);
    }
}

static PacketInfo syn_packet(uint32_t source, uint16_t port)
{
    PacketInfo packet = {0};
    packet.has_ipv4 = true;
    packet.has_tcp = true;
    packet.has_ports = true;
    packet.src_ipv4 = source;
    packet.dst_ipv4 = 10U;
    packet.src_port = 50000U;
    packet.dst_port = port;
    packet.tcp_flags = 0x02U;
    packet.tcp_sequence = 1U;
    return packet;
}

static void test_scan_and_schedule(void)
{
    ScanDetector *detector = scan_detector_create(10U, 20U);
    ScanSnapshot *snapshot;
    ScanSnapshot *refreshed;
    ScanAlert alert;
    PacketInfo packet;
    DisplayCounts counts = {4U, 2U};
    uint8_t segments[4];
    unsigned int port;

    assert(detector != NULL);
    snapshot = scan_detector_snapshot(detector);
    assert(snapshot != NULL && scan_snapshot_max_ports(snapshot, 1000) == 0U);
    scan_snapshot_destroy(snapshot);
    for (port = 1U; port <= 12U; ++port) {
        packet = syn_packet(2U, (uint16_t)port);
        assert(!scan_detector_observe_at(detector, &packet, &alert, 1000));
        if (port <= 8U) {
            packet = syn_packet(1U, (uint16_t)port);
            assert(!scan_detector_observe_at(detector, &packet, &alert, 1000));
        }
    }
    snapshot = scan_detector_snapshot(detector);
    assert(snapshot != NULL);
    assert(scan_snapshot_max_ports(snapshot, 1010) == 12U);
    assert(scan_snapshot_max_ports(snapshot, 1011) == 0U);
    display_render(&counts, snapshot, 0U, 1000, segments);
    expect_digits(segments, "1004");
    display_render(&counts, snapshot, 999U, 1000, segments);
    expect_digits(segments, "1004");
    display_render(&counts, snapshot, 1000U, 1000, segments);
    expect_digits(segments, "2002");
    display_render(&counts, snapshot, 2000U, 1000, segments);
    expect_digits(segments, "3012");
    display_render(&counts, snapshot, 2999U, 1011, segments);
    expect_digits(segments, "3000");
    display_render(&counts, snapshot, 3000U, 1011, segments);
    expect_digits(segments, "1004");
    counts.icmp = UINT64_MAX;
    counts.ssh = 1001U;
    display_render(&counts, snapshot, 0U, 1000, segments);
    expect_digits(segments, "1999");
    display_render(&counts, snapshot, 1000U, 1000, segments);
    expect_digits(segments, "2999");
    tm1637_encode_number(3U, 1000U, segments);
    expect_digits(segments, "3999");

    packet = syn_packet(2U, 1U);
    assert(!scan_detector_observe_at(detector, &packet, &alert, 1005));
    refreshed = scan_detector_snapshot(detector);
    assert(refreshed != NULL);
    assert(scan_snapshot_max_ports(refreshed, 1005) == 12U);
    assert(scan_snapshot_max_ports(refreshed, 1011) == 1U);
    assert(scan_snapshot_max_ports(refreshed, 1015) == 1U);
    assert(scan_snapshot_max_ports(refreshed, 1016) == 0U);
    /* The original immutable snapshot must not inherit later refreshes. */
    assert(scan_snapshot_max_ports(snapshot, 1011) == 0U);
    scan_snapshot_destroy(snapshot);
    scan_snapshot_destroy(refreshed);

    for (port = 1U; port <= 25U; ++port) {
        packet = syn_packet(3U, (uint16_t)port);
        assert(scan_detector_observe_at(detector, &packet, &alert, 1020) == (port == 20U));
    }
    assert(alert.unique_ports == 20U);
    snapshot = scan_detector_snapshot(detector);
    assert(scan_snapshot_max_ports(snapshot, 1020) == 25U);
    scan_snapshot_destroy(snapshot);
    for (port = 1U; port <= 25U; ++port) {
        packet = syn_packet(3U, (uint16_t)port);
        assert(!scan_detector_observe_at(detector, &packet, &alert, 1029));
    }
    assert(!scan_detector_observe_at(detector, &packet, &alert, 1030));
    assert(scan_detector_observe_at(detector, &packet, &alert, 1031));
    packet = syn_packet(4U, 80U);
    packet.tcp_flags = 0x12U;
    assert(!scan_detector_observe_at(detector, &packet, &alert, 1042));
    packet.tcp_flags = 0x02U;
    assert(!scan_detector_observe_at(detector, &packet, &alert, 1042));
    snapshot = scan_detector_snapshot(detector);
    /* Both original source groups have actually been pruned. */
    assert(scan_snapshot_max_ports(snapshot, 1042) == 1U);
    scan_detector_destroy(detector);
    assert(scan_snapshot_max_ports(snapshot, 1053) == 0U);
    scan_snapshot_destroy(snapshot);
}

typedef struct FakeOutput {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    pthread_t worker;
    uint8_t latest[4];
    bool open_failure;
    bool write_failure;
    bool gate;
    bool blocked;
    bool closed;
    unsigned int writes;
} FakeOutput;

static bool output_open(void *context, char *warning, size_t size)
{
    FakeOutput *output = context;
    output->worker = pthread_self();
    if (output->open_failure) {
        (void)snprintf(warning, size, "injected open failure");
        return false;
    }
    return true;
}

static bool output_write(void *context, const uint8_t segments[4])
{
    FakeOutput *output = context;
    bool ok;
    assert(pthread_equal(output->worker, pthread_self()));
    assert(pthread_mutex_lock(&output->mutex) == 0);
    while (output->gate) {
        output->blocked = true;
        assert(pthread_cond_broadcast(&output->condition) == 0);
        assert(pthread_cond_wait(&output->condition, &output->mutex) == 0);
    }
    memcpy(output->latest, segments, sizeof(output->latest));
    ++output->writes;
    ok = !output->write_failure;
    assert(pthread_cond_broadcast(&output->condition) == 0);
    assert(pthread_mutex_unlock(&output->mutex) == 0);
    return ok;
}

static void output_close(void *context)
{
    FakeOutput *output = context;
    assert(pthread_equal(output->worker, pthread_self()));
    assert(pthread_mutex_lock(&output->mutex) == 0);
    memset(output->latest, 0, sizeof(output->latest));
    output->closed = true;
    assert(pthread_cond_broadcast(&output->condition) == 0);
    assert(pthread_mutex_unlock(&output->mutex) == 0);
}

static void init_output(FakeOutput *output)
{
    memset(output, 0, sizeof(*output));
    assert(pthread_mutex_init(&output->mutex, NULL) == 0);
    assert(pthread_cond_init(&output->condition, NULL) == 0);
}

static void destroy_output(FakeOutput *output)
{
    assert(output->closed);
    assert(pthread_cond_destroy(&output->condition) == 0);
    assert(pthread_mutex_destroy(&output->mutex) == 0);
}

static DisplayController *create_output(FakeOutput *output, char *warning)
{
    DisplayOutput callbacks = {output, output_open, output_write, output_close};
    return display_controller_create_with_output(&callbacks, warning, 256U);
}

/* Real-time deadlines bound tests even though detector/rules time is injected. */
static struct timespec test_deadline(void)
{
    struct timespec deadline;
    assert(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
    deadline.tv_sec += 5;
    return deadline;
}

static void wait_output(FakeOutput *output, bool blocked, bool closed, const uint8_t *segments)
{
    struct timespec deadline = test_deadline();
    assert(pthread_mutex_lock(&output->mutex) == 0);
    while ((blocked && !output->blocked) || (closed && !output->closed) ||
           (segments != NULL && memcmp(output->latest, segments, 4U) != 0)) {
        assert(pthread_cond_timedwait(&output->condition, &output->mutex, &deadline) == 0);
    }
    assert(pthread_mutex_unlock(&output->mutex) == 0);
}

static void test_events_and_nonblocking_worker(void)
{
    FakeOutput output;
    DisplayController *display;
    RulesEngine *rules = rules_engine_create();
    ScanDetector *detector = scan_detector_create(10U, 20U);
    ScanAlert alert;
    PacketInfo packet = {0};
    Event event;
    char warning[256];
    uint8_t expected[4];
    DisplayCounts counts;
    unsigned int index;

    atomic_store(&test_time, 1000);
    init_output(&output);
    display = create_output(&output, warning);
    assert(display != NULL && warning[0] == '\0');
    assert(display_controller_is_available(display));
    assert(!pthread_equal(output.worker, pthread_self()));
    assert(pthread_mutex_lock(&output.mutex) == 0);
    expect_digits(output.latest, "1000");
    output.gate = true;
    assert(pthread_mutex_unlock(&output.mutex) == 0);

    packet.has_icmp = true;
    packet.icmp_type = 8U;
    assert(rules_engine_evaluate_packet(rules, &packet, &event));
    display_controller_record_event(display, &event);
    wait_output(&output, true, false, NULL);
    /* The hardware worker is deliberately stuck until AFTER all producer calls.
     * A producer waiting for GPIO/worker completion would deadlock this test. */
    for (index = 0U; index < 1004U; ++index) {
        display_controller_record_event(display, &event);
    }
    packet.icmp_type = 0U;
    assert(rules_engine_evaluate_packet(rules, &packet, &event));
    display_controller_record_event(display, &event);
    packet = syn_packet(1U, 22U);
    assert(rules_engine_evaluate_packet(rules, &packet, &event));
    display_controller_record_event(display, &event);
    atomic_store(&test_time, 1005);
    assert(rules_engine_evaluate_packet(rules, &packet, &event));
    assert(event.led_action == LED_ACTION_NONE);
    display_controller_record_event(display, &event);
    atomic_store(&test_time, 1010);
    assert(rules_engine_evaluate_packet(rules, &packet, &event));
    assert(event.led_action == LED_ACTION_NONE); /* Repeated SYN refreshed dedup time. */
    display_controller_record_event(display, &event);
    atomic_store(&test_time, 1016);
    assert(rules_engine_evaluate_packet(rules, &packet, &event));
    display_controller_record_event(display, &event);
    packet.tcp_flags = 0x12U;
    assert(rules_engine_evaluate_packet(rules, &packet, &event));
    display_controller_record_event(display, &event);
    counts = display_controller_counts(display);
    assert(counts.icmp == 1005U && counts.ssh == 2U);

    atomic_store(&test_time, 1000);
    for (index = 1U; index <= 200U; ++index) {
        packet = syn_packet(1U, (uint16_t)index);
        (void)scan_detector_observe_at(detector, &packet, &alert, 1000);
        display_controller_publish_scan(display, detector);
    }
    assert(pthread_mutex_lock(&output.mutex) == 0);
    output.gate = false;
    assert(pthread_cond_broadcast(&output.condition) == 0);
    assert(pthread_mutex_unlock(&output.mutex) == 0);
    tm1637_encode_number(3U, 200U, expected);
    wait_output(&output, false, false, expected);
    /* No packet or snapshot publication: the worker must still age out Type 3. */
    atomic_store(&test_time, 1011);
    tm1637_encode_number(3U, 0U, expected);
    wait_output(&output, false, false, expected);
    counts = display_controller_counts(display);
    assert(counts.icmp == 1005U && counts.ssh == 2U);
    display_controller_destroy(display);
    destroy_output(&output);
    rules_engine_destroy(rules);
    scan_detector_destroy(detector);

    init_output(&output);
    display = create_output(&output, warning);
    counts = display_controller_counts(display);
    assert(counts.icmp == 0U && counts.ssh == 0U);
    display_controller_destroy(display);
    destroy_output(&output);
}

static void test_failures(void)
{
    FakeOutput output;
    DisplayController *display;
    DisplayConfig disabled = {false, "/dev/gpiochip0", 27U, 22U, 3U};
    ScanDetector *detector;
    ScanAlert alert;
    PacketInfo packet = syn_packet(1U, 80U);
    char warning[256];

    display = display_controller_create(&disabled, warning, sizeof(warning));
    assert(display != NULL && !display_controller_is_available(display) && warning[0] == '\0');
    display_controller_destroy(display);
    atomic_store(&fail_calloc, true);
    assert(display_controller_create(&disabled, warning, sizeof(warning)) == NULL);
    assert(warning[0] != '\0');

    disabled.enabled = true;
    disabled.chip_path = "/netmon-test-no-such-gpiochip";
    display = display_controller_create(&disabled, warning, sizeof(warning));
    assert(display != NULL && !display_controller_is_available(display));
    assert(warning[0] != '\0');
    display_controller_destroy(display);

    init_output(&output);
    output.open_failure = true;
    display = create_output(&output, warning);
    assert(display != NULL && !display_controller_is_available(display));
    assert(warning[0] != '\0');
    display_controller_destroy(display);
    destroy_output(&output);

    init_output(&output);
    output.write_failure = true;
    display = create_output(&output, warning);
    assert(!display_controller_is_available(display) && warning[0] != '\0');
    display_controller_destroy(display);
    destroy_output(&output);

    init_output(&output);
    display = create_output(&output, warning);
    assert(pthread_mutex_lock(&output.mutex) == 0);
    output.write_failure = true;
    assert(pthread_mutex_unlock(&output.mutex) == 0);
    {
        Event event = {.kind = EVENT_KIND_ICMP, .led_action = LED_ACTION_SHORT};
        display_controller_record_event(display, &event);
    }
    wait_output(&output, false, true, NULL);
    assert(!display_controller_is_available(display));
    display_controller_destroy(display);
    destroy_output(&output);

    init_output(&output);
    display = create_output(&output, warning);
    detector = scan_detector_create(10U, 20U);
    assert(detector != NULL);
    (void)scan_detector_observe_at(detector, &packet, &alert, 1000);
    atomic_store(&fail_malloc, true);
    display_controller_publish_scan(display, detector);
    assert(!display_controller_is_available(display));
    wait_output(&output, false, true, NULL);
    /* Monitoring state still accepts packets after the display is disabled. */
    packet.dst_port = 81U;
    assert(!scan_detector_observe_at(detector, &packet, &alert, 1000));
    display_controller_destroy(display);
    scan_detector_destroy(detector);
    destroy_output(&output);
    display_controller_destroy(NULL);
}

int main(void)
{
    test_protocol();
    test_scan_and_schedule();
    test_events_and_nonblocking_worker();
    test_failures();
    puts("display_synthetic: all checks passed");
    return 0;
}
