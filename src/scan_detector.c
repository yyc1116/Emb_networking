#include "scan_detector.h"

#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct PortEntry {
    /* Each unique destination port seen from the same source within the time window. */
    uint16_t port;
    time_t seen_at;
    struct PortEntry *next;
} PortEntry;

typedef struct SourceEntry {
    /* Per-source state used to decide whether many ports were touched quickly. */
    uint32_t src_ipv4;
    time_t last_seen_at;
    time_t last_alert_at;
    PortEntry *ports;
    struct SourceEntry *next;
} SourceEntry;

struct ScanDetector {
    /* Simple linked-list state is enough for the small prototype scope. */
    unsigned int window_seconds;
    size_t threshold;
    SourceEntry *sources;
    uint64_t revision;
};

typedef struct SnapshotPort {
    uint32_t src_ipv4;
    time_t seen_at;
} SnapshotPort;

struct ScanSnapshot {
    unsigned int window_seconds;
    size_t port_count;
    /* Entries from each source are contiguous, including refreshed timestamps. */
    SnapshotPort ports[];
};

static bool outside_window(time_t now, time_t seen_at, unsigned int window_seconds)
{
    /* Match the existing detector, including its strict > boundary. */
    return (unsigned int)difftime(now, seen_at) > window_seconds;
}

static void free_ports(PortEntry *ports)
{
    PortEntry *next_port;

    while (ports != NULL) {
        next_port = ports->next;
        free(ports);
        ports = next_port;
    }
}

static void prune_ports(SourceEntry *source, time_t now, unsigned int window_seconds)
{
    PortEntry *current;
    PortEntry *previous;
    PortEntry *next;

    if (source == NULL) {
        return;
    }

    previous = NULL;
    current = source->ports;

    while (current != NULL) {
        next = current->next;
        /* Ports outside the window should stop contributing to scan counts. */
        if (outside_window(now, current->seen_at, window_seconds)) {
            if (previous == NULL) {
                source->ports = next;
            } else {
                previous->next = next;
            }
            free(current);
        } else {
            previous = current;
        }
        current = next;
    }
}

static size_t count_ports(const PortEntry *ports)
{
    size_t count = 0U;

    while (ports != NULL) {
        ++count;
        ports = ports->next;
    }

    return count;
}

static SourceEntry *find_or_create_source(ScanDetector *detector, uint32_t src_ipv4)
{
    SourceEntry *source = detector->sources;

    while (source != NULL) {
        if (source->src_ipv4 == src_ipv4) {
            return source;
        }
        source = source->next;
    }

    /* New source IP, start a fresh tracking bucket for it. */
    source = (SourceEntry *)calloc(1U, sizeof(*source));
    if (source == NULL) {
        return NULL;
    }

    source->src_ipv4 = src_ipv4;
    source->next = detector->sources;
    detector->sources = source;
    return source;
}

static bool upsert_port(SourceEntry *source, uint16_t port, time_t now)
{
    PortEntry *current = source->ports;
    PortEntry *entry;

    while (current != NULL) {
        if (current->port == port) {
            /* Re-touching the same port refreshes its timestamp but does not grow the set. */
            current->seen_at = now;
            return true;
        }
        current = current->next;
    }

    entry = (PortEntry *)calloc(1U, sizeof(*entry));
    if (entry == NULL) {
        return false;
    }

    entry->port = port;
    entry->seen_at = now;
    entry->next = source->ports;
    source->ports = entry;
    return true;
}

static void prune_sources(ScanDetector *detector, time_t now)
{
    SourceEntry *current = detector->sources;
    SourceEntry *previous = NULL;
    SourceEntry *next;

    while (current != NULL) {
        next = current->next;
        prune_ports(current, now, detector->window_seconds);
        /* Drop fully idle source buckets to keep memory bounded over long runs. */
        if (current->ports == NULL &&
            (unsigned int)difftime(now, current->last_seen_at) > detector->window_seconds &&
            (unsigned int)difftime(now, current->last_alert_at) > detector->window_seconds) {
            if (previous == NULL) {
                detector->sources = next;
            } else {
                previous->next = next;
            }
            free(current);
        } else {
            previous = current;
        }
        current = next;
    }
}

ScanDetector *scan_detector_create(unsigned int window_seconds, size_t threshold)
{
    ScanDetector *detector;

    detector = (ScanDetector *)calloc(1U, sizeof(*detector));
    if (detector == NULL) {
        return NULL;
    }

    detector->window_seconds = (window_seconds == 0U) ? 10U : window_seconds;
    detector->threshold = (threshold == 0U) ? 20U : threshold;
    return detector;
}

bool scan_detector_observe(ScanDetector *detector, const PacketInfo *packet, ScanAlert *alert)
{
    /* Preserve the original fast path: unrelated packets do not even read time. */
    if (detector == NULL || packet == NULL || alert == NULL ||
        !packet->has_ipv4 || !packet->has_tcp || !packet->has_ports ||
        (packet->tcp_flags & TH_SYN) == 0U || (packet->tcp_flags & TH_ACK) != 0U) {
        return false;
    }
    return scan_detector_observe_at(detector, packet, alert, time(NULL));
}

bool scan_detector_observe_at(ScanDetector *detector, const PacketInfo *packet, ScanAlert *alert, time_t now)
{
    SourceEntry *source;
    size_t unique_ports;

    if (detector == NULL || packet == NULL || alert == NULL) {
        return false;
    }

    /* The spec defines a scan as many TCP initial SYNs from one source. */
    if (!packet->has_ipv4 || !packet->has_tcp || !packet->has_ports) {
        return false;
    }

    if ((packet->tcp_flags & TH_SYN) == 0U || (packet->tcp_flags & TH_ACK) != 0U) {
        return false;
    }

    if (now == (time_t)-1) {
        return false;
    }

    ++detector->revision;
    prune_sources(detector, now);

    source = find_or_create_source(detector, packet->src_ipv4);
    if (source == NULL) {
        return false;
    }

    source->last_seen_at = now;
    prune_ports(source, now, detector->window_seconds);
    if (!upsert_port(source, packet->dst_port, now)) {
        return false;
    }

    unique_ports = count_ports(source->ports);
    if (unique_ports < detector->threshold) {
        return false;
    }

    /* Cooldown prevents one ongoing scan from raising an alert on every packet. */
    if ((unsigned int)difftime(now, source->last_alert_at) <= detector->window_seconds) {
        return false;
    }

    source->last_alert_at = now;
    alert->src_ipv4 = packet->src_ipv4;
    alert->unique_ports = unique_ports;
    alert->window_seconds = detector->window_seconds;
    return true;
}

uint64_t scan_detector_revision(const ScanDetector *detector)
{
    return detector == NULL ? 0U : detector->revision;
}

ScanSnapshot *scan_detector_snapshot(const ScanDetector *detector)
{
    const SourceEntry *source;
    const PortEntry *port;
    ScanSnapshot *snapshot;
    size_t count = 0U;
    size_t index = 0U;
    const size_t capacity = (SIZE_MAX - sizeof(ScanSnapshot)) / sizeof(SnapshotPort);

    if (detector == NULL) {
        return NULL;
    }
    for (source = detector->sources; source != NULL; source = source->next) {
        for (port = source->ports; port != NULL; port = port->next) {
            if (count == capacity) {
                return NULL;
            }
            ++count;
        }
    }
    snapshot = malloc(sizeof(*snapshot) + count * sizeof(snapshot->ports[0]));
    if (snapshot == NULL) {
        return NULL;
    }
    snapshot->window_seconds = detector->window_seconds;
    snapshot->port_count = count;
    for (source = detector->sources; source != NULL; source = source->next) {
        for (port = source->ports; port != NULL; port = port->next) {
            snapshot->ports[index].src_ipv4 = source->src_ipv4;
            snapshot->ports[index++].seen_at = port->seen_at;
        }
    }
    return snapshot;
}

size_t scan_snapshot_max_ports(const ScanSnapshot *snapshot, time_t now)
{
    size_t maximum = 0U;
    size_t count = 0U;
    size_t index;

    if (snapshot == NULL || now == (time_t)-1) {
        return 0U;
    }
    for (index = 0U; index < snapshot->port_count; ++index) {
        if (index == 0U || snapshot->ports[index].src_ipv4 != snapshot->ports[index - 1U].src_ipv4) {
            count = 0U;
        }
        if (!outside_window(now, snapshot->ports[index].seen_at, snapshot->window_seconds)) {
            ++count;
            if (count > maximum) {
                maximum = count;
            }
        }
    }
    return maximum;
}

void scan_snapshot_destroy(ScanSnapshot *snapshot)
{
    free(snapshot);
}

void scan_detector_destroy(ScanDetector *detector)
{
    SourceEntry *current;
    SourceEntry *next;

    if (detector == NULL) {
        return;
    }

    current = detector->sources;
    while (current != NULL) {
        next = current->next;
        free_ports(current->ports);
        free(current);
        current = next;
    }

    free(detector);
}
