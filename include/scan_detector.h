#ifndef SCAN_DETECTOR_H
#define SCAN_DETECTOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "packet_info.h"

typedef struct ScanAlert {
    uint32_t src_ipv4;
    size_t unique_ports;
    unsigned int window_seconds;
} ScanAlert;

typedef struct ScanDetector ScanDetector;
typedef struct ScanSnapshot ScanSnapshot;

ScanDetector *scan_detector_create(unsigned int window_seconds, size_t threshold);
bool scan_detector_observe(ScanDetector *detector, const PacketInfo *packet, ScanAlert *alert);
/* Explicit time keeps window boundaries testable; production uses observe(). */
bool scan_detector_observe_at(ScanDetector *detector, const PacketInfo *packet, ScanAlert *alert, time_t now);
uint64_t scan_detector_revision(const ScanDetector *detector);
/* Call on the detector's owning thread. The returned snapshot is independent. */
ScanSnapshot *scan_detector_snapshot(const ScanDetector *detector);
size_t scan_snapshot_max_ports(const ScanSnapshot *snapshot, time_t now);
void scan_snapshot_destroy(ScanSnapshot *snapshot);
void scan_detector_destroy(ScanDetector *detector);

#endif
