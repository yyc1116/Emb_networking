#ifndef SCAN_DETECTOR_H
#define SCAN_DETECTOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "packet_info.h"

typedef struct ScanAlert {
    uint32_t src_ipv4;
    size_t unique_ports;
    unsigned int window_seconds;
} ScanAlert;

typedef struct ScanDetector ScanDetector;

ScanDetector *scan_detector_create(unsigned int window_seconds, size_t threshold);
bool scan_detector_observe(ScanDetector *detector, const PacketInfo *packet, ScanAlert *alert);
void scan_detector_destroy(ScanDetector *detector);

#endif
