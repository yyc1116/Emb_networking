#ifndef RULES_H
#define RULES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "gpio_led.h"
#include "packet_info.h"

typedef enum EventSeverity {
    EVENT_SEVERITY_INFO = 0,
    EVENT_SEVERITY_ALERT
} EventSeverity;

typedef enum EventKind {
    EVENT_KIND_NONE = 0,
    EVENT_KIND_ARP,
    EVENT_KIND_IPV6_OBSERVED,
    EVENT_KIND_IPV4_PROTOCOL,
    EVENT_KIND_ICMP,
    EVENT_KIND_TCP,
    EVENT_KIND_UDP,
    EVENT_KIND_PORT_SCAN
} EventKind;

typedef struct Event {
    EventKind kind;
    EventSeverity severity;
    bool should_print;
    bool should_log;
    LedAction led_action;
    PacketInfo packet;
    size_t scan_unique_ports;
    unsigned int scan_window_seconds;
} Event;

bool rules_evaluate_packet(const PacketInfo *packet, Event *event);
void rules_make_scan_alert(uint32_t src_ipv4, size_t unique_ports, unsigned int window_seconds, Event *event);

#endif
