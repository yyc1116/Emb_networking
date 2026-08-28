#include "rules.h"

#include <net/if_arp.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <string.h>

static void clear_event(Event *event)
{
    memset(event, 0, sizeof(*event));
}

static void init_event_from_packet(const PacketInfo *packet, Event *event, EventKind kind, EventSeverity severity, LedAction led_action)
{
    clear_event(event);
    event->kind = kind;
    event->severity = severity;
    event->should_print = true;
    event->should_log = true;
    event->led_action = led_action;
    event->packet = *packet;
}

bool rules_evaluate_packet(const PacketInfo *packet, Event *event)
{
    if (packet == NULL || event == NULL) {
        return false;
    }

    clear_event(event);

    if (packet->malformed || packet->truncated) {
        return false;
    }

    if (packet->has_arp) {
        init_event_from_packet(packet, event, EVENT_KIND_ARP, EVENT_SEVERITY_INFO, LED_ACTION_NONE);
        return true;
    }

    if (packet->is_ipv6_observed) {
        init_event_from_packet(packet, event, EVENT_KIND_IPV6_OBSERVED, EVENT_SEVERITY_INFO, LED_ACTION_NONE);
        return true;
    }

    if (packet->has_icmp) {
        if (packet->icmp_type == ICMP_ECHO) {
            init_event_from_packet(packet, event, EVENT_KIND_ICMP, EVENT_SEVERITY_INFO, LED_ACTION_SHORT);
            return true;
        }

        init_event_from_packet(packet, event, EVENT_KIND_ICMP, EVENT_SEVERITY_INFO, LED_ACTION_NONE);
        return true;
    }

    if (packet->has_tcp) {
        if (packet->dst_port == 22U &&
            (packet->tcp_flags & TH_SYN) != 0U &&
            (packet->tcp_flags & TH_ACK) == 0U) {
            init_event_from_packet(packet, event, EVENT_KIND_TCP, EVENT_SEVERITY_ALERT, LED_ACTION_LONG);
            return true;
        }

        init_event_from_packet(packet, event, EVENT_KIND_TCP, EVENT_SEVERITY_INFO, LED_ACTION_NONE);
        return true;
    }

    if (packet->has_udp) {
        init_event_from_packet(packet, event, EVENT_KIND_UDP, EVENT_SEVERITY_INFO, LED_ACTION_NONE);
        return true;
    }

    if (packet->has_ipv4) {
        init_event_from_packet(packet, event, EVENT_KIND_IPV4_PROTOCOL, EVENT_SEVERITY_INFO, LED_ACTION_NONE);
        return true;
    }

    return false;
}

void rules_make_scan_alert(uint32_t src_ipv4, size_t unique_ports, unsigned int window_seconds, Event *event)
{
    PacketInfo packet;

    if (event == NULL) {
        return;
    }

    packet_info_reset(&packet, 0U, 0U);
    packet.has_ipv4 = true;
    packet.src_ipv4 = src_ipv4;

    clear_event(event);
    event->kind = EVENT_KIND_PORT_SCAN;
    event->severity = EVENT_SEVERITY_ALERT;
    event->should_print = true;
    event->should_log = true;
    event->led_action = LED_ACTION_RAPID;
    event->packet = packet;
    event->scan_unique_ports = unique_ports;
    event->scan_window_seconds = window_seconds;
}
