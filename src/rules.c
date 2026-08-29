#include "rules.h"

#include <net/if_arp.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SSH_ALERT_DEDUP_SECONDS 5U

typedef struct SshAttemptEntry {
    uint32_t src_ipv4;
    uint32_t dst_ipv4;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t tcp_sequence;
    time_t seen_at;
    struct SshAttemptEntry *next;
} SshAttemptEntry;

struct RulesEngine {
    SshAttemptEntry *ssh_attempts;
};

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

static void prune_ssh_attempts(RulesEngine *engine, time_t now)
{
    SshAttemptEntry *current;
    SshAttemptEntry *previous;
    SshAttemptEntry *next;

    if (engine == NULL) {
        return;
    }

    previous = NULL;
    current = engine->ssh_attempts;

    while (current != NULL) {
        next = current->next;
        if ((unsigned int)difftime(now, current->seen_at) > SSH_ALERT_DEDUP_SECONDS) {
            if (previous == NULL) {
                engine->ssh_attempts = next;
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

static bool is_ssh_initial_syn(const PacketInfo *packet)
{
    return packet->dst_port == 22U &&
           (packet->tcp_flags & TH_SYN) != 0U &&
           (packet->tcp_flags & TH_ACK) == 0U;
}

static bool ssh_alert_should_escalate(RulesEngine *engine, const PacketInfo *packet)
{
    SshAttemptEntry *current;
    SshAttemptEntry *entry;
    time_t now;

    if (engine == NULL || packet == NULL) {
        return true;
    }

    now = time(NULL);
    if (now == (time_t)-1) {
        return true;
    }

    prune_ssh_attempts(engine, now);

    current = engine->ssh_attempts;
    while (current != NULL) {
        if (current->src_ipv4 == packet->src_ipv4 &&
            current->dst_ipv4 == packet->dst_ipv4 &&
            current->src_port == packet->src_port &&
            current->dst_port == packet->dst_port &&
            current->tcp_sequence == packet->tcp_sequence) {
            current->seen_at = now;
            return false;
        }
        current = current->next;
    }

    entry = (SshAttemptEntry *)calloc(1U, sizeof(*entry));
    if (entry == NULL) {
        /* If tracking allocation fails, keep the alert rather than missing it. */
        return true;
    }

    entry->src_ipv4 = packet->src_ipv4;
    entry->dst_ipv4 = packet->dst_ipv4;
    entry->src_port = packet->src_port;
    entry->dst_port = packet->dst_port;
    entry->tcp_sequence = packet->tcp_sequence;
    entry->seen_at = now;
    entry->next = engine->ssh_attempts;
    engine->ssh_attempts = entry;
    return true;
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
        if (is_ssh_initial_syn(packet)) {
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

RulesEngine *rules_engine_create(void)
{
    return (RulesEngine *)calloc(1U, sizeof(RulesEngine));
}

void rules_engine_destroy(RulesEngine *engine)
{
    SshAttemptEntry *current;
    SshAttemptEntry *next;

    if (engine == NULL) {
        return;
    }

    current = engine->ssh_attempts;
    while (current != NULL) {
        next = current->next;
        free(current);
        current = next;
    }

    free(engine);
}

bool rules_engine_evaluate_packet(RulesEngine *engine, const PacketInfo *packet, Event *event)
{
    if (!rules_evaluate_packet(packet, event)) {
        return false;
    }

    if (packet != NULL &&
        event != NULL &&
        event->kind == EVENT_KIND_TCP &&
        event->severity == EVENT_SEVERITY_ALERT &&
        is_ssh_initial_syn(packet) &&
        !ssh_alert_should_escalate(engine, packet)) {
        init_event_from_packet(packet, event, EVENT_KIND_TCP, EVENT_SEVERITY_INFO, LED_ACTION_NONE);
    }

    return true;
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
