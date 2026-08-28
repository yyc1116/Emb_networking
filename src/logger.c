#include "logger.h"

#include <arpa/inet.h>
#include <net/if_arp.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct Logger {
    FILE *log_file;
};

static const char *severity_name(EventSeverity severity)
{
    return (severity == EVENT_SEVERITY_ALERT) ? "ALERT" : "INFO";
}

static const char *service_hint_name(ServiceHint hint)
{
    switch (hint) {
    case SERVICE_HINT_SSH:
        return "SSH";
    case SERVICE_HINT_HTTP:
        return "HTTP";
    case SERVICE_HINT_HTTPS:
        return "HTTPS";
    case SERVICE_HINT_DNS:
        return "DNS";
    case SERVICE_HINT_DHCP:
        return "DHCP";
    default:
        return NULL;
    }
}

static void format_mac(const uint8_t mac[6], char *buffer, size_t buffer_size)
{
    (void)snprintf(buffer, buffer_size,
                   "%02x:%02x:%02x:%02x:%02x:%02x",
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void format_ipv4(uint32_t ipv4_network_order, char *buffer, size_t buffer_size)
{
    struct in_addr address;

    /* PacketInfo keeps IPv4 addresses in network byte order, matching packet layout. */
    address.s_addr = ipv4_network_order;
    if (inet_ntop(AF_INET, &address, buffer, (socklen_t)buffer_size) == NULL) {
        strncpy(buffer, "0.0.0.0", buffer_size - 1U);
        buffer[buffer_size - 1U] = '\0';
    }
}

static void format_tcp_flags(uint8_t flags, char *buffer, size_t buffer_size)
{
    size_t written = 0U;

    /* Only show the flags this prototype cares about in logs and demos. */
    buffer[0] = '\0';

    if ((flags & 0x02U) != 0U) {
        written += (size_t)snprintf(buffer + written, buffer_size - written, "%sSYN", (written == 0U) ? "" : ",");
    }
    if ((flags & 0x10U) != 0U && written < buffer_size) {
        written += (size_t)snprintf(buffer + written, buffer_size - written, "%sACK", (written == 0U) ? "" : ",");
    }
    if ((flags & 0x01U) != 0U && written < buffer_size) {
        written += (size_t)snprintf(buffer + written, buffer_size - written, "%sFIN", (written == 0U) ? "" : ",");
    }
    if ((flags & 0x04U) != 0U && written < buffer_size) {
        written += (size_t)snprintf(buffer + written, buffer_size - written, "%sRST", (written == 0U) ? "" : ",");
    }
    if (written == 0U) {
        strncpy(buffer, "NONE", buffer_size - 1U);
        buffer[buffer_size - 1U] = '\0';
    }
}

static void format_timestamp(char *buffer, size_t buffer_size)
{
    time_t now;
    struct tm local_time;
    char raw_buffer[32];
    size_t raw_length;

    /* Log timestamps are ISO-8601-like so shell tools can still parse them comfortably. */
    now = time(NULL);
    if (now == (time_t)-1) {
        strncpy(buffer, "1970-01-01T00:00:00+00:00", buffer_size - 1U);
        buffer[buffer_size - 1U] = '\0';
        return;
    }

#if defined(_WIN32)
    localtime_s(&local_time, &now);
#else
    localtime_r(&now, &local_time);
#endif

    if (strftime(raw_buffer, sizeof(raw_buffer), "%Y-%m-%dT%H:%M:%S%z", &local_time) == 0U) {
        strncpy(buffer, "1970-01-01T00:00:00+00:00", buffer_size - 1U);
        buffer[buffer_size - 1U] = '\0';
        return;
    }

    raw_length = strlen(raw_buffer);
    if (raw_length >= 5U) {
        raw_buffer[raw_length + 1U] = '\0';
        raw_buffer[raw_length] = raw_buffer[raw_length - 1U];
        raw_buffer[raw_length - 1U] = raw_buffer[raw_length - 2U];
        raw_buffer[raw_length - 2U] = ':';
    }

    strncpy(buffer, raw_buffer, buffer_size - 1U);
    buffer[buffer_size - 1U] = '\0';
}

static void build_terminal_message(const Event *event, char *buffer, size_t buffer_size)
{
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    char sender_ip[INET_ADDRSTRLEN];
    char target_ip[INET_ADDRSTRLEN];
    char mac[18];
    char flags[32];
    const PacketInfo *packet = &event->packet;
    const char *hint = service_hint_name(packet->service_hint);

    src_ip[0] = '\0';
    dst_ip[0] = '\0';
    sender_ip[0] = '\0';
    target_ip[0] = '\0';
    mac[0] = '\0';
    flags[0] = '\0';

    /* Terminal output is optimized for quick reading during live demos. */
    switch (event->kind) {
    case EVENT_KIND_ARP:
        format_ipv4(packet->arp_sender_ipv4, sender_ip, sizeof(sender_ip));
        format_ipv4(packet->arp_target_ipv4, target_ip, sizeof(target_ip));
        if (packet->arp_opcode == ARPOP_REQUEST) {
            (void)snprintf(buffer, buffer_size, "ARP REQUEST %s asks for %s", sender_ip, target_ip);
            return;
        }
        if (packet->arp_opcode == ARPOP_REPLY) {
            format_mac(packet->arp_sender_mac, mac, sizeof(mac));
            (void)snprintf(buffer, buffer_size, "ARP REPLY %s is-at %s", sender_ip, mac);
            return;
        }
        (void)snprintf(buffer, buffer_size, "ARP OPCODE=%u %s -> %s", packet->arp_opcode, sender_ip, target_ip);
        return;
    case EVENT_KIND_IPV6_OBSERVED:
        (void)snprintf(buffer, buffer_size, "IPv6 packet observed");
        return;
    case EVENT_KIND_IPV4_PROTOCOL:
        format_ipv4(packet->src_ipv4, src_ip, sizeof(src_ip));
        format_ipv4(packet->dst_ipv4, dst_ip, sizeof(dst_ip));
        if (packet->ipv4_fragmented && !packet->ipv4_l4_header_available) {
            (void)snprintf(buffer, buffer_size, "IPv4 fragmented packet %s -> %s PROTOCOL=%u", src_ip, dst_ip, packet->ip_protocol);
            return;
        }
        (void)snprintf(buffer, buffer_size, "IPv4 %s -> %s PROTOCOL=%u", src_ip, dst_ip, packet->ip_protocol);
        return;
    case EVENT_KIND_ICMP:
        format_ipv4(packet->src_ipv4, src_ip, sizeof(src_ip));
        format_ipv4(packet->dst_ipv4, dst_ip, sizeof(dst_ip));
        if (packet->icmp_type == ICMP_ECHO) {
            (void)snprintf(buffer, buffer_size, "ICMP Echo Request %s -> %s", src_ip, dst_ip);
            return;
        }
        if (packet->icmp_type == ICMP_ECHOREPLY) {
            (void)snprintf(buffer, buffer_size, "ICMP Echo Reply %s -> %s", src_ip, dst_ip);
            return;
        }
        (void)snprintf(buffer, buffer_size, "ICMP TYPE=%u CODE=%u %s -> %s", packet->icmp_type, packet->icmp_code, src_ip, dst_ip);
        return;
    case EVENT_KIND_TCP:
        format_ipv4(packet->src_ipv4, src_ip, sizeof(src_ip));
        format_ipv4(packet->dst_ipv4, dst_ip, sizeof(dst_ip));
        format_tcp_flags(packet->tcp_flags, flags, sizeof(flags));
        if (hint != NULL) {
            (void)snprintf(buffer, buffer_size, "TCP %s:%u -> %s:%u FLAGS=%s SERVICE_HINT=%s", src_ip, packet->src_port, dst_ip, packet->dst_port, flags, hint);
            return;
        }
        (void)snprintf(buffer, buffer_size, "TCP %s:%u -> %s:%u FLAGS=%s", src_ip, packet->src_port, dst_ip, packet->dst_port, flags);
        return;
    case EVENT_KIND_UDP:
        format_ipv4(packet->src_ipv4, src_ip, sizeof(src_ip));
        format_ipv4(packet->dst_ipv4, dst_ip, sizeof(dst_ip));
        if (hint != NULL) {
            (void)snprintf(buffer, buffer_size, "UDP %s:%u -> %s:%u SERVICE_HINT=%s", src_ip, packet->src_port, dst_ip, packet->dst_port, hint);
            return;
        }
        (void)snprintf(buffer, buffer_size, "UDP %s:%u -> %s:%u", src_ip, packet->src_port, dst_ip, packet->dst_port);
        return;
    case EVENT_KIND_PORT_SCAN:
        format_ipv4(packet->src_ipv4, src_ip, sizeof(src_ip));
        (void)snprintf(buffer, buffer_size, "Possible port scan SRC=%s UNIQUE_PORTS=%zu WINDOW=%us", src_ip, event->scan_unique_ports, event->scan_window_seconds);
        return;
    default:
        break;
    }

    strncpy(buffer, "Unknown event", buffer_size - 1U);
    buffer[buffer_size - 1U] = '\0';
}

static void build_log_message(const Event *event, char *buffer, size_t buffer_size)
{
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    char sender_ip[INET_ADDRSTRLEN];
    char target_ip[INET_ADDRSTRLEN];
    char sender_mac[18];
    char flags[32];
    const PacketInfo *packet = &event->packet;
    const char *hint = service_hint_name(packet->service_hint);

    src_ip[0] = '\0';
    dst_ip[0] = '\0';
    sender_ip[0] = '\0';
    target_ip[0] = '\0';
    sender_mac[0] = '\0';
    flags[0] = '\0';

    /* Log output is flatter and more key-value shaped for grep/awk usage. */
    switch (event->kind) {
    case EVENT_KIND_ARP:
        format_ipv4(packet->arp_sender_ipv4, sender_ip, sizeof(sender_ip));
        format_ipv4(packet->arp_target_ipv4, target_ip, sizeof(target_ip));
        format_mac(packet->arp_sender_mac, sender_mac, sizeof(sender_mac));
        (void)snprintf(buffer, buffer_size, "ARP OPCODE=%u SRC=%s SMAC=%s TARGET=%s", packet->arp_opcode, sender_ip, sender_mac, target_ip);
        return;
    case EVENT_KIND_IPV6_OBSERVED:
        (void)snprintf(buffer, buffer_size, "IPV6 OBSERVED");
        return;
    case EVENT_KIND_IPV4_PROTOCOL:
        format_ipv4(packet->src_ipv4, src_ip, sizeof(src_ip));
        format_ipv4(packet->dst_ipv4, dst_ip, sizeof(dst_ip));
        (void)snprintf(buffer, buffer_size, "IPV4 SRC=%s DST=%s PROTOCOL=%u FRAGMENTED=%s", src_ip, dst_ip, packet->ip_protocol, packet->ipv4_fragmented ? "YES" : "NO");
        return;
    case EVENT_KIND_ICMP:
        format_ipv4(packet->src_ipv4, src_ip, sizeof(src_ip));
        format_ipv4(packet->dst_ipv4, dst_ip, sizeof(dst_ip));
        (void)snprintf(buffer, buffer_size, "ICMP SRC=%s DST=%s TYPE=%u CODE=%u", src_ip, dst_ip, packet->icmp_type, packet->icmp_code);
        return;
    case EVENT_KIND_TCP:
        format_ipv4(packet->src_ipv4, src_ip, sizeof(src_ip));
        format_ipv4(packet->dst_ipv4, dst_ip, sizeof(dst_ip));
        format_tcp_flags(packet->tcp_flags, flags, sizeof(flags));
        if (hint != NULL) {
            (void)snprintf(buffer, buffer_size,
                           "TCP SRC=%s SPORT=%u DST=%s DPORT=%u FLAGS=%s SEQ=%u ACKNUM=%u HLEN=%u SERVICE_HINT=%s",
                           src_ip, packet->src_port, dst_ip, packet->dst_port, flags,
                           packet->tcp_sequence, packet->tcp_acknowledgment, packet->tcp_header_length, hint);
            return;
        }
        (void)snprintf(buffer, buffer_size,
                       "TCP SRC=%s SPORT=%u DST=%s DPORT=%u FLAGS=%s SEQ=%u ACKNUM=%u HLEN=%u",
                       src_ip, packet->src_port, dst_ip, packet->dst_port, flags,
                       packet->tcp_sequence, packet->tcp_acknowledgment, packet->tcp_header_length);
        return;
    case EVENT_KIND_UDP:
        format_ipv4(packet->src_ipv4, src_ip, sizeof(src_ip));
        format_ipv4(packet->dst_ipv4, dst_ip, sizeof(dst_ip));
        if (hint != NULL) {
            (void)snprintf(buffer, buffer_size,
                           "UDP SRC=%s SPORT=%u DST=%s DPORT=%u LEN=%u SERVICE_HINT=%s",
                           src_ip, packet->src_port, dst_ip, packet->dst_port, packet->udp_length, hint);
            return;
        }
        (void)snprintf(buffer, buffer_size,
                       "UDP SRC=%s SPORT=%u DST=%s DPORT=%u LEN=%u",
                       src_ip, packet->src_port, dst_ip, packet->dst_port, packet->udp_length);
        return;
    case EVENT_KIND_PORT_SCAN:
        format_ipv4(packet->src_ipv4, src_ip, sizeof(src_ip));
        (void)snprintf(buffer, buffer_size, "PORT_SCAN SRC=%s UNIQUE_PORTS=%zu WINDOW=%us", src_ip, event->scan_unique_ports, event->scan_window_seconds);
        return;
    default:
        break;
    }

    strncpy(buffer, "UNKNOWN", buffer_size - 1U);
    buffer[buffer_size - 1U] = '\0';
}

Logger *logger_open(const char *path, char *error_buffer, size_t error_buffer_size)
{
    Logger *logger;

    if (path == NULL) {
        if (error_buffer != NULL && error_buffer_size > 0U) {
            strncpy(error_buffer, "log path is required", error_buffer_size - 1U);
            error_buffer[error_buffer_size - 1U] = '\0';
        }
        return NULL;
    }

    logger = (Logger *)calloc(1U, sizeof(*logger));
    if (logger == NULL) {
        if (error_buffer != NULL && error_buffer_size > 0U) {
            strncpy(error_buffer, "failed to allocate logger", error_buffer_size - 1U);
            error_buffer[error_buffer_size - 1U] = '\0';
        }
        return NULL;
    }

    logger->log_file = fopen(path, "a");
    if (logger->log_file == NULL) {
        if (error_buffer != NULL && error_buffer_size > 0U) {
            (void)snprintf(error_buffer, error_buffer_size, "failed to open log file: %s", path);
        }
        free(logger);
        return NULL;
    }

    if (error_buffer != NULL && error_buffer_size > 0U) {
        error_buffer[0] = '\0';
    }

    return logger;
}

void logger_emit(Logger *logger, const Event *event)
{
    char terminal_message[512];
    char log_message[512];
    char timestamp[40];

    if (logger == NULL || event == NULL) {
        return;
    }

    /* One event fan-outs into human-readable terminal output and structured log output. */
    build_terminal_message(event, terminal_message, sizeof(terminal_message));
    build_log_message(event, log_message, sizeof(log_message));

    if (event->should_print) {
        (void)printf("[%-5s] %s\n", severity_name(event->severity), terminal_message);
        (void)fflush(stdout);
    }

    if (event->should_log && logger->log_file != NULL) {
        format_timestamp(timestamp, sizeof(timestamp));
        (void)fprintf(logger->log_file, "%s %s %s\n", timestamp, severity_name(event->severity), log_message);
        (void)fflush(logger->log_file);
    }
}

void logger_close(Logger *logger)
{
    if (logger == NULL) {
        return;
    }

    if (logger->log_file != NULL) {
        fclose(logger->log_file);
    }

    free(logger);
}
