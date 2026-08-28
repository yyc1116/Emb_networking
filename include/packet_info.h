#ifndef PACKET_INFO_H
#define PACKET_INFO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum ServiceHint {
    SERVICE_HINT_NONE = 0,
    SERVICE_HINT_SSH,
    SERVICE_HINT_HTTP,
    SERVICE_HINT_HTTPS,
    SERVICE_HINT_DNS,
    SERVICE_HINT_DHCP
} ServiceHint;

typedef struct PacketInfo {
    size_t captured_length;
    size_t wire_length;

    bool has_ethernet;
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    uint16_t ether_type;

    bool is_ipv6_observed;

    bool has_arp;
    uint16_t arp_opcode;
    uint8_t arp_sender_mac[6];
    uint8_t arp_target_mac[6];
    uint32_t arp_sender_ipv4;
    uint32_t arp_target_ipv4;

    bool has_ipv4;
    uint8_t ipv4_version;
    uint8_t ipv4_ihl;
    uint16_t ipv4_total_length;
    uint8_t ip_protocol;
    uint32_t src_ipv4;
    uint32_t dst_ipv4;
    bool ipv4_fragmented;
    bool ipv4_l4_header_available;

    bool has_icmp;
    uint8_t icmp_type;
    uint8_t icmp_code;

    bool has_ports;
    uint16_t src_port;
    uint16_t dst_port;

    bool has_tcp;
    uint32_t tcp_sequence;
    uint32_t tcp_acknowledgment;
    uint8_t tcp_header_length;
    uint8_t tcp_flags;

    bool has_udp;
    uint16_t udp_length;

    ServiceHint service_hint;

    bool malformed;
    bool truncated;
} PacketInfo;

void packet_info_reset(PacketInfo *info, size_t captured_length, size_t wire_length);

#endif
