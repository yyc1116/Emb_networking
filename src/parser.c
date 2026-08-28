#include "parser.h"

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>

static uint16_t read_u16_be(const uint8_t *buffer)
{
    uint16_t value;

    memcpy(&value, buffer, sizeof(value));
    return ntohs(value);
}

static uint32_t read_u32_be(const uint8_t *buffer)
{
    uint32_t value;

    memcpy(&value, buffer, sizeof(value));
    return ntohl(value);
}

void packet_info_reset(PacketInfo *info, size_t captured_length, size_t wire_length)
{
    if (info == NULL) {
        return;
    }

    memset(info, 0, sizeof(*info));
    info->captured_length = captured_length;
    info->wire_length = wire_length;
    info->service_hint = SERVICE_HINT_NONE;
}

static ServiceHint detect_service_hint(uint8_t ip_protocol, uint16_t src_port, uint16_t dst_port)
{
    if (ip_protocol == IPPROTO_TCP) {
        if (dst_port == 22U || src_port == 22U) {
            return SERVICE_HINT_SSH;
        }
        if (dst_port == 80U || src_port == 80U) {
            return SERVICE_HINT_HTTP;
        }
        if (dst_port == 443U || src_port == 443U) {
            return SERVICE_HINT_HTTPS;
        }
    }

    if (ip_protocol == IPPROTO_UDP) {
        if (dst_port == 53U || src_port == 53U) {
            return SERVICE_HINT_DNS;
        }
        if (dst_port == 67U || src_port == 67U || dst_port == 68U || src_port == 68U) {
            return SERVICE_HINT_DHCP;
        }
    }

    return SERVICE_HINT_NONE;
}

static void parse_arp(const uint8_t *buffer, size_t available_length, PacketInfo *info)
{
    struct arphdr arp_header;
    const size_t ethernet_ipv4_arp_payload_size = 20U;
    size_t offset = sizeof(struct arphdr);

    if (available_length < sizeof(struct arphdr)) {
        info->truncated = true;
        return;
    }

    memcpy(&arp_header, buffer, sizeof(arp_header));

    if (ntohs(arp_header.ar_hrd) != ARPHRD_ETHER ||
        ntohs(arp_header.ar_pro) != ETHERTYPE_IP ||
        arp_header.ar_hln != 6U ||
        arp_header.ar_pln != 4U) {
        info->malformed = true;
        return;
    }

    if (available_length < offset + ethernet_ipv4_arp_payload_size) {
        info->truncated = true;
        return;
    }

    info->has_arp = true;
    info->arp_opcode = ntohs(arp_header.ar_op);

    memcpy(info->arp_sender_mac, buffer + offset, 6U);
    offset += 6U;
    memcpy(&info->arp_sender_ipv4, buffer + offset, sizeof(info->arp_sender_ipv4));
    offset += sizeof(info->arp_sender_ipv4);
    memcpy(info->arp_target_mac, buffer + offset, 6U);
    offset += 6U;
    memcpy(&info->arp_target_ipv4, buffer + offset, sizeof(info->arp_target_ipv4));
}

static void parse_icmp(const uint8_t *buffer, size_t available_length, PacketInfo *info)
{
    if (available_length < sizeof(struct icmphdr)) {
        info->truncated = true;
        return;
    }

    info->has_icmp = true;
    info->icmp_type = buffer[0];
    info->icmp_code = buffer[1];
}

static void parse_tcp(const uint8_t *buffer, size_t available_length, PacketInfo *info)
{
    uint8_t header_length;

    if (available_length < sizeof(struct tcphdr)) {
        info->truncated = true;
        return;
    }

    header_length = (uint8_t)((buffer[12] >> 4) * 4U);
    if (header_length < sizeof(struct tcphdr)) {
        info->malformed = true;
        return;
    }

    if (available_length < header_length) {
        info->truncated = true;
        return;
    }

    info->has_ports = true;
    info->has_tcp = true;
    info->src_port = read_u16_be(buffer);
    info->dst_port = read_u16_be(buffer + 2U);
    info->tcp_sequence = read_u32_be(buffer + 4U);
    info->tcp_acknowledgment = read_u32_be(buffer + 8U);
    info->tcp_header_length = header_length;
    info->tcp_flags = buffer[13];
    info->service_hint = detect_service_hint(IPPROTO_TCP, info->src_port, info->dst_port);
}

static void parse_udp(const uint8_t *buffer, size_t available_length, PacketInfo *info)
{
    uint16_t udp_length;

    if (available_length < sizeof(struct udphdr)) {
        info->truncated = true;
        return;
    }

    udp_length = read_u16_be(buffer + 4U);
    if (udp_length < sizeof(struct udphdr)) {
        info->malformed = true;
        return;
    }

    info->has_ports = true;
    info->has_udp = true;
    info->src_port = read_u16_be(buffer);
    info->dst_port = read_u16_be(buffer + 2U);
    info->udp_length = udp_length;
    info->service_hint = detect_service_hint(IPPROTO_UDP, info->src_port, info->dst_port);
}

static void parse_ipv4(const uint8_t *buffer, size_t available_length, PacketInfo *info)
{
    uint8_t version;
    uint8_t ihl_bytes;
    uint16_t fragment_field;
    uint16_t fragment_offset;
    bool more_fragments;
    const uint8_t *transport;
    size_t transport_length;

    if (available_length < sizeof(struct ip)) {
        info->truncated = true;
        return;
    }

    version = (uint8_t)(buffer[0] >> 4);
    ihl_bytes = (uint8_t)((buffer[0] & 0x0FU) * 4U);
    if (version != 4U || ihl_bytes < sizeof(struct ip)) {
        info->malformed = true;
        return;
    }

    if (available_length < ihl_bytes) {
        info->truncated = true;
        return;
    }

    info->has_ipv4 = true;
    info->ipv4_version = version;
    info->ipv4_ihl = ihl_bytes;
    info->ipv4_total_length = read_u16_be(buffer + 2U);
    if (info->ipv4_total_length < ihl_bytes) {
        info->malformed = true;
        return;
    }
    info->ip_protocol = buffer[9];
    memcpy(&info->src_ipv4, buffer + 12U, sizeof(info->src_ipv4));
    memcpy(&info->dst_ipv4, buffer + 16U, sizeof(info->dst_ipv4));

    fragment_field = read_u16_be(buffer + 6U);
    fragment_offset = (uint16_t)(fragment_field & 0x1FFFU);
    more_fragments = (fragment_field & 0x2000U) != 0U;
    info->ipv4_fragmented = more_fragments || fragment_offset != 0U;
    info->ipv4_l4_header_available = (fragment_offset == 0U);

    if (!info->ipv4_l4_header_available) {
        return;
    }

    transport = buffer + ihl_bytes;
    transport_length = available_length - ihl_bytes;

    switch (info->ip_protocol) {
    case IPPROTO_ICMP:
        parse_icmp(transport, transport_length, info);
        break;
    case IPPROTO_TCP:
        parse_tcp(transport, transport_length, info);
        break;
    case IPPROTO_UDP:
        parse_udp(transport, transport_length, info);
        break;
    default:
        break;
    }
}

bool parse_packet(const uint8_t *packet, size_t captured_length, size_t wire_length, PacketInfo *info)
{
    struct ether_header ethernet_header;
    size_t offset = sizeof(struct ether_header);

    if (packet == NULL || info == NULL) {
        return false;
    }

    packet_info_reset(info, captured_length, wire_length);

    if (captured_length < sizeof(struct ether_header)) {
        info->truncated = true;
        return false;
    }

    memcpy(&ethernet_header, packet, sizeof(ethernet_header));
    info->has_ethernet = true;
    memcpy(info->src_mac, ethernet_header.ether_shost, sizeof(info->src_mac));
    memcpy(info->dst_mac, ethernet_header.ether_dhost, sizeof(info->dst_mac));
    info->ether_type = ntohs(ethernet_header.ether_type);

    switch (info->ether_type) {
    case ETHERTYPE_ARP:
        parse_arp(packet + offset, captured_length - offset, info);
        break;
    case ETHERTYPE_IP:
        parse_ipv4(packet + offset, captured_length - offset, info);
        break;
    case ETHERTYPE_IPV6:
        info->is_ipv6_observed = true;
        break;
    default:
        break;
    }

    return !(info->malformed || info->truncated);
}
