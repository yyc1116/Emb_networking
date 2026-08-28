#ifndef PARSER_H
#define PARSER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "packet_info.h"

bool parse_packet(const uint8_t *packet, size_t captured_length, size_t wire_length, PacketInfo *info);

#endif
