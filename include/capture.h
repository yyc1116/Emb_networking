#ifndef CAPTURE_H
#define CAPTURE_H

#include <stddef.h>
#include <stdint.h>

#include <pcap.h>

typedef struct CaptureHandle CaptureHandle;

typedef void (*CapturePacketCallback)(const struct pcap_pkthdr *header, const uint8_t *packet, void *user_data);

CaptureHandle *capture_open(const char *interface_name, int snaplen, int promiscuous, int timeout_ms, char *error_buffer, size_t error_buffer_size);
int capture_loop(CaptureHandle *handle, CapturePacketCallback callback, void *user_data);
void capture_break(CaptureHandle *handle);
const char *capture_get_error(CaptureHandle *handle);
void capture_close(CaptureHandle *handle);

#endif
