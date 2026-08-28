#include "capture.h"

#include <stdlib.h>
#include <string.h>

struct CaptureHandle {
    pcap_t *pcap_handle;
};

typedef struct CaptureLoopContext {
    CapturePacketCallback callback;
    void *user_data;
} CaptureLoopContext;

static void copy_error(char *destination, size_t destination_size, const char *source)
{
    if (destination == NULL || destination_size == 0U) {
        return;
    }

    if (source == NULL) {
        destination[0] = '\0';
        return;
    }

    strncpy(destination, source, destination_size - 1U);
    destination[destination_size - 1U] = '\0';
}

static void capture_dispatch(u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
{
    CaptureLoopContext *context = (CaptureLoopContext *)user;

    if (context == NULL || context->callback == NULL) {
        return;
    }

    context->callback(header, packet, context->user_data);
}

CaptureHandle *capture_open(const char *interface_name, int snaplen, int promiscuous, int timeout_ms, char *error_buffer, size_t error_buffer_size)
{
    CaptureHandle *handle;
    pcap_t *pcap_handle;
    char pcap_error_buffer[PCAP_ERRBUF_SIZE];

    if (interface_name == NULL) {
        copy_error(error_buffer, error_buffer_size, "interface name is required");
        return NULL;
    }

    pcap_handle = pcap_open_live(interface_name, snaplen, promiscuous, timeout_ms, pcap_error_buffer);
    if (pcap_handle == NULL) {
        copy_error(error_buffer, error_buffer_size, pcap_error_buffer);
        return NULL;
    }

    handle = (CaptureHandle *)calloc(1U, sizeof(*handle));
    if (handle == NULL) {
        copy_error(error_buffer, error_buffer_size, "failed to allocate capture handle");
        pcap_close(pcap_handle);
        return NULL;
    }

    handle->pcap_handle = pcap_handle;
    copy_error(error_buffer, error_buffer_size, "");
    return handle;
}

int capture_loop(CaptureHandle *handle, CapturePacketCallback callback, void *user_data)
{
    CaptureLoopContext context;

    if (handle == NULL || handle->pcap_handle == NULL || callback == NULL) {
        return -1;
    }

    context.callback = callback;
    context.user_data = user_data;

    return pcap_loop(handle->pcap_handle, -1, capture_dispatch, (u_char *)&context);
}

void capture_break(CaptureHandle *handle)
{
    if (handle == NULL || handle->pcap_handle == NULL) {
        return;
    }

    pcap_breakloop(handle->pcap_handle);
}

const char *capture_get_error(CaptureHandle *handle)
{
    if (handle == NULL || handle->pcap_handle == NULL) {
        return "capture handle is not available";
    }

    return pcap_geterr(handle->pcap_handle);
}

void capture_close(CaptureHandle *handle)
{
    if (handle == NULL) {
        return;
    }

    if (handle->pcap_handle != NULL) {
        pcap_close(handle->pcap_handle);
    }

    free(handle);
}
