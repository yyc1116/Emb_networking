#ifndef LOGGER_H
#define LOGGER_H

#include <stddef.h>

#include "rules.h"

typedef struct Logger Logger;

Logger *logger_open(const char *path, char *error_buffer, size_t error_buffer_size);
void logger_emit(Logger *logger, const Event *event);
void logger_close(Logger *logger);

#endif
