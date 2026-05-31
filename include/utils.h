#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>
#include <stdint.h>

int hex_to_bytes(const char *hex, uint8_t **bytes, size_t *length);
void bytes_to_hex(const uint8_t *bytes, size_t length, char *hex);

#endif
