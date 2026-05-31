#include "utils.h"

#include <ctype.h>
#include <stdlib.h>

static int hex_value(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

int hex_to_bytes(const char *hex, uint8_t **bytes, size_t *length) {
    size_t hex_len;
    size_t i;
    uint8_t *buffer;

    if (hex == NULL || bytes == NULL || length == NULL) {
        return -1;
    }

    hex_len = 0U;
    while (hex[hex_len] != '\0') {
        if (!isxdigit((unsigned char)hex[hex_len])) {
            return -1;
        }
        ++hex_len;
    }

    if ((hex_len % 2U) != 0U) {
        return -1;
    }

    buffer = (uint8_t *)malloc(hex_len / 2U);
    if (buffer == NULL && hex_len != 0U) {
        return -1;
    }

    for (i = 0; i < hex_len; i += 2U) {
        int high = hex_value(hex[i]);
        int low = hex_value(hex[i + 1U]);
        if (high < 0 || low < 0) {
            free(buffer);
            return -1;
        }
        buffer[i / 2U] = (uint8_t)((high << 4) | low);
    }

    *bytes = buffer;
    *length = hex_len / 2U;
    return 0;
}

void bytes_to_hex(const uint8_t *bytes, size_t length, char *hex) {
    static const char digits[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < length; ++i) {
        hex[i * 2U] = digits[(bytes[i] >> 4) & 0x0fU];
        hex[i * 2U + 1U] = digits[bytes[i] & 0x0fU];
    }
    hex[length * 2U] = '\0';
}
