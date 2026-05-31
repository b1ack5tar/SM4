#include "sm4.h"

#include <stdlib.h>
#include <string.h>

static const uint8_t SM4_SBOX[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

static const uint32_t SM4_FK[4] = {
    0xa3b1bac6U, 0x56aa3350U, 0x677d9197U, 0xb27022dcU
};

static const uint32_t SM4_CK[32] = {
    0x00070e15U, 0x1c232a31U, 0x383f464dU, 0x545b6269U,
    0x70777e85U, 0x8c939aa1U, 0xa8afb6bdU, 0xc4cbd2d9U,
    0xe0e7eef5U, 0xfc030a11U, 0x181f262dU, 0x343b4249U,
    0x50575e65U, 0x6c737a81U, 0x888f969dU, 0xa4abb2b9U,
    0xc0c7ced5U, 0xdce3eaf1U, 0xf8ff060dU, 0x141b2229U,
    0x30373e45U, 0x4c535a61U, 0x686f767dU, 0x848b9299U,
    0xa0a7aeb5U, 0xbcc3cad1U, 0xd8dfe6edU, 0xf4fb0209U,
    0x10171e25U, 0x2c333a41U, 0x484f565dU, 0x646b7279U
};

static uint32_t rotl32(uint32_t value, unsigned int shift) {
    return (value << shift) | (value >> (32U - shift));
}

static uint32_t load_be32(const uint8_t *bytes) {
    return ((uint32_t)bytes[0] << 24) |
           ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) |
           (uint32_t)bytes[3];
}

static void store_be32(uint32_t value, uint8_t *bytes) {
    bytes[0] = (uint8_t)(value >> 24);
    bytes[1] = (uint8_t)(value >> 16);
    bytes[2] = (uint8_t)(value >> 8);
    bytes[3] = (uint8_t)value;
}

static uint32_t tau(uint32_t value) {
    uint8_t a0 = SM4_SBOX[(value >> 24) & 0xffU];
    uint8_t a1 = SM4_SBOX[(value >> 16) & 0xffU];
    uint8_t a2 = SM4_SBOX[(value >> 8) & 0xffU];
    uint8_t a3 = SM4_SBOX[value & 0xffU];

    return ((uint32_t)a0 << 24) |
           ((uint32_t)a1 << 16) |
           ((uint32_t)a2 << 8) |
           (uint32_t)a3;
}

static uint32_t linear_transform(uint32_t value) {
    return value ^ rotl32(value, 2) ^ rotl32(value, 10) ^
           rotl32(value, 18) ^ rotl32(value, 24);
}

static uint32_t linear_transform_key(uint32_t value) {
    return value ^ rotl32(value, 13) ^ rotl32(value, 23);
}

static uint32_t t_transform(uint32_t value) {
    return linear_transform(tau(value));
}

static uint32_t t_transform_key(uint32_t value) {
    return linear_transform_key(tau(value));
}

static void sm4_set_key(sm4_context *ctx, const uint8_t key[SM4_KEY_SIZE], int decrypt) {
    uint32_t k[36];
    size_t i;

    for (i = 0; i < 4; ++i) {
        k[i] = load_be32(key + (i * 4U)) ^ SM4_FK[i];
    }

    for (i = 0; i < SM4_ROUND_KEYS; ++i) {
        k[i + 4] = k[i] ^ t_transform_key(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ SM4_CK[i]);
        ctx->rk[decrypt ? (SM4_ROUND_KEYS - 1U - i) : i] = k[i + 4];
    }
}

void sm4_set_encrypt_key(sm4_context *ctx, const uint8_t key[SM4_KEY_SIZE]) {
    sm4_set_key(ctx, key, 0);
}

void sm4_set_decrypt_key(sm4_context *ctx, const uint8_t key[SM4_KEY_SIZE]) {
    sm4_set_key(ctx, key, 1);
}

void sm4_encrypt_block(const sm4_context *ctx,
                       const uint8_t input[SM4_BLOCK_SIZE],
                       uint8_t output[SM4_BLOCK_SIZE]) {
    uint32_t x[36];
    size_t i;

    for (i = 0; i < 4; ++i) {
        x[i] = load_be32(input + (i * 4U));
    }

    for (i = 0; i < SM4_ROUND_KEYS; ++i) {
        x[i + 4] = x[i] ^ t_transform(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ ctx->rk[i]);
    }

    for (i = 0; i < 4; ++i) {
        store_be32(x[35 - i], output + (i * 4U));
    }
}

void sm4_decrypt_block(const sm4_context *ctx,
                       const uint8_t input[SM4_BLOCK_SIZE],
                       uint8_t output[SM4_BLOCK_SIZE]) {
    sm4_encrypt_block(ctx, input, output);
}

int sm4_encrypt_ecb(const uint8_t key[SM4_KEY_SIZE],
                    const uint8_t *input,
                    size_t input_len,
                    uint8_t **output,
                    size_t *output_len) {
    sm4_context ctx;
    uint8_t *buffer;
    size_t pad_len;
    size_t total_len;
    size_t offset;

    if (output == NULL || output_len == NULL) {
        return -1;
    }

    pad_len = SM4_BLOCK_SIZE - (input_len % SM4_BLOCK_SIZE);
    if (pad_len == 0U) {
        pad_len = SM4_BLOCK_SIZE;
    }
    total_len = input_len + pad_len;

    buffer = (uint8_t *)malloc(total_len);
    if (buffer == NULL) {
        return -1;
    }

    if (input_len > 0U) {
        memcpy(buffer, input, input_len);
    }
    memset(buffer + input_len, (int)pad_len, pad_len);

    sm4_set_encrypt_key(&ctx, key);
    for (offset = 0; offset < total_len; offset += SM4_BLOCK_SIZE) {
        sm4_encrypt_block(&ctx, buffer + offset, buffer + offset);
    }

    *output = buffer;
    *output_len = total_len;
    return 0;
}

int sm4_decrypt_ecb(const uint8_t key[SM4_KEY_SIZE],
                    const uint8_t *input,
                    size_t input_len,
                    uint8_t **output,
                    size_t *output_len) {
    sm4_context ctx;
    uint8_t *buffer;
    uint8_t pad_len;
    size_t offset;
    size_t plain_len;

    if (output == NULL || output_len == NULL || input == NULL) {
        return -1;
    }
    if (input_len == 0U || (input_len % SM4_BLOCK_SIZE) != 0U) {
        return -1;
    }

    buffer = (uint8_t *)malloc(input_len);
    if (buffer == NULL) {
        return -1;
    }
    memcpy(buffer, input, input_len);

    sm4_set_decrypt_key(&ctx, key);
    for (offset = 0; offset < input_len; offset += SM4_BLOCK_SIZE) {
        sm4_decrypt_block(&ctx, buffer + offset, buffer + offset);
    }

    pad_len = buffer[input_len - 1U];
    if (pad_len == 0U || pad_len > SM4_BLOCK_SIZE) {
        free(buffer);
        return -1;
    }

    for (offset = 0; offset < pad_len; ++offset) {
        if (buffer[input_len - 1U - offset] != pad_len) {
            free(buffer);
            return -1;
        }
    }

    plain_len = input_len - pad_len;
    *output = buffer;
    *output_len = plain_len;
    return 0;
}
