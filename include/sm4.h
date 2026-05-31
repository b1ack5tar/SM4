#ifndef SM4_H
#define SM4_H

#include <stddef.h>
#include <stdint.h>

#define SM4_BLOCK_SIZE 16U
#define SM4_KEY_SIZE 16U
#define SM4_ROUND_KEYS 32U

typedef struct {
    uint32_t rk[SM4_ROUND_KEYS];
} sm4_context;

void sm4_set_encrypt_key(sm4_context *ctx, const uint8_t key[SM4_KEY_SIZE]);
void sm4_set_decrypt_key(sm4_context *ctx, const uint8_t key[SM4_KEY_SIZE]);
void sm4_encrypt_block(const sm4_context *ctx,
                       const uint8_t input[SM4_BLOCK_SIZE],
                       uint8_t output[SM4_BLOCK_SIZE]);
void sm4_decrypt_block(const sm4_context *ctx,
                       const uint8_t input[SM4_BLOCK_SIZE],
                       uint8_t output[SM4_BLOCK_SIZE]);

int sm4_encrypt_ecb(const uint8_t key[SM4_KEY_SIZE],
                    const uint8_t *input,
                    size_t input_len,
                    uint8_t **output,
                    size_t *output_len);

int sm4_decrypt_ecb(const uint8_t key[SM4_KEY_SIZE],
                    const uint8_t *input,
                    size_t input_len,
                    uint8_t **output,
                    size_t *output_len);

#endif
