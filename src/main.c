#include "sm4.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_usage(const char *program) {
    fprintf(stderr,
            "Usage:\n"
            "  %s enc <32-hex-key> <hex-plaintext>\n"
            "  %s dec <32-hex-key> <hex-ciphertext>\n"
            "  %s enc-block <32-hex-key> <32-hex-plaintext>\n"
            "  %s dec-block <32-hex-key> <32-hex-ciphertext>\n",
            program, program, program, program);
}

int main(int argc, char *argv[]) {
    uint8_t *key = NULL;
    uint8_t *input = NULL;
    uint8_t *output = NULL;
    char *hex_output = NULL;
    size_t key_len = 0U;
    size_t input_len = 0U;
    size_t output_len = 0U;
    int status = EXIT_FAILURE;
    int rc;

    if (argc != 4) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    rc = hex_to_bytes(argv[2], &key, &key_len);
    if (rc != 0 || key_len != SM4_KEY_SIZE) {
        fprintf(stderr, "Error: key must be exactly 32 hexadecimal characters.\n");
        goto cleanup;
    }

    rc = hex_to_bytes(argv[3], &input, &input_len);
    if (rc != 0) {
        fprintf(stderr, "Error: input must be a valid hexadecimal string.\n");
        goto cleanup;
    }

    if (strcmp(argv[1], "enc") == 0) {
        rc = sm4_encrypt_ecb(key, input, input_len, &output, &output_len);
        if (rc != 0) {
            fprintf(stderr, "Error: encryption failed.\n");
            goto cleanup;
        }
    } else if (strcmp(argv[1], "dec") == 0) {
        rc = sm4_decrypt_ecb(key, input, input_len, &output, &output_len);
        if (rc != 0) {
            fprintf(stderr, "Error: decryption failed. Check ciphertext length and padding.\n");
            goto cleanup;
        }
    } else if (strcmp(argv[1], "enc-block") == 0) {
        sm4_context ctx;

        if (input_len != SM4_BLOCK_SIZE) {
            fprintf(stderr, "Error: block mode requires exactly 32 hexadecimal characters of input.\n");
            goto cleanup;
        }

        output = (uint8_t *)malloc(SM4_BLOCK_SIZE);
        if (output == NULL) {
            fprintf(stderr, "Error: memory allocation failed.\n");
            goto cleanup;
        }

        sm4_set_encrypt_key(&ctx, key);
        sm4_encrypt_block(&ctx, input, output);
        output_len = SM4_BLOCK_SIZE;
    } else if (strcmp(argv[1], "dec-block") == 0) {
        sm4_context ctx;

        if (input_len != SM4_BLOCK_SIZE) {
            fprintf(stderr, "Error: block mode requires exactly 32 hexadecimal characters of input.\n");
            goto cleanup;
        }

        output = (uint8_t *)malloc(SM4_BLOCK_SIZE);
        if (output == NULL) {
            fprintf(stderr, "Error: memory allocation failed.\n");
            goto cleanup;
        }

        sm4_set_decrypt_key(&ctx, key);
        sm4_decrypt_block(&ctx, input, output);
        output_len = SM4_BLOCK_SIZE;
    } else {
        print_usage(argv[0]);
        goto cleanup;
    }

    hex_output = (char *)malloc((output_len * 2U) + 1U);
    if (hex_output == NULL) {
        fprintf(stderr, "Error: memory allocation failed.\n");
        goto cleanup;
    }

    bytes_to_hex(output, output_len, hex_output);
    puts(hex_output);
    status = EXIT_SUCCESS;

cleanup:
    free(key);
    free(input);
    free(output);
    free(hex_output);
    return status;
}
