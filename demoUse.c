#define _GNU_SOURCE

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <unistd.h>

#define MLK_CONFIG_PARAMETER_SET 768
#include "mlkem_native.h"

int randombytes(uint8_t *out, size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        ssize_t count = getrandom(out + offset, length - offset, 0);

        if (count < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }

        if (count == 0)
            return -1;

        offset += (size_t)count;
    }

    return 0;
}

static void print_hex(const char *label, const uint8_t *data, size_t length)
{
    size_t i;

    printf("%s: ", label);
    for (i = 0; i < length; i++)
        printf("%02x", data[i]);
    printf("\n");
}

int main(int argc, char **argv)
{
    int use_static_seed = 0;
    int result;

    if (argc > 2 || (argc == 2 && strcmp(argv[1], "-s") != 0)) {
        fprintf(stderr, "Usage: %s [-s]\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (argc == 2)
        use_static_seed = 1;

    /* Slight delay before starting. */
    sleep(1);

    uint8_t public_key[MLKEM_PUBLICKEYBYTES(768)];
    uint8_t secret_key[MLKEM_SECRETKEYBYTES(768)];
    uint8_t ciphertext[MLKEM_CIPHERTEXTBYTES(768)];
    uint8_t encapsulated_secret[MLKEM_BYTES];
    uint8_t decapsulated_secret[MLKEM_BYTES];
    size_t i;

    if (use_static_seed) {
        uint8_t keypair_coins[2 * MLKEM_SYMBYTES];
        uint8_t encapsulation_coins[MLKEM_SYMBYTES];

        /* Deterministic demo inputs. Use the randomized API by default. */
        for (i = 0; i < sizeof(keypair_coins); i++)
            keypair_coins[i] = (uint8_t)i;

        for (i = 0; i < sizeof(encapsulation_coins); i++)
            encapsulation_coins[i] = (uint8_t)(0xa0U + i);

        result = PQCP_MLKEM_NATIVE_MLKEM768_keypair_derand(
            public_key, secret_key, keypair_coins);
        if (result != 0) {
            fprintf(stderr, "Key generation failed: %d\n", result);
            return EXIT_FAILURE;
        }

        result = PQCP_MLKEM_NATIVE_MLKEM768_enc_derand(
            ciphertext, encapsulated_secret, public_key, encapsulation_coins);
    } else {
        result = PQCP_MLKEM_NATIVE_MLKEM768_keypair(
            public_key, secret_key);
        if (result != 0) {
            fprintf(stderr, "Key generation failed: %d\n", result);
            return EXIT_FAILURE;
        }

        result = PQCP_MLKEM_NATIVE_MLKEM768_enc(
            ciphertext, encapsulated_secret, public_key);
    }

    if (result != 0) {
        fprintf(stderr, "Encapsulation failed: %d\n", result);
        return EXIT_FAILURE;
    }

    print_hex("Ciphertext", ciphertext, sizeof(ciphertext));
    print_hex("Encapsulated shared secret", encapsulated_secret,
              sizeof(encapsulated_secret));

    /* Slight delay before decapsulation. */
    sleep(1);

    result = PQCP_MLKEM_NATIVE_MLKEM768_dec(
        decapsulated_secret, ciphertext, secret_key);
    if (result != 0) {
        fprintf(stderr, "Decapsulation failed: %d\n", result);
        return EXIT_FAILURE;
    }

    print_hex("Decapsulated shared secret", decapsulated_secret,
              sizeof(decapsulated_secret));

    if (memcmp(encapsulated_secret, decapsulated_secret,
               sizeof(encapsulated_secret)) != 0) {
        fprintf(stderr, "Shared secrets do not match\n");
        return EXIT_FAILURE;
    }

    printf("Shared secrets match.\n");
    return EXIT_SUCCESS;
}

