#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MLK_CONFIG_PARAMETER_SET 768
#include "mlkem_native.h"

static void print_hex(const char *label, const uint8_t *data, size_t length)
{
    size_t i;

    printf("%s: ", label);
    for (i = 0; i < length; i++)
        printf("%02x", data[i]);
    printf("\n");
}

int main(void)
{
    /* Slight delay before starting. */
    sleep(1);

    uint8_t public_key[MLKEM_PUBLICKEYBYTES(768)];
    uint8_t secret_key[MLKEM_SECRETKEYBYTES(768)];
    uint8_t ciphertext[MLKEM_CIPHERTEXTBYTES(768)];
    uint8_t encapsulated_secret[MLKEM_BYTES];
    uint8_t decapsulated_secret[MLKEM_BYTES];
    uint8_t keypair_coins[2 * MLKEM_SYMBYTES];
    uint8_t encapsulation_coins[MLKEM_SYMBYTES];
    size_t i;
    int result;

    /* Deterministic demo inputs. Use the randomized API in production. */
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

