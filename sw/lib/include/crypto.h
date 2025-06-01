#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Computes the SHA-256 hash of the input data.
 *
 * This function processes the input data buffer and produces a 256-bit (32-byte) hash digest
 * according to the SHA-256 cryptographic hash algorithm. The resulting digest is stored as
 * eight 32-bit unsigned integers in the provided output array.
 *
 * @param[in]  data        Pointer to the input data buffer to be hashed.
 * @param[in]  len         Length of the input data buffer in bytes.
 * @param[out] out_digest  Pointer to an array of 8 uint32_t where the resulting hash digest will be stored.
 */
void sha256(const unsigned char *data, size_t len, uint32_t out_digest[8]);

#endif // CRYPTO_H
