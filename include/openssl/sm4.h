#ifndef OPENSSL_HEADER_SM4_H
#define OPENSSL_HEADER_SM4_H

#include <openssl/base.h>

#if defined(__cplusplus)
extern "C" {
#endif

#define SM4_BLOCK_SIZE 16

struct sm4_key_st {
  uint32_t rk[32];
};
typedef struct sm4_key_st SM4_KEY;

OPENSSL_EXPORT int SM4_set_key(const uint8_t *key, SM4_KEY *ks);
OPENSSL_EXPORT void SM4_encrypt(const uint8_t *in, uint8_t *out,
                                const SM4_KEY *ks);
OPENSSL_EXPORT void SM4_decrypt(const uint8_t *in, uint8_t *out,
                                const SM4_KEY *ks);

#if defined(__cplusplus)
}  // extern "C"
#endif

#endif  // OPENSSL_HEADER_SM4_H
