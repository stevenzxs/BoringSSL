#include <openssl/aead.h>

#include <string.h>

#include <openssl/cipher.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/sm4.h>
#include <openssl/span.h>

#include "../fipsmodule/cipher/internal.h"
#include "internal.h"

using namespace bssl;

struct aead_sm4_gcm_ctx {
  uint8_t key[16];
};

static_assert(sizeof(((EVP_AEAD_CTX *)nullptr)->state) >=
                  sizeof(aead_sm4_gcm_ctx),
              "AEAD state is too small");

static int aead_sm4_gcm_init(EVP_AEAD_CTX *ctx, const uint8_t *key,
                             size_t key_len, size_t tag_len) {
  if (key_len != 16) return 0;
  if (tag_len == 0) tag_len = 16;
  if (tag_len != 16) return 0;
  memcpy(reinterpret_cast<aead_sm4_gcm_ctx *>(&ctx->state)->key, key, 16);
  ctx->tag_len = tag_len;
  return 1;
}

static void aead_sm4_gcm_cleanup(EVP_AEAD_CTX *ctx) {
  memset(&ctx->state, 0, sizeof(ctx->state));
}

static int aead_sm4_gcm_sealv(const EVP_AEAD_CTX *ctx,
                              Span<const CRYPTO_IOVEC> iovecs,
                              Span<uint8_t> out_tag, size_t *out_tag_len,
                              Span<const uint8_t> nonce,
                              Span<const CRYPTO_IVEC> aadvecs) {
  if (nonce.size() != 12 || iovecs.size() > 1 || aadvecs.size() > 1 ||
      out_tag.size() < ctx->tag_len) {
    return 0;
  }
  const aead_sm4_gcm_ctx *state =
      reinterpret_cast<const aead_sm4_gcm_ctx *>(&ctx->state);
  const uint8_t *in = iovecs.empty() ? nullptr : iovecs[0].in;
  uint8_t *out = iovecs.empty() ? nullptr : iovecs[0].out;
  const uint8_t *aad = aadvecs.empty() ? nullptr : aadvecs[0].in;
  const size_t in_len = iovecs.empty() ? 0 : iovecs[0].len;
  const size_t aad_len = aadvecs.empty() ? 0 : aadvecs[0].len;
  if (!SM4_GCM_encrypt(state->key, nonce.data(), aad, aad_len, in, in_len,
                       out, out_tag.data())) {
    return 0;
  }
  *out_tag_len = ctx->tag_len;
  return 1;
}

static int aead_sm4_gcm_openv_detached(
    const EVP_AEAD_CTX *ctx, Span<const CRYPTO_IOVEC> iovecs,
    Span<const uint8_t> nonce, Span<const uint8_t> in_tag,
    Span<const CRYPTO_IVEC> aadvecs) {
  if (nonce.size() != 12 || iovecs.size() > 1 || aadvecs.size() > 1 ||
      in_tag.size() != ctx->tag_len) {
    return 0;
  }
  const aead_sm4_gcm_ctx *state =
      reinterpret_cast<const aead_sm4_gcm_ctx *>(&ctx->state);
  const uint8_t *in = iovecs.empty() ? nullptr : iovecs[0].in;
  uint8_t *out = iovecs.empty() ? nullptr : iovecs[0].out;
  const uint8_t *aad = aadvecs.empty() ? nullptr : aadvecs[0].in;
  const size_t in_len = iovecs.empty() ? 0 : iovecs[0].len;
  const size_t aad_len = aadvecs.empty() ? 0 : aadvecs[0].len;
  if (!SM4_GCM_decrypt(state->key, nonce.data(), aad, aad_len, in, in_len,
                       in_tag.data(), out)) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_DECRYPT);
    return 0;
  }
  return 1;
}

static const EVP_AEAD aead_sm4_gcm = {
    16,  // key len
    12,  // nonce len
    16,  // overhead
    16,  // max tag length
    aead_sm4_gcm_init,
    nullptr,  // init_with_direction
    aead_sm4_gcm_cleanup,
    nullptr,  // openv
    aead_sm4_gcm_sealv,
    aead_sm4_gcm_openv_detached,
    nullptr,  // get_iv
    nullptr,  // tag_len
};

const EVP_AEAD *EVP_aead_sm4_gcm() { return &aead_sm4_gcm; }
