#include <openssl/sm4.h>

#include <openssl/mem.h>

#include <stdint.h>

namespace {

void XorBlock(uint8_t out[16], const uint8_t in[16]) {
  for (size_t i = 0; i < 16; ++i) out[i] ^= in[i];
}

void ShiftRight(uint8_t v[16]) {
  uint8_t carry = 0;
  for (size_t i = 0; i < 16; ++i) {
    const uint8_t next = v[i] & 1;
    v[i] = static_cast<uint8_t>((v[i] >> 1) | (carry << 7));
    carry = next;
  }
}

void GHashMultiply(uint8_t x[16], const uint8_t h[16]) {
  uint8_t z[16] = {}, v[16];
  OPENSSL_memcpy(v, h, sizeof(v));
  for (unsigned bit = 0; bit < 128; ++bit) {
    const uint8_t mask = static_cast<uint8_t>(0 - ((x[bit / 8] >> (7 - bit % 8)) & 1));
    for (size_t i = 0; i < 16; ++i) z[i] ^= v[i] & mask;
    const uint8_t lsb = v[15] & 1;
    ShiftRight(v);
    v[0] ^= static_cast<uint8_t>(0xe1 & (0 - lsb));
  }
  OPENSSL_memcpy(x, z, sizeof(z));
}

void GHash(uint8_t out[16], const uint8_t h[16], const uint8_t *aad,
           size_t aad_len, const uint8_t *data, size_t data_len) {
  OPENSSL_memset(out, 0, 16);
  auto absorb = [&](const uint8_t *p, size_t len) {
    while (len >= 16) {
      XorBlock(out, p);
      GHashMultiply(out, h);
      p += 16;
      len -= 16;
    }
    if (len != 0) {
      uint8_t block[16] = {};
      OPENSSL_memcpy(block, p, len);
      XorBlock(out, block);
      GHashMultiply(out, h);
    }
  };
  absorb(aad, aad_len);
  absorb(data, data_len);
  uint8_t lengths[16] = {};
  const uint64_t aad_bits = static_cast<uint64_t>(aad_len) * 8;
  const uint64_t data_bits = static_cast<uint64_t>(data_len) * 8;
  for (unsigned i = 0; i < 8; ++i) {
    lengths[7 - i] = static_cast<uint8_t>(aad_bits >> (8 * i));
    lengths[15 - i] = static_cast<uint8_t>(data_bits >> (8 * i));
  }
  XorBlock(out, lengths);
  GHashMultiply(out, h);
}

void Increment32(uint8_t counter[16]) {
  uint32_t value = (uint32_t(counter[12]) << 24) | (uint32_t(counter[13]) << 16) |
                   (uint32_t(counter[14]) << 8) | counter[15];
  ++value;
  counter[12] = static_cast<uint8_t>(value >> 24);
  counter[13] = static_cast<uint8_t>(value >> 16);
  counter[14] = static_cast<uint8_t>(value >> 8);
  counter[15] = static_cast<uint8_t>(value);
}

void Crypt(const SM4_KEY *ks, const uint8_t counter0[16], const uint8_t *in,
           size_t len, uint8_t *out) {
  uint8_t counter[16], stream[16];
  OPENSSL_memcpy(counter, counter0, sizeof(counter));
  while (len != 0) {
    Increment32(counter);
    SM4_encrypt(counter, stream, ks);
    const size_t n = len < 16 ? len : 16;
    for (size_t i = 0; i < n; ++i) out[i] = in[i] ^ stream[i];
    in += n;
    out += n;
    len -= n;
  }
}

int GCM(const uint8_t key[16], const uint8_t nonce[12], const uint8_t *aad,
        size_t aad_len, const uint8_t *in, size_t in_len, const uint8_t *tag,
        uint8_t *out, uint8_t *out_tag, bool decrypt) {
  if (!key || !nonce || (decrypt && !tag) || (!decrypt && !out_tag) ||
      (aad_len > UINT64_MAX / 8) || (in_len > UINT64_MAX / 8) ||
      (in_len != 0 && (!in || !out)) || (aad_len != 0 && !aad)) {
    return 0;
  }
  SM4_KEY ks;
  if (SM4_set_key(key, &ks) != 0) return 0;
  uint8_t h[16] = {}, j0[16] = {}, expected[16];
  SM4_encrypt(h, h, &ks);
  OPENSSL_memcpy(j0, nonce, 12);
  j0[15] = 1;
  if (decrypt) {
    Crypt(&ks, j0, in, in_len, out);
  }
  GHash(expected, h, aad, aad_len, decrypt ? out : in, in_len);
  uint8_t mask[16];
  SM4_encrypt(j0, mask, &ks);
  XorBlock(expected, mask);
  if (decrypt) {
    uint8_t diff = 0;
    for (size_t i = 0; i < 16; ++i) diff |= expected[i] ^ tag[i];
    if (diff != 0) {
      OPENSSL_memset(out, 0, in_len);
      return 0;
    }
    return 1;
  }
  Crypt(&ks, j0, in, in_len, out);
  OPENSSL_memcpy(out_tag, expected, 16);
  return 1;
}

}  // namespace

extern "C" int SM4_GCM_encrypt(const uint8_t key[16], const uint8_t nonce[12],
                                const uint8_t *aad, size_t aad_len,
                                const uint8_t *in, size_t in_len, uint8_t *out,
                                uint8_t tag[16]) {
  return GCM(key, nonce, aad, aad_len, in, in_len, nullptr, out, tag, false);
}

extern "C" int SM4_GCM_decrypt(const uint8_t key[16], const uint8_t nonce[12],
                                const uint8_t *aad, size_t aad_len,
                                const uint8_t *in, size_t in_len,
                                const uint8_t tag[16], uint8_t *out) {
  return GCM(key, nonce, aad, aad_len, in, in_len, tag, out, nullptr, true);
}
