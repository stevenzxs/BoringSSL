#include <openssl/sm4.h>

#include <string.h>

#include <gtest/gtest.h>

TEST(SM4GCMTest, RoundTripAndTamperDetection) {
  const uint8_t key[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
  const uint8_t nonce[12] = {0,1,2,3,4,5,6,7,8,9,10,11};
  const uint8_t aad[] = "rtp-header";
  const uint8_t plain[] = "SM4-SRTP prototype payload";
  uint8_t ciphertext[sizeof(plain) - 1], tag[16], decrypted[sizeof(plain) - 1];
  ASSERT_EQ(SM4_GCM_encrypt(key, nonce, aad, sizeof(aad) - 1, plain,
                            sizeof(plain) - 1, ciphertext, tag), 1);
  EXPECT_EQ(SM4_GCM_decrypt(key, nonce, aad, sizeof(aad) - 1, ciphertext,
                            sizeof(ciphertext), tag, decrypted), 1);
  EXPECT_EQ(memcmp(decrypted, plain, sizeof(decrypted)), 0);
  tag[0] ^= 1;
  EXPECT_EQ(SM4_GCM_decrypt(key, nonce, aad, sizeof(aad) - 1, ciphertext,
                            sizeof(ciphertext), tag, decrypted), 0);
}
