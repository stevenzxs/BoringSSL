# GM SM4 implementation boundary

This document defines the first source-level change after the
Electron `v43.3.0` BoringSSL baseline.

## Scope

The first patch implements and tests the SM4 block primitive only. It must not
enable `OPENSSL_NO_SM4` removal until the implementation and tests are present.
SM4-GCM is the next layer and must reuse the existing AEAD/GCM framing only
after the block primitive is verified.

## Planned source layout

- `include/openssl/sm4.h`: public raw block API and key type
- `crypto/sm4/sm4.cc`: key expansion and encrypt/decrypt implementation
- `crypto/sm4/sm4_test.cc`: known-answer tests and round-trip tests
- `CMakeLists.txt`: standalone source and test target registration
- Chromium generated source manifests: update after the patch is accepted

## Required known-answer test

SM4-ECB, one block:

- key: `0123456789abcdeffedcba9876543210`
- plaintext: `0123456789abcdeffedcba9876543210`
- ciphertext: `681edf34d206965e86b3e94f536e4246`

The test must also verify decrypt(encrypt(plaintext)) equals the original
plaintext and must not depend on the Jitsi Java implementation.

## Acceptance gate

Only after the block test passes on Linux and Windows should the patch expose
SM4 to the AEAD layer and add the SM4-GCM cross-language vector from the Jitsi
SRTP tests.
