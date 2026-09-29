# BoringSSL GM baseline

This directory is the BoringSSL baseline used by the Electron `v43.3.0`
DTLS-SRTP GM work.

- Electron baseline: `v43.3.0`
- Chromium BoringSSL commit: `e52cff204127ca0f6d6d094cf84207af4f53811c`
- Baseline purpose: reproducible source dependency and later SM4/SM3 patch base
- Current status: upstream baseline; GM cryptographic implementation is not yet included

## Local build

```text
cmake -S . -B out/Release -GNinja -DCMAKE_BUILD_TYPE=Release
cmake --build out/Release
ctest --test-dir out/Release --output-on-failure
```

The baseline must pass its upstream tests before any GM patch is applied.

## Release

Create and push a tag such as `v43.3.0-gm1`. The GitHub Actions workflow
builds the baseline on Linux and Windows and publishes a source ZIP release.
