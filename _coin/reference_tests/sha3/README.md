# SHA3-256 Implementation and Test Suite

This directory contains a SHA3-256 implementation with NIST test vectors for validation.

## Implementation Source

The core SHA3-256 implementation was extracted from the XKCP (eXtended Keccak Code Package):
https://github.com/XKCP/XKCP/blob/master/Standalone/CompactFIPS202/C/Keccak-more-compact.c

## Added Convenience Functions

To maintain the same structure as the SHA256 tests, we added convenience functions similar to the SHA256 API:

```c
/* Convenience functions for SHA3-256 (similar to SHA256 API) */
void sha3_256_easy_hash(const void* data, size_t size, uint8_t* hash)
{
    FIPS202_SHA3_256((const u8*)data, (u64)size, hash);
}

void sha3_256_to_hex(const uint8_t* hash, char* hex)
{
    const char hex_chars[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        hex[i * 2] = hex_chars[(hash[i] >> 4) & 0xF];
        hex[i * 2 + 1] = hex_chars[hash[i] & 0xF];
    }
}

void sha3_256_easy_hash_hex(const void* data, size_t size, char* hex)
{
    uint8_t hash[32];
    sha3_256_easy_hash(data, size, hash);
    sha3_256_to_hex(hash, hex);
}
```

## Building

To build the SHA3 implementation:

```bash
./docker-build.sh sha3/sha3.c
```

## Test Vectors

The test vectors are generated from NIST CAVS test files:
- `rsp/SHA3_256ShortMsg.rsp`
- `rsp/SHA3_256LongMsg.rsp`

To regenerate test vectors:
```bash
python parse_sha3_rsp.py -o test_vectors.h rsp/SHA3_256ShortMsg.rsp rsp/SHA3_256LongMsg.rsp
```

## Running Tests

To run comprehensive SHA3 tests (EMU execution + verification + prove/verify):

```bash
./test_elfs.sh --start-index 0 sha3/sha3_test.yaml
```

The test reads the test vector index from memory address `0xAA000000` and validates the SHA3-256 implementation in both the emulator and bitcoin implementation against NIST test vectors.