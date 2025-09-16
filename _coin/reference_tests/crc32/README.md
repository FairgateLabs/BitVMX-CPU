# CRC32 Implementation and Test Suite

This directory contains a CRC32 implementation with comprehensive test vectors for validation.

## Test Vector Generation

Test vectors are generated using a Python script that creates various test patterns:

```python
# Generate 20 test vectors
python generate_crc32_vectors.py -o test_vectors.h --num-vectors 20
```

## Building

To build the CRC32 test:

```bash
./docker-build.sh crc32/crc32_test.c
```

This will compile the test runner with the CRC32 implementation and test vectors.

## Running Tests

To run comprehensive CRC32 tests (EMU execution + verification + prove/verify):

```bash
./test_elfs.sh --start-index 0 crc32/crc32_test.yaml
```

The test reads the test vector index from memory address `0xAA000000` and validates the CRC32 implementation against the expected values.