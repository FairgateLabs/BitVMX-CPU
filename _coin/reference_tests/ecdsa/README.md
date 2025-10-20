# ECDSA P-256 SHA-256 Implementation and Test Suite

This directory contains an ECDSA P-256 SHA-256 implementation with NIST test vectors for signature verification validation.

## Implementation Source

The core P-256 elliptic curve implementation is contained in `p256.c` and `p256.h`, providing ECDSA signature verification functionality for the NIST P-256 curve with SHA-256 hashing.

## Building

To build the ECDSA implementation:

```bash
./docker-build.sh ecdsa/ecdsa.c
```

## Test Vectors

The test vectors are generated from NIST CAVS test files:
- `rsp/SigVer.rsp` - ECDSA P-256 SHA-256 signature verification test vectors

To regenerate test vectors:
```bash
python parse_ecdsa_rsp.py -o test_vectors.h rsp/SigVer.rsp
```

## Running Tests

To run comprehensive ECDSA tests (EMU execution + verification + prove/verify):

```bash
./test_elfs.sh --start-index 0 ecdsa/ecdsa_test.yaml
```

The test reads the test vector index from memory address `0xAA000000` and validates the ECDSA P-256 SHA-256 signature verification implementation against NIST test vectors.
