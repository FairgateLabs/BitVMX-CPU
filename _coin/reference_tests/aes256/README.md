Original repository: github @ ilvn/aes256

## Building and Running Tests

To build the AES-256 test:

```bash
./docker-build.sh aes256/aes256.c
```

To run comprehensive AES-256 tests (EMU execution + verification + prove/verify):

```bash
./test_elfs.sh --start-index 0 aes256/aes256.yaml
```  

## Test Vectors

The [aes256.c](aes256.c) uses a few known-answer tests from several official 
documents to verify this is a valid AES-256 implementation.
