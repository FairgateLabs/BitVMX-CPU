# ChaCha20 Test

This directory contains ChaCha20 cipher test vectors and test harness for the BitVMX-CPU project.

## Building and Running

### Compile the test file

```sh
./docker-build.sh chacha/chacha_test.c
```

### Run comprehensive tests (EMU execution + verification + prove/verify)

```sh
./test_elfs.sh chacha/chacha_test.yaml
```

This will run all available ChaCha20 cipher test vectors sequentially.

## Test Vectors

The test vectors include 4 ChaCha20 cipher tests that verify encryption functionality.

Each test vector contains:
- **Key**: 32-byte ChaCha20 key
- **Nonce**: 12-byte initialization vector
- **Counter**: 32-bit block counter 
- **Plaintext**: Input data to encrypt
- **Expected Ciphertext**: Known correct encryption result

The implementation validates that the ChaCha20 cipher produces the correct ciphertext when encrypting the given plaintext with the specified key, nonce, and counter parameters.