/*
 * ChaCha20 Test Harness
 * 
 * This file implements a test harness for ChaCha20 cipher tests
 * following the same pattern as the ECDSA test harness. It receives a test index
 * via memory mapping and runs the corresponding ChaCha20 test vector.
 * 
 * The test harness encrypts plaintext and compares it with expected ciphertext.
 * 
 * Memory layout:
 * - 0xAA000000: Test index (32-bit input)
 * 
 * Return codes:
 * - 0: Test passed
 * - 1: Test failed  
 * - 42: Test index out of bounds
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Include the ChaCha20 implementation and test vectors
#define CHACHA20_IMPLEMENTATION
#include "ChaCha20.h"
#include "test_vectors.h"

// Memory-mapped input address (same as ECDSA and SHA3)
#define INPUT_ADDRESS 0xAA000000

// Maximum buffer size for test data
#define MAX_BUFFER_SIZE 1024

int main() {
    // Read test index from memory-mapped input
    volatile uint32_t *input_ptr = (volatile uint32_t *)INPUT_ADDRESS;
    uint32_t test_index = *input_ptr;
    
    // Check bounds
    if (test_index >= num_chacha20_test_vectors) {
        return 42; // Out of bounds
    }
    
    // Get the test vector
    const ChaCha20TestVector *vector = &chacha20_test_vectors[test_index];
    
    // Check buffer size
    if (vector->plaintext_len > MAX_BUFFER_SIZE) {
        return 1; // Buffer too small
    }
    
    // Copy plaintext to a working buffer
    uint8_t buffer[MAX_BUFFER_SIZE];
    memcpy(buffer, vector->plaintext, vector->plaintext_len);
    
    // Initialize ChaCha20 context and encrypt
    ChaCha20_Ctx ctx;
    ChaCha20_init(&ctx, vector->key, vector->nonce, vector->count);
    ChaCha20_xor(&ctx, buffer, vector->plaintext_len);
    
    // Compare encrypted result with expected ciphertext
    if (memcmp(buffer, vector->expected_ciphertext, vector->plaintext_len) != 0) {
        return 1; // Encryption test failed
    }
    
    return 0; // Test passed
}
