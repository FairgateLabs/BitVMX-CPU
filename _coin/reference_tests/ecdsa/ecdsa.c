/*
 * ECDSA P-256 SHA-256 Test Harness
 * 
 * This file implements a test harness for ECDSA P-256 SHA-256 signature verification
 * following the same pattern as the SHA3 test harness. It receives a test index
 * via memory mapping and runs the corresponding ECDSA test vector.
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

// Include the P256 implementation and test vectors
#include "p256.c"
#include "test_vectors.h"

// Memory-mapped input address (same as SHA3)
#define INPUT_ADDRESS 0xAA000000

int main() {
    // Read test index from memory-mapped input
    volatile uint32_t *input_ptr = (volatile uint32_t *)INPUT_ADDRESS;
    uint32_t test_index = *input_ptr;
    
    // Check bounds
    if (test_index >= num_ecdsa_p256_sigver_test_vectors) {
        return 42; // Out of bounds
    }
    
    // Get the test vector
    const EcdsaSigVerTestVector *vector = &ecdsa_p256_sigver_test_vectors[test_index];
    
    // Run ECDSA verification
    p256_ret_t result = p256_verify(
        (uint8_t *)vector->message,
        vector->message_len,
        (uint8_t *)vector->signature,
        vector->public_key
    );
    
    // Check if result matches expectation
    if (result == vector->expected_result) {
        return 0; // Test passed
    } else {
        return 1; // Test failed
    }
}
