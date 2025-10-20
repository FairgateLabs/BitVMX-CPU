/* CRC32 Test Runner
 * This file runs CRC32 test vectors similar to the SHA3 test structure.
 * It reads a test case index from a fixed memory address and validates
 * the CRC32 computation against known test vectors.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Include the CRC32 implementation
#include "crc32.c"

// Include the auto-generated test vectors
#include "test_vectors.h"

// The memory address from which the test case index will be read.
#define INPUT_ADDRESS 0xAA000000

int main()
{
    unsigned int actual_crc32;
    const CRC32TestVector *selected_test;
    unsigned int test_index = *(unsigned int*)INPUT_ADDRESS;

    // Perform a bounds check to prevent reading past the end of the array.
    // We use `num_crc32_test_vectors` which is defined in the generated "test_vectors.h".
    if (test_index >= num_crc32_test_vectors)
    {
        // Return a distinct error code if the index is out of bounds.
        return 42;
    }

    // Select the test case from the array defined in "test_vectors.h".
    selected_test = &crc32_test_vectors[test_index];

    // Compute the CRC32 of the message from the selected test vector.
    // Handle the case where the message is NULL (empty message)
    if (selected_test->message == NULL || selected_test->message_len == 0)
    {
        actual_crc32 = crc32(NULL, 0);
    }
    else
    {
        actual_crc32 = crc32(selected_test->message, selected_test->message_len);
    }

    // Compare the computed CRC32 with the expected value.
    if (actual_crc32 == selected_test->expected_crc32)
    {
        // Success: The computed CRC32 matches the expected value.
        return 0;
    }
    else
    {
        // Failure: The computed CRC32 does not match the expected value.
        return 1;
    }
}
