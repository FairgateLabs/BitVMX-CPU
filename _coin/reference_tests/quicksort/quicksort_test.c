/*
 * Quicksort Test Program
 * 
 * This test program generates arrays of different sizes and patterns
 * based on a memory-mapped index input, then verifies the quicksort
 * algorithm implementation.
 * 
 * The test index is read from a memory-mapped address similar to
 * other reference tests in this project.
 */

#include "./sortlib/sort.h"

// Include the quicksort implementation files
#include "./sortlib/quicksort.c"
#include "./sortlib/sorted.c"

// The memory address from which the test case index will be read
#define INPUT_ADDRESS ((volatile unsigned int *)0xAA000000)

// Maximum array size for testing
#define MAX_ARRAY_SIZE 100

// Number of different test cases
#define NUM_TEST_CASES 14

// Simple linear congruential generator for pseudo-random numbers
// Using the same seed for reproducible results
static unsigned long rng_state = 12345;

unsigned long simple_rand() {
    rng_state = (rng_state * 1103515245 + 12345) & 0x7fffffff;
    return rng_state;
}

void simple_srand(unsigned long seed) {
    rng_state = seed;
}

// Test case generators
void generate_random_array(KEY_T *array, int size, unsigned long seed) {
    simple_srand(seed);
    for (int i = 0; i < size; i++) {
        array[i] = (KEY_T)(simple_rand() % 1000);
    }
}

void generate_sorted_array(KEY_T *array, int size) {
    for (int i = 0; i < size; i++) {
        array[i] = (KEY_T)i;
    }
}

void generate_reverse_sorted_array(KEY_T *array, int size) {
    for (int i = 0; i < size; i++) {
        array[i] = (KEY_T)(size - i - 1);
    }
}

// Copy array for comparison
void copy_array(KEY_T *dest, const KEY_T *src, int size) {
    for (int i = 0; i < size; i++) {
        dest[i] = src[i];
    }
}

// Test case structure
typedef struct {
    int array_size;
    unsigned long seed;
    int test_type; // 0=random, 1=sorted, 2=reverse
} TestCase;

// Define test cases
static const TestCase test_cases[NUM_TEST_CASES] = {
    {5, 42, 0},    // Small random array
    {10, 123, 0},  // Medium random array
    {20, 456, 0},  // Large random array
    {50, 789, 0},  // Very large random array
    
    {5, 0, 1},     // Small sorted array
    {10, 0, 1},    // Medium sorted array
    {20, 0, 1},    // Large sorted array
    
    {5, 0, 2},     // Small reverse sorted array
    {10, 0, 2},    // Medium reverse sorted array
    {20, 0, 2},    // Large reverse sorted array
    
    {1, 1, 0},     // Single element array
    {2, 2, 0},     // Two element array
    {3, 3, 0},     // Three element array
    {100, 999, 0},  // Large random array
};

int run_test_case(int test_index) {
    if (test_index >= NUM_TEST_CASES) {
        return 1;
    }
    
    const TestCase *test = &test_cases[test_index];
    
    // Check array size bounds
    if (test->array_size <= 0 || test->array_size > MAX_ARRAY_SIZE) {
        return 1;
    }
    
    KEY_T original_array[MAX_ARRAY_SIZE];
    KEY_T test_array[MAX_ARRAY_SIZE];
    KEY_T temp; // Required by SWAP macro
    
    // Generate test data based on test type
    if (test->test_type == 1) {
        generate_sorted_array(original_array, test->array_size);
    } else if (test->test_type == 2) {
        generate_reverse_sorted_array(original_array, test->array_size);
    } else {
        generate_random_array(original_array, test->array_size, test->seed);
    }
    
    // Copy array for sorting
    copy_array(test_array, original_array, test->array_size);
    
    // Sort the array
    if (test->array_size > 1) {
        quicksort(test_array, 0, test->array_size - 1);
    }
    
    // Verify the array is sorted
    if (!sorted(test_array, test->array_size)) {
        return 1; // Sort failed
    }
    
    return 0; // Success
}

int main() {
    unsigned int test_index = *INPUT_ADDRESS;
    
    // Bounds check
    if (test_index >= NUM_TEST_CASES) {
        return 42; // Error code for out of bounds
    }
    
    // Run the specified test case
    return run_test_case(test_index);
}
