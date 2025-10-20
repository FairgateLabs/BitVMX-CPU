# Quicksort Implementation and Test Suite

This directory contains comprehensive test cases for validation.

## Implementation Source

The core quicksort implementation is based on C.A.R. Hoare's Quick-sort algorithm (ala Jon Bentley) from Ariel Faigon's sorting library:

- `quicksort.c` - Main quicksort implementation
- `sorted.c` - Array validation utilities  
- `sort.h` - Customizable sorting library header

## Test Implementation

The test suite (`quicksort_test.c`) generates arrays with different patterns and sizes to thoroughly test the quicksort algorithm:

### Test Categories

1. **Random Arrays**: Arrays with pseudo-random elements using different seeds
2. **Sorted Arrays**: Already sorted arrays (best-case scenario)
3. **Reverse Sorted Arrays**: Arrays sorted in descending order (worst-case scenario)
4. **Edge Cases**: Single-element, two-element, and three-element arrays

### Test Cases

The test suite includes 15 different test cases covering:

```c
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
{75, 999, 0},  // Large random array
{100, 777, 0}  // Maximum size random array
```

## Key Configuration

The sorting library is configured for `long` integers:

```c
typedef long KEY_T;
```

Comparison and swap operations are defined as macros:

```c
#define GT(x, y) ((x) > (y))
#define LT(x, y) ((x) < (y))
#define SWAP(x, y) { temp = (x); (x) = (y); (y) = temp; }
```

## Installing

Before building you should download the quicksort implementation by running the `install.sh` script that will clone the sortlib repo.

## Building

To build the quicksort test:

```bash
./docker-build.sh quicksort/quicksort_test.c
```

## Running Tests

To run comprehensive quicksort tests (EMU execution + verification + prove/verify):

```bash
./test_elfs.sh --start-index 0 quicksort/quicksort_test.yaml
```

The test reads the test case index from memory address `0xAA000000` and:

1. Generates an array based on the test case parameters
2. Sorts the array using the quicksort algorithm
3. Verifies the array is properly sorted
4. Returns 0 for success, 1 for failure, or 42 for out-of-bounds index