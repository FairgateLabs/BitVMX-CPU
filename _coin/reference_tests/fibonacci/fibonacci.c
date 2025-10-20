// Read a 32-bit word from the memory-mapped address.
#define INPUT_ADDRESS ((volatile unsigned int *)0xAA000000)

// The maximum N before a 32-bit unsigned int overflows. F(47) is the last valid result.
#define MAX_FIB_N 47

typedef struct {
    unsigned int n;
    unsigned int expected_result;
} FibonacciTestVector;

// Test vectors are now limited to results that fit within a 32-bit integer.
static const FibonacciTestVector test_vectors[] = {
    {1, 1},
    {2, 1},
    {5, 5},
    {10, 55},
    {20, 6765},
    {30, 832040},
    {40, 102334155},
    {45, 1134903170},
    {46, 1836311903},
    {47, 2971215073}
};

static unsigned int cache[MAX_FIB_N + 1];

// All calculations use the native 32-bit 'unsigned int'.
unsigned int fib_memo(unsigned int n) {
    if (n <= 2) {
        return 1;
    }
    if (cache[n] != 0) {
        return cache[n];
    }
    // Note: The addition here can overflow if n > 47.
    unsigned int result = fib_memo(n - 1) + fib_memo(n - 2);
    cache[n] = result;
    return result;
}

unsigned int fib(unsigned int n) {
    if (n == 0) return 0;
    if (n > MAX_FIB_N) return 0; 

    for (int i = 0; i <= MAX_FIB_N; ++i) {
        cache[i] = 0;
    }
    cache[1] = 1;
    cache[2] = 1;

    return fib_memo(n);
}


int main() {
    unsigned int test_index = *INPUT_ADDRESS;

    if (test_index >= (sizeof(test_vectors) / sizeof(FibonacciTestVector))) {
        return 42; // Failure: index is out of bounds.
    }

    const FibonacciTestVector* selected_test = &test_vectors[test_index];

    // Calculate the Fibonacci number.
    unsigned int result = fib(selected_test->n);

    // Check if the result matches the expected outcome.
    if (result == selected_test->expected_result) {
        return 0; // Success
    }
    else {
        return 1; // Failure
    }
}