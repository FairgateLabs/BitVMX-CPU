# RISC-V Compliance Tests

This directory contains compliance tests that extend the tests from [riscv-tests](https://github.com/riscv-software-src/riscv-tests).

## Building and Running Tests

### 1. Build the Docker Image

```bash
docker build -t riscv-coin .
```

### 2. Compile the Tests

```bash
sudo ./docker-run-coin-compliance.sh riscv-coin ./build_all.sh
```

### 3. Run the Tests

```bash
./run_tests.sh
```

To verify that all scripts provide the same result in Bitcoin, use the `--verify` flag:

```bash
./run_tests.sh --verify
```

## Understanding Test Failures

When tests fail, they will output something like `halt(5,200)`. To identify which test is failing:

1. Take the first number (5 in this example)
2. Subtract 1: `5 - 1 = 4`
3. Divide by 2: `4 / 2 = 2`

The result (2) is the test number that is failing.

## Options

- `./run_tests.sh` - Run tests without Bitcoin verification (faster)
- `./run_tests.sh --verify` - Run tests with Bitcoin verification (slower but more thorough)