# BitVMX-CPU TEST 

## Run complete test suite
  ```bash
  cargo test
  ```

## Run particular test
  ```bash
  cargo test test_example
  ```

## Run complete test suite with code coverage
  ```bash
  cargo tarpaulin -out Html --output-dir tests/resources
  ```
  - We can output the coverage report in differents formats, like Json