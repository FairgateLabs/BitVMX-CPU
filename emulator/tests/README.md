# BitVMX-CPU - Local 

## Run complete test suite
  ```bash
  cargo test
  ```

## Run particular test
  ```bash
  cargo test test_example
  ```

## Run complete test suite with code coverage (tarpaulin)
  ```bash
  cargo tarpaulin --out Html --output-dir tests/resources --no-fail-fast --exclude-files bitcoin-script-riscv/*
  ```
  - We can output the coverage report in differents formats, like Json, Xml, etc.
<br>
<br>
<br>
# CI/CD Test
There is configured a **GitHub** action to run test on each PR to a branch **main** 

- For each PR it will run a GH action that executes the whole test suite.
- If you want to get the test **coverage**, you can add **[cov]** in the PR name and will execute the test action with coverage.

Coverage results will be automatically published in PR description