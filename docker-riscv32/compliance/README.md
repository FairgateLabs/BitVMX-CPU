# RISCV-32 Compliance Test 

### Build the image
`docker build -t riscv32compliance .`


### Run the container
`docker run -v %cd%:/data -it --name riscv32compliance riscv32compliance:latest`
`docker rm riscv32compliance`

### Build all the test cases
`./build_all.sh`

### Testing
Once the resulting files are placed on the build folder, running `cargo test` on the emulator folder will also test these files.
