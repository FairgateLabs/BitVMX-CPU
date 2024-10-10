## Build Environment

This folder contains the necessary files to create a program that can be run in the BitVMX-CPU.
To simplify the environment and the build tools required to build for RISCV-32 architecture a Dockerfile is provided. 


### Build the image
Run
`docker build -t riscv32 .`

### Running the docker container
This command will run the docker file and mount the current dir inside `/data`

Win: `docker run -v %cd%:/data -it --name riscv32 riscv32:latest`

linux/mac: `docker run -v $(pwd):/data -it --name riscv32 riscv32:latest`

For simplicity `run.bat` and `run.sh` are provided

### Remove the container after use
`docker rm riscv32`
(this step is done automatically by the previous `run.bat` and `run.sh` commands)

### Inside the Docker Container

### Compiling

#### build.sh
Use `build.sh FILE_NAME.c` to generate the .elf file. (It might be necessary to `chmod +x` the file to execute it)

Before creating your own `.c` file please take a look at some of the examples: `hello-world.c` `plain.c` or `test_input.c` and also the build script (`build.sh`) itself.

Some requirements are:

The `.c` file needs to include at least this part:
```
    #include "emulator.h"
    #include <stdint.h>

    int main(int x) {
        return 0;
    }
```
And the file needs to be linked using `linkd.ld` file which describes the memory sections of the files and using `entrypoint.s` which defines the real entrypoint and calls main.


### Compliance
The compliance folder contains a Docker file that is used to generate the RISCV compliance tests files.

### Verifier
The verifier folder contains a Docker file that is used to generate the groth16 verifier.


### Acknowledgement:
The Dockerfile and some instructions were taken and modified from: https://github.com/halseth/docker-riscv forked from (https://github.com/rene-fonseca/docker-riscv) 
