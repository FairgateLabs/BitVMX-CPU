This `Dockerfile` supports building and emulating riscv32 architecture.

### Build the image
`docker build -t riscv32 .`

### Running the docker container
This command will run the docker file and mount the current dir inside `/data`

Win: `docker run -v %cd%:/data -it --name riscv32 riscv32:latest`

linux/mac: `docker run -v $(pwd):/data -it --name riscv32 riscv32:latest`

### Remove the container after use
`docker rm riscv32`

### Inside the Dcoker file

### Compiling

#### C++
`$CXX test.cpp -o test.elf`

#### Plain C into asm
`$CC -S plainc.c`

#### Linking with entrypoint
`$CC -nostdlib entrypoint.s plainc.s -o plainc.elf`

It's also possible to define the linking address space using link.ld file 

`$CC -nostdlib -T link.ld entrypoint.s plainc.s -o plainc.elf`

#### Dissasembling 
`$DUMP -d test.elf >trace.s`

### Running in QEMU
`$QEMU test.elf` (you should get "Hello, World!" printed)

`$QEMU -d in_asm -D traces.txt test.elf` to produce asm traces. Check other `$QEMU -h` for other traces.


### Aknowledge:
The Dockerfile and some instructions were taken and modified from: https://github.com/halseth/docker-riscv forked from (https://github.com/rene-fonseca/docker-riscv) 
