FROM riscv32:latest

WORKDIR /

RUN apt-get update && \
    apt-get install -y --no-install-recommends clang

RUN cd /src && \ 
    git clone -v --recursive https://github.com/FairgateLabs/bitvmx-zk-verifier


RUN cp -r /src/riscv-gnu-toolchain/install-newlib-nano/riscv32-unknown-elf/include/* /src/bitvmx-zk-verifier/mcl/include/  

RUN cd /src/bitvmx-zk-verifier && \
    make 

