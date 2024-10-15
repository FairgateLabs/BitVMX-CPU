FROM riscv32:latest

WORKDIR /

RUN pacman -Syu --noconfirm && \
    pacman -S --noconfirm --needed clang git base-devel vim

RUN cd /src && \ 
    git clone -v --recursive https://github.com/FairgateLabs/bitvmx-zk-verifier --branch custom_flags

RUN cp -r /riscv32/riscv32-unknown-elf/include/* /src/bitvmx-zk-verifier/mcl/include/  




