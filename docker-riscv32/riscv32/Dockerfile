FROM archlinux:latest

# Install dependencies
RUN pacman -Syu --noconfirm \
    && pacman -S --noconfirm base-devel git sudo vim

RUN pacman -Syu --noconfirm autoconf automake curl python3 libmpc mpfr gmp gawk base-devel bison flex texinfo gperf libtool patchutils bc zlib expat libslirp

RUN mkdir /src && \
  cd /src && \
  git clone https://github.com/riscv/riscv-gnu-toolchain --branch 2024.09.03

RUN cd /src/riscv-gnu-toolchain/ && \
  ./configure --prefix=/riscv32 --with-arch=rv32im --with-abi=ilp32 && \
  make -j 8 

#get some files to compile multiplication and division for riscv32
RUN cd /src && curl -LJO https://github.com/gcc-mirror/gcc/raw/master/libgcc/config/epiphany/mulsi3.c \
            && curl -LJO https://github.com/gcc-mirror/gcc/raw/master/libgcc/config/riscv/riscv-asm.h \ 
            && curl -LJO https://github.com/gcc-mirror/gcc/raw/master/libgcc/config/riscv/div.S 


# Define a build argument (default to false)
ARG INSTALL_QEMU=true

# Update the package manager and optionally install qemu-full based on the argument
RUN pacman -Sy --noconfirm && \
    if [ "$INSTALL_QEMU" = "true" ]; then \
        pacman -S --noconfirm qemu-full; \
    fi

RUN pacman -Sy --noconfirm dos2unix

ENV PATH=/riscv32/bin:$PATH

ENV CC=riscv32-unknown-elf-gcc
ENV CXX=riscv32-unknown-elf-c++
ENV CPP=riscv32-unknown-elf-cpp
ENV AS=riscv32-unknown-elf-as
ENV LD=riscv32-unknown-elf-ld
ENV AR=riscv32-unknown-elf-ar
ENV DUMP=riscv32-unknown-elf-objdump
ENV RANLIB=riscv32-unknown-elf-ranlib
ENV HOST=riscv32-unknown-elf
ENV QEMU=qemu-riscv32

WORKDIR /data

# Default command
CMD ["/bin/bash"]