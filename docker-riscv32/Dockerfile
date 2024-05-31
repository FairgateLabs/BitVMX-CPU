# This file was taken from: https://github.com/halseth/docker-riscv/blob/master/riscv32-toolchain/Dockerfile and modified.
# see https://github.com/riscv/riscv-gnu-toolchain

FROM ubuntu:22.04 as build

RUN apt-get -y update
RUN apt-get -y install git autoconf automake autotools-dev curl libmpc-dev libmpfr-dev libgmp-dev gawk build-essential bison flex texinfo gperf libtool patchutils bc zlib1g-dev libexpat-dev
RUN apt-get -y install python3 # also required by riscv-gnu-toolchain
RUN apt-get -y install autoconf automake autotools-dev curl python3 python3-pip libmpc-dev libmpfr-dev libgmp-dev gawk build-essential bison flex texinfo gperf libtool patchutils bc zlib1g-dev libexpat-dev ninja-build git cmake libglib2.0-dev

RUN git config --global http.sslverify false

RUN mkdir /src && \
  cd /src && \
  git clone https://github.com/riscv/riscv-gnu-toolchain

# Build newlib toolchain
RUN cd /src/riscv-gnu-toolchain/ && \
  ./configure --prefix=/riscv32 --with-arch=rv32ia --with-abi=ilp32 && \
  make -j 8 # also installs

RUN apt-get -y install python3 pkg-config libglib2.0-dev libpixman-1-dev vim 

RUN apt-get update -y && \
  apt-get install -y libmpc-dev libmpfr-dev libgmp-dev && \
  rm -rf /var/lib/apt/lists/*

RUN cd /src && \
  git clone https://git.qemu.org/git/qemu.git && \
  cd qemu && \
  ./configure --prefix=/riscv32 --static --disable-system --target-list=riscv32-linux-user && \
  make -j 8 && \
  make install

ENV PATH /riscv32/bin:$PATH

ENV CC riscv32-unknown-elf-gcc
ENV CXX riscv32-unknown-elf-c++
ENV CPP riscv32-unknown-elf-cpp
ENV AS riscv32-unknown-elf-as
ENV LD riscv32-unknown-elf-ld
ENV AR riscv32-unknown-elf-ar
ENV DUMP riscv32-unknown-elf-objdump
ENV RANLIB riscv32-unknown-elf-ranlib
ENV HOST riscv32-unknown-elf
ENV QEMU qemu-riscv32 -L /riscv32/sysroot 

WORKDIR /data