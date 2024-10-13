FROM archlinux:latest

# Install dependencies
RUN pacman -Syu --noconfirm \
    && pacman -S --noconfirm base-devel git sudo

# Create a non-root user
RUN useradd -m builder \
    && echo "builder ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Switch to the non-root user
USER builder
WORKDIR /home/builder

# Install yay (an AUR helper)
RUN git clone https://aur.archlinux.org/yay.git /home/builder/yay \
    && cd /home/builder/yay \
    && makepkg -si --noconfirm

# Install riscv-gnu-toolchain-bin from the AUR
RUN yay -S --noconfirm riscv-gnu-toolchain-bin

# Switch back to the root user to clean up
USER root

# Clean up unnecessary files to reduce image size
RUN pacman -Sc --noconfirm \
    && rm -rf /var/cache/pacman/pkg/* /home/builder/yay

# Set environment variables if needed
ENV PATH="/opt/riscv/bin:$PATH"

#get some files to compile multiplication and division for riscv32
RUN mkdir /src && cd /src && curl -LJO https://github.com/gcc-mirror/gcc/raw/master/libgcc/config/epiphany/mulsi3.c \
            && curl -LJO https://github.com/gcc-mirror/gcc/raw/master/libgcc/config/riscv/riscv-asm.h \ 
            && curl -LJO https://github.com/gcc-mirror/gcc/raw/master/libgcc/config/riscv/div.S 

ENV PATH /opt/riscv32-gnu-toolchain-elf-bin/bin:$PATH

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

# Default command
CMD ["/bin/bash"]
