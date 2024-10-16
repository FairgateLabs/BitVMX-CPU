docker pull ljmf00/archlinux
docker build -t archlinux:latest -f riscv32/Docker.arch riscv32
docker build --build-arg INSTALL_QEMU=false -t riscv32:latest  riscv32 
docker build -t compliance:latest compliance
docker build -t verifier:latest verifier
