docker run -v %cd%:/data -it --name riscv32 riscv32:latest sh -c /data/build.sh
docker rm riscv32