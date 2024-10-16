./docker-run.sh riscv32 riscv32/build.sh src/plainc.c --with-mul
./docker-run.sh compliance compliance/build_all.sh
./docker-run.sh verifier verifier/build.sh --with-mul