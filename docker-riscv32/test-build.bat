call docker-run.bat riscv32 riscv32/build.sh src/plainc.c --with-mul
call docker-run.bat compliance compliance/build_all.sh
call docker-run.bat verifier verifier/build.sh