cd /src/bitvmx-zk-verifier
mkdir bin

rm obj/*.o
rm mcl/obj/*.o
rm mcl/lib/*

cp /data/verifier/constants.h /src/bitvmx-zk-verifier/groth16-verifier/constants.h
cp /data/linker/link.ld /src/bitvmx-zk-verifier/linkers/link.ld
cp /data/src/entrypoint.s /src/bitvmx-zk-verifier/start.S

# Check if --with-mul is passed as an argument
if [[ " $@ " =~ " --with-mul " ]]; then
    make zkverifier CUSTOM_FLAGS="-march=rv32im -mabi=ilp32 -O3" INPUT_SECTION=0xAA000000
    cp bin/zkverifier /data/verifier/build/zkverifier-new-mul
else
    make zkverifier CUSTOM_FLAGS="-march=rv32i -mabi=ilp32 -O3" INPUT_SECTION=0xAA000000
    cp bin/zkverifier /data/verifier/build/zkverifier-new
fi
