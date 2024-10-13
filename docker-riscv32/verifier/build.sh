cd /src/bitvmx-zk-verifier
mkdir bin

rm obj/*.o
rm mcl/obj/*.o
rm mcl/lib/*

cp /data/constants.h /src/bitvmx-zk-verifier/groth16-verifier/constants.h
cp /data/link.ld /src/bitvmx-zk-verifier/linkers/link.ld
cp /data/start.S /src/bitvmx-zk-verifier/start.S

make zkverifier CUSTOM_FLAGS="-march=rv32i -mabi=ilp32"
cp bin/zkverifier /data/zkverifier-new