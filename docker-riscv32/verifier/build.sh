cd /src/bitvmx-zk-verifier
mkdir bin

rm obj/*.o
cp /data/constants.h /src/bitvmx-zk-verifier/groth16-verifier/constants.h

make zkverifier
cp bin/zkverifier /data/zkverifier-new