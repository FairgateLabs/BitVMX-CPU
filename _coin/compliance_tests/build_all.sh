echo "Executing build_all.sh"
chmod +x build.sh
chmod +x build_mul.sh
dos2unix build.sh
dos2unix build_mul.sh

for f in /riscv-tests/isa/rv32ui/*.S; do
  filename=$(basename "${f%.*}")
  echo $filename
  ./build.sh $filename
done

for f in /riscv-tests/isa/rv32um/*.S; do
  filename=$(basename "${f%.*}")
  echo $filename
   ./build_mul.sh $filename
done