cd compliance
chmod +x build.sh
chmod +x build_mul.sh
dos2unix build.sh
dos2unix build_mul.sh
for f in /riscv-tests/isa/rv32ui/*.S; do
  filename=$(basename "${f%.*}")
  if [[ "$filename" != "fence_i" ]]; then
     echo "$filename"
    ./build.sh "$filename"
  fi
done

for f in /riscv-tests/isa/rv32um/*.S; do
  filename=$(basename "${f%.*}")
  if [[ "$filename" != "fence_i" ]]; then
     echo "$filename"
    ./build_mul.sh "$filename"
 fi
done