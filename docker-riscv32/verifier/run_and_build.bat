@echo off
set MUL_FLAG=""

copy ..\link.ld .\link.ld
copy ..\entrypoint.s .\start.S


REM Check if --with-mul is passed as an argument
for %%i in (%*) do (
    if "%%i"=="--with-mul" (
        set MUL_FLAG=--with-mul
    )
)

if  "%MUL_FLAG%"=="--with-mul" (
    echo "Genereating version with RISCV Multiplication extension"
    docker run -v %cd%:/data -it --name verifier verifier:latest sh -c "/data/build.sh --with-mul"
) else (
    echo "Generating version with RISV32-i (no multiplication extension)"
    docker run -v %cd%:/data -it --name verifier verifier:latest sh -c "/data/build.sh"
)
docker rm verifier