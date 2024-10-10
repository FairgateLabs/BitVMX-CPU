@echo off
REM Check if an argument is provided
IF "%~1"=="" (
    echo Usage: %0 input_filename
    exit /b 1
)

REM Set the input filename from the argument
SET input_filename=%1

REM Run the Docker container and pass the filename to the build script
docker run -v %cd%:/data -it --name riscv32 riscv32:latest sh -c "/data/build.sh %input_filename%"

REM Remove the Docker container after completion
docker rm riscv32
