@echo off
REM Check if at least one argument is provided
IF "%~1"=="" (
    echo Usage: %0 input_filename [with_m_extension]
    exit /b 1
)

REM Set the input filename from the first argument
SET input_filename=%1

REM Check if the second argument is provided and set the script name accordingly
IF "%~2"=="" (
    SET script_name=build.sh
) ELSE (
    SET script_name=build_with_m.sh
)

REM Run the Docker container and pass the filename to the build script
docker run -v %cd%:/data -it --name riscv32 riscv32arch2:latest sh -c "/data/%script_name% %input_filename%"

REM Remove the Docker container after completion
docker rm riscv32
