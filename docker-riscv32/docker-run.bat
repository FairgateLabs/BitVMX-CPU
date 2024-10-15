@echo off
REM Check if at least two arguments are provided
IF "%~2"=="" (
    echo Usage: %0 container_name script_name [arguments]
    exit /b 1
)

REM Extract the first argument as the container name
SET container_name=%1

REM Extract the second argument as the script name
SET script_name=%2

REM Shift the arguments so that the rest can be passed as %arguments%
SHIFT
SHIFT

REM Initialize an empty arguments variable
SET arguments=

REM Collect all remaining arguments
:loop
IF "%~1"=="" GOTO after_loop
SET arguments=%arguments% %1
SHIFT
GOTO loop

:after_loop

echo Using %container_name% to execute script %script_name% with arguments:%arguments%

REM Run the Docker container with the provided container and image name, and script and arguments
docker run -v %cd%:/data -it --name %container_name% %container_name%:latest sh -c "dos2unix /data/%script_name% && /data/%script_name% %arguments%"

REM Remove the Docker container after completion
docker rm %container_name%
