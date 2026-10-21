@echo off
setlocal

echo ====================================
echo   EasyJWT - Setup
echo ====================================
echo.

where docker >nul 2>&1
if errorlevel 1 (
    echo Docker was not found on this machine.
    echo Install Docker Desktop first from https://www.docker.com/products/docker-desktop
    echo Then run this setup.bat again.
    goto :end
)

echo Docker found, checking if Docker is running...
docker info >nul 2>&1
if errorlevel 1 (
    echo Docker is installed but not running.
    echo Please start Docker Desktop, wait until it is ready, then run setup.bat again.
    goto :end
)

echo Docker is running.
echo.

if not exist wordlists (
    echo Creating wordlists folder...
    mkdir wordlists
)

echo.
echo Building the web UI image, this also pulls jwt_tool as its base...
docker compose build
if errorlevel 1 (
    echo.
    echo Failed to build the image. Check your internet connection and try again.
    goto :end
)

echo.
echo ====================================
echo   Setup complete
echo ====================================
echo.
echo The image is ready. The container has not been started yet.
echo.
echo Next steps:
echo   1. Drop a wordlist file into the wordlists folder.
echo   2. Run start.bat to start the toolkit and open it in your browser.
echo.

:end
pause
