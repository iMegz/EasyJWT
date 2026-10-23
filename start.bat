@echo off
setlocal
title EasyJWT

echo ====================================
echo   EasyJWT
echo ====================================
echo.

where docker >nul 2>&1
if errorlevel 1 (
    echo Docker was not found on this machine.
    echo Install Docker Desktop first from https://www.docker.com/products/docker-desktop
    echo Then run start.bat again.
    pause
    goto :eof
)

echo Checking Docker is running...
docker info >nul 2>&1
if errorlevel 1 (
    echo Docker is installed but not running.
    echo Please start Docker Desktop, wait until it is ready, then run start.bat again.
    pause
    goto :eof
)

if not exist wordlists (
    echo Creating wordlists folder...
    mkdir wordlists
)

if exist ".git" (
    where git >nul 2>&1
    if not errorlevel 1 (
        git diff --quiet >nul 2>&1
        git diff --cached --quiet >nul 2>&1
        if errorlevel 1 (
            echo You have local changes, skipping update check so nothing gets overwritten.
        ) else (
            echo Checking for updates...
            git pull --ff-only >nul 2>&1
            if errorlevel 1 (
                echo Could not check for updates right now, continuing with what you have.
            )
        )
    )
)

echo.
echo Building the image, this makes sure you are always running the latest version...
echo ^(usually quick on later runs, Docker only rebuilds what actually changed. The
echo  very first build is the exception: it compiles gmpy2 and the crypto library
echo  from source, which can take several minutes, that is expected, not stuck^)
docker compose build
if errorlevel 1 (
    echo.
    echo Failed to build the image. Check your internet connection and try again.
    pause
    goto :eof
)

echo.
echo Starting container...
docker compose up -d
if errorlevel 1 (
    echo.
    echo Failed to start the container.
    echo Make sure Docker Desktop is running.
    pause
    goto :eof
)

echo.
echo Opening the web UI in your browser...
start "" http://localhost:5000

echo.
echo The toolkit is running at http://localhost:5000, always the latest version.
echo Run shutdown.bat when you are done, it stops the container without removing it.
echo.
pause
