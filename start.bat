@echo off
setlocal
title EasyJWT

echo Starting container...
docker compose up -d
if errorlevel 1 (
    echo.
    echo Failed to start the container.
    echo Make sure Docker Desktop is running and you ran setup.bat first.
    pause
    goto :eof
)

echo.
echo Opening the web UI in your browser...
start "" http://localhost:5000

echo.
echo The toolkit is running at http://localhost:5000
echo Run shutdown.bat when you are done, it stops the container without removing it.
echo.
pause
