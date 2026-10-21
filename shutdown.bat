@echo off
setlocal

echo ====================================
echo   EasyJWT - Shutdown
echo ====================================
echo.
echo Stopping container, this does not remove it or its data.
echo.

docker compose stop
if errorlevel 1 (
    echo.
    echo Could not stop the container. It may already be stopped,
    echo or Docker Desktop may not be running.
) else (
    echo.
    echo Container stopped. Run start.bat any time to bring it back.
)

echo.
pause
