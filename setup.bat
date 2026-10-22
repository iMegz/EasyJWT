@echo off
setlocal

echo ====================================
echo   EasyJWT - Setup
echo ====================================
echo.
echo setup.bat is no longer a separate step, start.bat now checks Docker,
echo pulls the latest code, builds the image, and starts the toolkit all
echo by itself. Running start.bat below for you.
echo.
pause

call "%~dp0start.bat"
