@echo off
title BettingShield Mobile Hub & Testing Suite
echo =======================================================
echo   🛡️  Starting BettingShield Mobile Hub & Testing Suite
echo   Testing on: Android & iOS Devices
echo =======================================================
echo.
set "PATH=C:\Program Files\nodejs;%PATH%"
cd /d "%~dp0web-hub"
node server.js
pause
