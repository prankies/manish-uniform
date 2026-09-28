@echo off
title Manish Uniform (port 5004)
cd /d "%~dp0"
netstat -ano | findstr ":5004" | findstr "LISTENING" >nul
if %errorlevel%==0 (
    echo Manish Uniform is already running:  http://localhost:5004
    pause
    exit /b 0
)
pip show waitress >nul 2>&1 || pip install -r requirements.txt
python app.py
pause
