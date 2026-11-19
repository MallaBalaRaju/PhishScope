@echo off
echo ===================================================
echo   Starting PhishScope Full-Stack & ML Services
echo ===================================================
echo.

cd /d "%~dp0"

echo [1/2] Launching Python ML Microservice (Port 8000)...
start "PhishScope ML Service (Port 8000)" cmd /k "cd ml-service && call venv\Scripts\activate.bat && python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload"

echo [2/2] Launching PhishScope Web Application (Port 3000)...
start "PhishScope Web App (Port 3000)" cmd /k "npm run dev"

echo.
echo ===================================================
echo   Both services are starting in separate windows!
echo   - ML Service: http://127.0.0.1:8000/docs
echo   - Web App   : http://localhost:3000
echo ===================================================
echo.
timeout /t 3 >nul
start http://localhost:3000
