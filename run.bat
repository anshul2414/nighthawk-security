@echo off
echo.
echo  ============================================
echo   NightHawk Pro v2  --  16 Security Modules
echo  ============================================
echo.
echo  Building and starting Docker container...
echo.
docker compose up --build -d
echo.
echo  Done!  Open your browser at:
echo  http://localhost:8080
echo.
start http://localhost:8080
