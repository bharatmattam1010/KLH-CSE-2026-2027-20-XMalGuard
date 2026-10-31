@echo off
echo Starting XMalGuard Servers...

echo Starting FastAPI Backend on port 8000...
start "XMalGuard Backend" /D "C:\Users\bhara\.gemini\antigravity\scratch\XMalGuard\src\backend" "C:\Users\bhara\.gemini\antigravity\scratch\XMalGuard\src\backend\.venv\Scripts\python.exe" -m uvicorn app.main:app --host 0.0.0.0 --port 8000

echo Starting Vite Frontend on port 3000...
start "XMalGuard Frontend" /D "C:\Users\bhara\.gemini\antigravity\scratch\XMalGuard\src\frontend" cmd /c "npm run dev -- --host 0.0.0.0 --port 3000"

echo Both servers are booting up!
echo FastAPI Documentation: http://localhost:8000/docs
echo Frontend Dashboard:    http://localhost:3000
