@echo off
echo Starting XMalGuard Servers...

echo Starting FastAPI Backend...
start cmd /k "cd src\backend && .\.venv\Scripts\activate && uvicorn app.main:app --reload --port 8000"

echo Starting Vite Frontend...
start cmd /k "cd src\frontend && npm run dev"

echo Both servers are booting up! 
echo Dashboard will be available at http://localhost:3000
