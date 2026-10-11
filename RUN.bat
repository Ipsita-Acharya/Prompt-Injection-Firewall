python -m pip install -r requirements.txt
python -m pip install httpx==0.28.1
python -m pip install uvicorn==0.54.0
python -m pip install fastapi==0.142.2
python -m pip install markdown-it-py==4.2.0
python -m pip install scipy==1.15.3
python -m pip install scipy==1.18.1
python -m pip install scikit-learn==1.9.1


@echo off
REM ============================================================
REM  Prompt Injection Firewall - one-click launcher
REM
REM  Starts three components directly from the current folder:
REM    1. PIF API          scripts\main.py         -> port 8000
REM    2. UI_PIF Portal    UI_PIF\pif_portal.py    -> port 8081
REM    3. UI_AI_Replica    UI_AI_Replica\server.py -> port 8080
REM
REM  Opens each web page in the default browser.
REM  Close the three server windows to stop the components.
REM ============================================================

@echo off
for %%p in (8000 8080 8081) do (
    for /f "tokens=5" %%a in ('netstat -aon ^| findstr /r /c:":%%p .*LISTENING"') do (
        taskkill /F /PID %%a
    )
)

setlocal

set "ROOT=%~dp0"
set "PY=python"

REM Check that the scripts exist directly in the current folder
if not exist "%ROOT%scripts\main.py" (
    echo [RUN] ERROR: scripts\main.py not found next to RUN.bat
    pause
    exit /b 1
)

if not exist "%ROOT%UI_PIF\pif_portal.py" (
    echo [RUN] ERROR: UI_PIF\pif_portal.py not found
    pause
    exit /b 1
)

if not exist "%ROOT%UI_AI_Replica\server.py" (
    echo [RUN] ERROR: UI_AI_Replica\server.py not found
    pause
    exit /b 1
)

echo [RUN] Starting PIF API on http://127.0.0.1:8000 ...
start "PIF API :8000" /D "%ROOT%" cmd /k python scripts\main.py

echo [RUN] Starting UI_PIF Portal on http://127.0.0.1:8081 ...
start "UI_PIF Portal :8081" /D "%ROOT%" cmd /k python UI_PIF\pif_portal.py

echo [RUN] Starting UI_AI_Replica on http://127.0.0.1:8080 ...
start "UI_AI_Replica :8080" /D "%ROOT%" cmd /k python UI_AI_Replica\server.py

echo [RUN] Waiting for the servers to start ...
timeout /t 6 /nobreak >nul

echo [RUN] Opening web pages in the default browser ...
start "" http://127.0.0.1:8081
start "" http://127.0.0.1:8080
:: start "" http://127.0.0.1:8000/docs

echo.
echo [RUN] Launcher finished.
echo [RUN] Close the three server windows to stop the components.

endlocal