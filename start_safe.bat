@echo off
echo Starting PhishAnalyzer v3.0...
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    pause
    exit /b 1
)

REM Check if required files exist
if not exist "phishanalyzer_unified.py" (
    echo ERROR: phishanalyzer_unified.py not found
    pause
    exit /b 1
)

if not exist "api.py" (
    echo ERROR: api.py not found
    pause
    exit /b 1
)

if not exist "random_forest_url_model.sav" (
    echo ERROR: ML model file not found
    pause
    exit /b 1
)

REM Check if dependencies are installed
echo Checking dependencies...
python -c "import fastapi, uvicorn, pandas, sklearn" >nul 2>&1
if errorlevel 1 (
    echo WARNING: Some dependencies may be missing
    echo Installing dependencies...
    pip install -r requirements.txt
)

echo Starting API server...
echo API will be available at: http://localhost:8000
echo.
python api.py

pause
