@echo off
echo ======================================================================
echo           AGEINS CYBER GUARD - Universal Defense Matrix
echo       Pure HTML/CSS/JS + FastAPI + Trained on Kaggle/MBOX Datasets
echo ======================================================================
echo.

cd /d "%~dp0"

echo [1/3] Verifying Python Environment ^& Real Data Models...
if not exist "backend\models\phishing_url_model.joblib" (
    echo [ML Training] Training models on real Kaggle CSV and Nazario MBOX data...
    python backend\train_on_real_data.py
) else (
    echo [ML Status] Models already trained on real Kaggle ^& MBOX datasets!
)

echo.
echo [2/3] Starting AGEINS Cyber Intelligence Core on http://127.0.0.1:8000...
start "AGEINS Cyber Guard Server" cmd /k "cd /d %~dp0backend && python main.py"

echo.
echo [3/3] Initializing Web Interface...
timeout /t 2 /nobreak >nul

start "" "http://127.0.0.1:8000"

echo.
echo ======================================================================
echo AGEINS Cyber Guard is LIVE and OPERATIONAL!
echo Web Portal:       http://127.0.0.1:8000
echo Direct File:      %~dp0index.html
echo API Docs:         http://127.0.0.1:8000/docs
echo ======================================================================
pause
