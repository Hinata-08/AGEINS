# AGEINS Cyber Guard

AGEINS is a lightweight, pure‑HTML/CSS/JavaScript frontend paired with a FastAPI backend written in Python. It detects:
- Phishing URLs
- Malicious emails (using NLP)
- Deepfake images, audio, and video
- Audio/Video synthetic media

## Features
- Real‑time risk scoring (0‑100) with colour‑coded tiers (green < 40, yellow 40‑79, red ≥ 80)
- Dashboard with live telemetry
- AI chat assistant for quick help
- Admin panel to adjust risk thresholds and retrain models on real Kaggle/MBOX data
- Zero‑trust data protection – no user data is persisted on the server

## Quick Start
1. **Backend** – Open a PowerShell terminal in `backend` and run:
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   uvicorn main:app --host 0.0.0.0 --port 8000
   ```
2. **Frontend** – Open `frontend/index.html` in a browser (or serve the `Ageins_2026` folder via any static server).
3. Visit `http://127.0.0.1:8000` to access the UI.

## Development
- Edit HTML/CSS/JS in the `frontend` folder; changes are hot‑reloaded when you refresh the page.
- Backend endpoints are documented at `http://127.0.0.1:8000/docs`.
- To retrain models on new data, drop CSV/mbox files into `backend/data/` and click **Execute Model Retrain** in the Admin tab.

## License
MIT – feel free to fork, modify, and deploy.
