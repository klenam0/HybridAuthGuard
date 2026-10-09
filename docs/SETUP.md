# Setup Guide

## Prerequisites

- Python 3.12+
- Node.js 18+ (tested on 24.x)
- [Ollama](https://ollama.com/) installed locally, with the `phi3:mini` model pulled
- (Optional, for retraining) the [RBA Dataset](https://github.com/vs-uulm/2021-RBA-Dataset) CSV

A pre-trained model is distributed as a [GitHub Release asset](https://github.com/klenam0/HybridAuthGuard/releases/tag/v2.0.0-model) rather than committed directly (it's about 390 MB). Download it and place it at `backend/data/model.pkl` before running the pipeline - see "Getting the pre-trained model" below.

### Getting the pre-trained model

The trained Isolation Forest (`backend/data/model.pkl`, about 390 MB) is distributed as a [GitHub Release asset](https://github.com/klenam0/HybridAuthGuard/releases/tag/v2.0.0-model) rather than committed to the repository.
This model was trained and pickled under `scikit-learn==1.8.0`. Loading it with a substantially different scikit-learn version may produce warnings or, in rare cases, fail to unpickle - install from `requirements.txt` exactly, or retrain locally if you need a different version.

**Download it and place it at `backend/data/model.pkl` before running `main.py`.** If this file is absent, the system will not error out - it silently falls back to training a weaker synthetic 5-feature model instead of loading the RBA-trained 10-feature one, which will not reproduce the reported precision/recall/F1 figures.

## 1. Clone and enter the repo

```bash
git clone https://github.com/klenam0/HybridAuthGuard.git
cd HybridAuthGuard
```

## 2. Backend setup

```bash
cd backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt --break-system-packages

cp .env.example .env
# Edit .env with your own values - see "Environment Variables" below
```

`.env` is never committed. If you delete or lose it, restore it from the template with `cp .env.example .env` and fill the values in again.

### Environment Variables (`backend/.env`)

| Variable         | Required    | Purpose                                                                                |
| ---------------- | ----------- | -------------------------------------------------------------------------------------- |
| `EMAIL_SENDER`   | No          | Gmail address used to send HIGH-severity alert emails                                  |
| `EMAIL_PASSWORD` | No          | Gmail **app password** (not your account password)                                     |
| `EMAIL_RECEIVER` | No          | Where alert emails are sent                                                            |
| `RBA_DATASET_PATH` | No        | Path to the RBA Dataset CSV; only needed to retrain. Defaults to `backend/data/rba-dataset.csv` |
| `CLEAR_TOKEN`    | Recommended | Bearer token required to clear alerts / the live queue via the API. Generate one with: |

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

If `EMAIL_*` variables are left blank, the system runs fine - email alerting is disabled gracefully and simulated actions are still logged. If `CLEAR_TOKEN` is left unset, requests to the clear/restore/queue-clear endpoints are refused until it's set.

### Running the backend

**Batch/demo mode** - generates synthetic logs, guarantees all six attack scenarios fire, then exits:

```bash
python main.py --delay 0.1
```

**Live mode** - requires three terminals:

```bash
# Terminal 1 - the persistent API + LLM enrichment service
python api.py

# Terminal 2 - the live-polling detection pipeline
python main.py --live

# Terminal 3 - a continuous simulated event stream
python live_simulator.py --rate 1.0 --attack-interval 60
```

**Retraining the ML model** (optional - requires the RBA Dataset CSV):

```bash
# Set RBA_DATASET_PATH in backend/.env to point at your local copy,
# or place the CSV at backend/data/rba-dataset.csv (the default)
python ml/train_from_dataset.py
```

The experiment scripts (`ml/train_from_dataset_v*.py`, `ml/evaluate_*.py`) read the same variable and write their results to `backend/results/` - see `backend/results/README.md`.

## 3. Frontend setup

```bash
cd frontend
npm install
cp .env.example .env
npm start
```

The dashboard runs at `http://localhost:3000` and expects the API at `http://localhost:5000/api` (set in `frontend/src/config/api.js`).

`frontend/.env` holds one variable, `REACT_APP_CLEAR_TOKEN`, which must match `CLEAR_TOKEN` in `backend/.env`. Without it the Settings page's **Clear Alerts** button stays disabled. As with the backend, restore a lost `frontend/.env` with `cp .env.example .env`.

## 4. Verifying everything works

1. Run batch mode (`python main.py --delay 0.1`) - you should see six attack scenarios fire in the console, and `backend/data/alerts.json` should be populated.
2. Open the dashboard - the "Alert Log" and "MITRE Mapping" pages should show six alert types.
3. If Ollama is running with `phi3:mini` pulled, alerts should transition from a template explanation to an AI-generated one within ~10–90 seconds (watch the "AI Enriching..." badge in the Alert Log).

## Common Issues

**Live mode appears "stuck," nothing writes to `alerts.json`:**
Almost always a mismatch between `live_queue.jsonl` and `live_queue.jsonl.cursor` - see the invariant note in `docs/ARCHITECTURE.md`. Reset both together via:

```bash
curl -X POST http://localhost:5000/api/queue/clear -H "X-Clear-Token: <your token>"
```

**`CLEAR_TOKEN` changes don't seem to take effect:**
Make sure `.env` is actually being loaded by the process that serves the endpoint you're calling - `api.py` needs its own `load_dotenv()` call; it does not inherit environment loading from other modules.

**LLM enrichment never completes:**
Confirm Ollama is running (`ollama serve`) and the model is pulled (`ollama pull phi3:mini`). On low-VRAM GPUs, expect 60–90 seconds per alert; this is expected, not a bug - enrichment runs asynchronously so it never blocks detection.

---
