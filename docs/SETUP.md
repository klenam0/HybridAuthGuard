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

**Download it and place it at `backend/data/model.pkl` before running `main.py`.** If the file is missing or cannot be loaded, `main.py` stops with an error and does not train or overwrite anything. To run without the RBA model, train the small synthetic 5-feature demo model explicitly with `python main.py --retrain`; it does not reproduce the reported precision/recall/F1 figures. `--retrain` refuses to replace an RBA-trained `model.pkl` unless you add `--force`, and even then the old file is renamed to `model.pkl.replaced-<timestamp>` rather than deleted. On every start `main.py` rewrites `backend/data/model_metrics.json` if it does not describe the loaded model, so the dashboard always shows the metrics of the model actually in use.

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
| `ADMIN_TOKEN`    | Yes, for admin actions | Required (header `X-Admin-Token`) for `/api/run`, clearing or restoring alerts, and clearing the live queue. `CLEAR_TOKEN` is accepted as the older name. |
| `INGEST_TOKEN`   | Yes, for live mode | Required (header `X-Ingest-Token`) by `/api/ingest`. `live_simulator.py` reads it from this file. Give log sources this token, not the admin one. |
| `DASHBOARD_ORIGINS` | No       | Comma-separated browser origins allowed by CORS. Defaults to `http://localhost:3000,http://127.0.0.1:3000`. |

Generate each token with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

If `EMAIL_*` variables are left blank, the system runs fine - email alerting is disabled gracefully and simulated actions are still logged. The token-protected endpoints fail closed: if `ADMIN_TOKEN` (or `CLEAR_TOKEN`) or `INGEST_TOKEN` is unset, the matching endpoints refuse every request until it is set. `/api/run` keeps existing alerts unless its JSON body sets `"fresh": true`.

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

No secrets go in `frontend/.env`: every `REACT_APP_*` value is compiled into the public JavaScript bundle. The admin token is typed into the dashboard at runtime (Settings page, or the prompt that appears the first time you press **Run**) and kept in that tab's memory only. If an older `frontend/.env` still sets `REACT_APP_CLEAR_TOKEN`, delete that line; the code no longer reads it.

## 4. Verifying everything works

1. Run batch mode (`python main.py --delay 0.1`) - you should see six attack scenarios fire in the console, and `backend/data/alerts.json` should be populated.
2. Open the dashboard - the "Alert Log" and "MITRE Mapping" pages should show six alert types.
3. If Ollama is running with `phi3:mini` pulled, alerts should transition from a template explanation to an AI-generated one within ~10–90 seconds (watch the "AI Enriching..." badge in the Alert Log).

## Common Issues

**Live mode appears "stuck," nothing writes to `alerts.json`:**
Almost always a mismatch between `live_queue.jsonl` and `live_queue.jsonl.cursor` - see the invariant note in `docs/ARCHITECTURE.md`. Reset both together via:

```bash
curl -X POST http://localhost:5000/api/queue/clear -H "X-Admin-Token: <your token>"
```

Events that fail validation or processing are skipped and written to `backend/data/live_queue.deadletter.jsonl` instead of stopping live mode.

**Token changes don't seem to take effect:**
Make sure `.env` is actually being loaded by the process that serves the endpoint you're calling - `api.py` needs its own `load_dotenv()` call; it does not inherit environment loading from other modules.

**LLM enrichment never completes:**
Confirm Ollama is running (`ollama serve`) and the model is pulled (`ollama pull phi3:mini`). On low-VRAM GPUs, expect 60–90 seconds per alert; this is expected, not a bug - enrichment runs asynchronously so it never blocks detection.

---
