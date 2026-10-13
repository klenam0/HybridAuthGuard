# backend/eval/phase2_baseline.py
"""
Phase 2.4 baseline under eval/PROTOCOL.md: the CURRENT model design retrained
on dev_train and replayed over the development stream, with metrics on
dev_val and on its cold-start subset (dev_val_cold). This is the "before"
reference for Phases 3 to 5. The locked test month is never read.

Pipeline
  1. Load Feb-Apr 2020 (eval/datasets.py "dev") as agent events.
  2. One dry pass of the real DetectionAgent with a recording stub finds the
     events that reach score_event(). It depends only on rule state, never
     on the model, so it is shared by every seed and contamination value.
  3. Frequency maps, known sets and the StandardScaler come from the
     non-attack dev_train rows (ml/train_from_dataset.py, unchanged), so the
     raw features are seed-independent too.
  4. Per seed, one IsolationForest fit (200 trees, max_samples=100000).
     Contamination moves only offset_ (the 100*c percentile of the training
     score_samples, which is what scikit-learn computes), so each grid value
     is an offset shift, not a refit. Contamination is chosen as the deployed
     0.4 was (ml/train_from_dataset_v3*.py): highest Isolation Forest
     event-level F1 (predict == -1) on dev_val over the eleven-point grid, at
     seed 42, vectorised (PROTOCOL.md amendment 1).
  5. Rules only once; the hybrid at the chosen value for each seed, replayed
     through the real agents (eval/harness.py replay with a PrecomputedScorer
     holding the batch decisions) over the whole development stream, in
     worker processes. Metrics on dev_val, on dev_val without the
     placeholder user ID's events, and on dev_val_cold.

Run from backend/:
    python -m eval.phase2_baseline [--workers 2] [--seeds 42 43 44]
Writes results/phase2_baseline_devval.json and
results/phase2_baseline_devval_summary.txt.
"""

import argparse
import contextlib
import io
import json
import os
import sys
import tempfile
import time
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor

import numpy as np

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

import config  # noqa: E402
from eval import datasets, harness, streams  # noqa: E402

RESULTS = os.path.join(BACKEND, "results")
OUT_JSON = os.path.join(RESULTS, "phase2_baseline_devval.json")
OUT_TXT = os.path.join(RESULTS, "phase2_baseline_devval_summary.txt")

SWEEP_GRID = [0.02, 0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50]  # Batch 3.7 grid
SWEEP_SEED = 42
SEEDS = (42, 43, 44)
FPR_BUDGETS = (0.01, 0.05)
FOREST = dict(n_estimators=200, max_samples=100000, max_features=1.0, n_jobs=-1)
STREAM_COLS = ["Login Timestamp", "User ID", "IP Address", "Country", "Device Type",
               "Login Successful", "Is Attack IP", "Is Account Takeover"]
ML_TYPE = "ML Anomaly Detected"


# ── Data ─────────────────────────────────────────────────────────────────────

def load_stream():
    """events, truth, n_train (dev_train rows come first), cold dev_val positions,
    and the non-attack dev_train rows in the old pipeline's column shape."""
    import pandas as pd
    df = datasets.load("dev", columns=STREAM_COLS)
    n_train = int((df[datasets.TS] < datasets.DEV_TRAIN_END).sum())
    assert df[datasets.TS].iloc[:n_train].max() < datasets.DEV_TRAIN_END
    limit = int(os.environ.get("PHASE2_LIMIT", "0"))
    if limit:   # smoke test only: first `limit` rows, first half as "train"
        df = df.iloc[:limit]
        n_train = limit // 2
    events, truth = streams.events_from_frame(df)
    train_users = set(df["User ID"].iloc[:n_train].unique())
    cold = n_train + np.flatnonzero(~df["User ID"].iloc[n_train:].isin(train_users).to_numpy())

    tr = df.iloc[:n_train][~truth[:n_train]]
    train_df = pd.DataFrame({
        "Login Timestamp": tr[datasets.TS].to_numpy(),
        "User ID": tr["User ID"].to_numpy(),
        "IP Address": tr["IP Address"].astype(str).to_numpy(),
        # Empty strings in the Parquet are the CSV's empty fields, which the
        # old read_csv pipeline saw as NaN (-> "XX" / "Unknown").
        "Country": tr["Country"].astype(str).replace("", np.nan).to_numpy(),
        "Device Type": tr["Device Type"].astype(str).replace("", np.nan).to_numpy(),
        "Login Successful": tr["Login Successful"].to_numpy(),
    })
    return events, truth, n_train, cold, train_df


def dry_pass(events):
    """Positions of the events that reach score_event(), in order."""
    from agents.detection_agent import DetectionAgent

    class _Stub(harness._RecordingStub):
        def score_event(self, log_event):
            self.reached.append(log_event["_pos"])
            return {"is_anomaly": False, "anomaly_score": 0.0,
                    "confidence": "Low", "feature_count": 10}

    stub = _Stub()
    agent = DetectionAgent(threshold=config.BRUTE_FORCE_THRESHOLD, anomaly_detector=stub)
    with contextlib.redirect_stdout(io.StringIO()):
        for i, e in enumerate(events):
            d = dict(e)
            d["_pos"] = i
            agent.analyze_event(d)
    return np.asarray(stub.reached, dtype=np.int64)


# ── Model ────────────────────────────────────────────────────────────────────

class Prepared:
    """Seed-independent training artefacts (current design, ml/train_from_dataset.py)."""

    def __init__(self, train_df):
        from sklearn.preprocessing import StandardScaler
        sys.path.insert(0, os.path.join(BACKEND, "ml"))
        from train_from_dataset import extract_features_freq, fit_frequency_maps
        with contextlib.redirect_stdout(io.StringIO()):
            self.maps, self.known_ips, self.known_countries = fit_frequency_maps(train_df)
            X = extract_features_freq(train_df, self.maps, self.known_ips, self.known_countries)
        self.scaler = StandardScaler().fit(X)
        self.X_train = self.scaler.transform(X)
        self.n_train_rows = len(train_df)
        self.n_train_users = int(train_df["User ID"].nunique())

    def detector(self, model=None):
        from ml.anomaly_model import AnomalyDetector
        from ml.explainer import AlertExplainer
        d = AnomalyDetector()
        d.model, d.scaler = model, self.scaler
        d.explainer = AlertExplainer(self.scaler)
        d.encoding_scheme = "frequency"
        d.ip_freq_map, d.user_freq_map = self.maps["ip"], self.maps["user"]
        d.country_freq_map, d.device_freq_map = self.maps["country"], self.maps["device"]
        d.known_ips_set, d.known_countries_set = self.known_ips, self.known_countries
        d.feature_count, d.is_trained = 10, True
        return d


def score_samples(model, X, n_threads=os.cpu_count() or 4):
    """model.score_samples(X) over row chunks in threads. Rows are scored
    independently, so the result is bit-identical to one call (checked when
    this was added: 300,000 rows, np.array_equal), about 3x faster."""
    from joblib import Parallel, delayed
    if len(X) < 50_000:
        return model.score_samples(X)
    parts = Parallel(n_jobs=n_threads, prefer="threads")(
        delayed(model.score_samples)(c) for c in np.array_split(X, n_threads * 4))
    return np.concatenate(parts)


def fit_forest(X_train, seed):
    from sklearn.ensemble import IsolationForest
    m = IsolationForest(contamination=0.4, random_state=seed, **FOREST).fit(X_train)
    return m, score_samples(m, X_train)


# ── Scorer and replay ────────────────────────────────────────────────────────

class FixedScorer(harness.PrecomputedScorer):
    """PrecomputedScorer whose dry pass and batch scores were computed once,
    outside, for the same stream (see module docstring)."""

    def __init__(self, detector, keys, raw, decision):
        super().__init__(detector)
        self.keys, self.raw = keys, raw
        self.decision = decision
        self.pred = np.where(decision < 0, -1, 1)

    def prepare(self, events):
        self._i = 0
        self.calls = []
        return self


def replay_hybrid(ctx, decision):
    det = ctx["prepared"].detector()
    scorer = FixedScorer(det, ctx["keys"], ctx["raw_reached"], decision)
    return harness.replay(ctx["events"], scorer)


# ── Metrics ──────────────────────────────────────────────────────────────────

def subset_result(r, idx):
    """ReplayResult restricted to positions idx (sorted). Block indices are
    remapped so that 'event after block' keeps its meaning; blocks made before
    the first position map to -1 and still apply."""
    def remap(d):
        return {ip: int(np.searchsorted(idx, b, side="right")) - 1 for ip, b in d.items()}
    return harness.ReplayResult(
        len(idx), [r.alert_type[i] for i in idx], [r.severity[i] for i in idx],
        [r.confidence[i] for i in idx], r.ml_scored[idx],
        remap(r.rule_block_idx), remap(r.ml_block_idx), remap(r.response_block_idx),
        sum(1 for i in idx if r.severity[i] in config.EMAIL_SEVERITIES))


def tpr_at_budgets_binary(recall, fpr):
    return {f"tpr_at_{int(b * 100)}pct_fpr": (recall if fpr <= b else None) for b in FPR_BUDGETS}


def evaluate(r, events, truth, idx, scores=None):
    """Protocol metrics on positions idx of a full-stream ReplayResult r.
    scores: Isolation Forest decision values at idx (lower = more anomalous)."""
    from sklearn.metrics import average_precision_score, roc_auc_score, roc_curve
    sub = subset_result(r, idx)
    ev = [events[i] for i in idx]
    tr = truth[idx]
    s = harness.summarize(sub, ev, tr)
    f = sub.flagged
    p, rc = s["precision"], s["event_recall"]
    s["f1"] = 2 * p * rc / (p + rc) if (p + rc) else 0.0

    ip_attack = defaultdict(bool)
    ip_flag = defaultdict(bool)
    for e, t, fl in zip(ev, tr, f):
        ip_attack[e["ip"]] |= bool(t)
        ip_flag[e["ip"]] |= bool(fl)
    s["benign_ips_flagged"] = sum(1 for ip, a in ip_attack.items() if not a and ip_flag[ip])
    s["attacking_ips_flagged"] = int(round(s["campaign_recall"] * s["attacking_ips"]))

    by_type = defaultdict(Counter)
    for t, a in zip(sub.alert_type, tr):
        if t:
            by_type[t]["attack" if a else "benign"] += 1
    s["per_type"] = {t: {"alerts": c["attack"] + c["benign"], "attack": c["attack"],
                         "precision": c["attack"] / (c["attack"] + c["benign"])}
                     for t, c in sorted(by_type.items())}
    s["per_type_severity_confidence"] = {
        k: v for k, v in s.pop("breakdown").items()}
    s.update(tpr_at_budgets_binary(rc, s["fpr"]))
    if scores is not None:
        y, a = tr.astype(int), -np.asarray(scores)
        fpr, tpr, _ = roc_curve(y, a)
        s["roc_auc"] = float(roc_auc_score(y, a))
        s["pr_auc"] = float(average_precision_score(y, a))
        for b in FPR_BUDGETS:
            s[f"tpr_at_{int(b * 100)}pct_fpr"] = float(tpr[fpr <= b].max())
    return s


def if_only_result(decision_all):
    """Isolation Forest alone on every event: flag decision < ML_ALERT_MARGIN
    (and < 0, i.e. predict == -1); severity from the analysis policy; the
    simulated block is the first HIGH alert per IP."""
    d = np.asarray(decision_all)
    flag = (d < 0) & (d < config.ML_ALERT_MARGIN)
    high = d < config.CONFIDENCE_HIGH_CUTOFF
    conf = np.where(high, "High", np.where(d < config.CONFIDENCE_MEDIUM_CUTOFF, "Medium", "Low"))
    sev_high = config.ML_UPGRADE_SEVERITY
    sev_def = config.SEVERITY_MAP.get(ML_TYPE, config.DEFAULT_SEVERITY)
    types, sevs, confs = [None] * len(d), [None] * len(d), [None] * len(d)
    for i in np.flatnonzero(flag):
        types[i] = ML_TYPE
        confs[i] = str(conf[i])
        sevs[i] = sev_high if (confs[i] == config.ML_UPGRADE_CONFIDENCE) else sev_def
    return types, sevs, confs


def if_only_replay_result(events, decision_all):
    types, sevs, confs = if_only_result(decision_all)
    resp = {}
    for i, sv in enumerate(sevs):
        if sv in config.SIMULATED_BLOCK_SEVERITIES:
            resp.setdefault(events[i]["ip"], i)
    return harness.ReplayResult(len(events), types, sevs, confs,
                                np.ones(len(events), dtype=bool), {}, {}, resp, 0)


def headline(s):
    keys = ("event_recall", "fpr", "precision", "f1", "campaign_recall",
            "attacking_ips_flagged", "attacking_ips", "benign_ips_flagged", "alerts",
            "tpr_at_1pct_fpr", "tpr_at_5pct_fpr", "roc_auc", "pr_auc")
    out = {k: s[k] for k in keys if k in s}
    rb = s["response_blocks"]
    out.update(response_benign_ips_blocked=rb["benign_ips_blocked"],
               response_attack_ips_blocked=rb["attack_ips_blocked"],
               response_benign_users_affected=rb["benign_users_affected"],
               response_benign_events_after_block=rb["benign_events_after_block"])
    return out



# ── Placeholder user and Credential Stuffing reports ─────────────────────────

# The user ID that carries 37% of development rows and almost only failures
# (audit_scratch/PHASE2_DATA_REPORT.md): apparently the dataset's pseudonym for
# logins against unknown usernames. Reported separately; never filtered out
# of a replay.
PLACEHOLDER_USER = "-4324475583306591935"
CS_TYPE = "Credential Stuffing"


def report_parts(events, n_train, cold):
    """Positions of the reported subsets, and of the placeholder's dev_val events."""
    val = np.arange(n_train, len(events))
    ph = np.fromiter((events[i]["user"] == PLACEHOLDER_USER for i in val), bool, len(val))
    assert not any(events[i]["user"] == PLACEHOLDER_USER for i in cold)
    return ({"dev_val": val, "dev_val_excl_placeholder": val[~ph], "dev_val_cold": cold},
            val[ph])


def placeholder_report(r, truth, ph_idx):
    by_type = defaultdict(Counter)
    for i in ph_idx:
        t = r.alert_type[i]
        if t:
            by_type[t]["attack" if truth[i] else "benign"] += 1
    alerts = sum(c["attack"] + c["benign"] for c in by_type.values())
    return {
        "events": int(len(ph_idx)),
        "attack_events": int(truth[ph_idx].sum()),
        "attack_share": float(truth[ph_idx].mean()) if len(ph_idx) else 0.0,
        "alerts": int(alerts),
        "alerts_by_type": {t: {"alerts": c["attack"] + c["benign"], "on_attack_events": c["attack"]}
                           for t, c in sorted(by_type.items())},
    }


def cs_report(r, events, truth, idx):
    """Credential Stuffing alerts in idx and the placeholder's part in them:
    the alert's own event is the placeholder; the placeholder is among the
    usernames the IP had tried by then (so it counted toward the threshold);
    without it the IP would have fewer than CRED_STUFFING_MIN_USERS usernames."""
    alerts = [int(i) for i in idx if r.alert_type[i] == CS_TYPE]
    ips = {events[i]["ip"] for i in alerts}
    seen = defaultdict(list)
    for j in range((max(alerts) + 1) if alerts else 0):
        ip = events[j]["ip"]
        if ip in ips:
            seen[ip].append((j, events[j]["user"]))
    c = Counter()
    for i in alerts:
        users = {u for j, u in seen[events[i]["ip"]] if j <= i}
        a = "attack" if truth[i] else "benign"
        c["alerts"] += 1
        c[f"alerts_{a}"] += 1
        if events[i]["user"] == PLACEHOLDER_USER:
            c["alert_event_is_placeholder"] += 1
            c[f"alert_event_is_placeholder_{a}"] += 1
        if PLACEHOLDER_USER in users:
            c["placeholder_among_ip_usernames"] += 1
            c[f"placeholder_among_ip_usernames_{a}"] += 1
            if len(users - {PLACEHOLDER_USER}) < config.CRED_STUFFING_MIN_USERS:
                c["below_username_threshold_without_placeholder"] += 1
                c[f"below_username_threshold_without_placeholder_{a}"] += 1
    keys = ["alerts", "alerts_attack", "alerts_benign"]
    for k in ("alert_event_is_placeholder", "placeholder_among_ip_usernames",
              "below_username_threshold_without_placeholder"):
        keys += [k, f"{k}_attack", f"{k}_benign"]
    return {k: int(c[k]) for k in keys}


def full_report(r, events, truth, parts, ph_idx, decision=None):
    out = {name: evaluate(r, events, truth, idx, None if decision is None else decision[idx])
           for name, idx in parts.items()}
    out["placeholder_user_dev_val"] = placeholder_report(r, truth, ph_idx)
    out["credential_stuffing_dev_val"] = cs_report(r, events, truth, parts["dev_val"])
    return out


# ── Parallel replay workers ──────────────────────────────────────────────────

_W = {}


def _worker_init(shared_dir):
    import pickle
    events, truth, n_train, cold, _ = load_stream()
    with open(os.path.join(shared_dir, "prepared.pkl"), "rb") as f:
        prepared = pickle.load(f)
    reached = np.load(os.path.join(shared_dir, "reached.npy"))
    parts, ph_idx = report_parts(events, n_train, cold)
    _W.update(events=events, truth=truth, prepared=prepared, parts=parts, ph_idx=ph_idx,
              keys=[harness.event_key(events[i]) for i in reached],
              raw_reached=np.load(os.path.join(shared_dir, "raw_reached.npy"), mmap_mode="r"))


def _worker_replay(job):
    label, decision = job
    t = time.time()
    r = replay_hybrid(_W, decision)
    t_replay = time.time() - t
    rep = full_report(r, _W["events"], _W["truth"], _W["parts"], _W["ph_idx"])
    return {"label": label, "report": rep, "replay_seconds": round(t_replay, 1),
            "metrics_seconds": round(time.time() - t - t_replay, 1)}


# ── Main ─────────────────────────────────────────────────────────────────────

def if_sweep_row(c, s_train, s_val, y):
    """Original rule: IsolationForest(contamination=c).predict == -1, i.e.
    score_samples below the 100*c percentile of the training scores."""
    flag = (s_val - np.percentile(s_train, 100.0 * c)) < 0
    tp = int((flag & y).sum())
    fp = int((flag & ~y).sum())
    fn = int((~flag & y).sum())
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {"contamination": c, "if_f1": 2 * p * r / (p + r) if p + r else 0.0,
            "precision": p, "recall": r, "fpr": fp / int((~y).sum()), "flag_rate": float(flag.mean())}


def main():
    import pickle
    import shutil
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, nargs="+", default=list(SEEDS))
    ap.add_argument("--workers", type=int, default=2, help="parallel hybrid replay processes")
    args = ap.parse_args()
    timings = {}
    T0 = time.time()

    def tick(name, t):
        timings[name] = round(time.time() - t, 1)
        print(f"[{timings[name]:7.1f} s] {name}", flush=True)

    t = time.time()
    events, truth, n_train, cold, train_df = load_stream()
    parts, ph_idx = report_parts(events, n_train, cold)
    val = parts["dev_val"]
    tick("load stream", t)

    t = time.time()
    reached = dry_pass(events)
    keys = [harness.event_key(events[i]) for i in reached]
    tick("dry pass", t)

    t = time.time()
    prepared = Prepared(train_df)
    del train_df
    det0 = prepared.detector()
    raw_reached = harness.build_features([events[i] for i in reached], det0)
    raw_all = harness.build_features(events, det0)
    X_reached = prepared.scaler.transform(raw_reached)
    X_all = prepared.scaler.transform(raw_all)
    del raw_all
    tick("features (frequency maps, scaler, reached and all-event features)", t)

    ctx = dict(events=events, truth=truth, prepared=prepared, keys=keys,
               raw_reached=raw_reached)
    # Workers load their own copy of the stream while the main process works.
    t = time.time()
    shared = tempfile.mkdtemp(prefix="phase2_")
    np.save(os.path.join(shared, "reached.npy"), reached)
    np.save(os.path.join(shared, "raw_reached.npy"), raw_reached)
    with open(os.path.join(shared, "prepared.pkl"), "wb") as f:
        pickle.dump(prepared, f)
    pool = ProcessPoolExecutor(max_workers=args.workers, initializer=_worker_init,
                               initargs=(shared,))
    tick("start replay workers", t)

    t = time.time()
    r = harness.replay(events, None)
    rules = full_report(r, events, truth, parts, ph_idx)
    del r
    tick("rules-only replay + metrics", t)

    scores = {}

    def score_seed(seed):
        t = time.time()
        model, s_train = fit_forest(prepared.X_train, seed)
        s_reached = score_samples(model, X_reached)
        s_all = score_samples(model, X_all)
        chk = X_reached[:2000]
        model.offset_ = np.percentile(s_train, 40.0)
        assert np.allclose(model.decision_function(chk), model.score_samples(chk) - model.offset_)
        scores[seed] = (s_train, s_reached, s_all)
        tick(f"fit + score seed {seed}", t)

    score_seed(SWEEP_SEED)
    t = time.time()
    s_train, _, s_all = scores[SWEEP_SEED]
    y_val = truth[val]
    ph_mask = np.isin(val, ph_idx)
    sweep = []
    for c in SWEEP_GRID:
        row = if_sweep_row(c, s_train, s_all[val], y_val)
        excl = if_sweep_row(c, s_train, s_all[val][~ph_mask], y_val[~ph_mask])
        row["if_f1_excl_placeholder"] = excl["if_f1"]
        sweep.append(row)
    chosen = max(sweep, key=lambda row: row["if_f1"])["contamination"]
    tick("contamination sweep (vectorised, IF event F1 on dev_val)", t)
    print(f"chosen contamination: {chosen}", flush=True)

    def decision_reached(seed):
        s_tr, s_re, _ = scores[seed]
        return s_re - np.percentile(s_tr, 100.0 * chosen)

    t_h = time.time()
    futures = {SWEEP_SEED: pool.submit(_worker_replay, (f"seed={SWEEP_SEED}", decision_reached(SWEEP_SEED)))}
    for s in args.seeds:
        if s not in scores:
            score_seed(s)
            futures[s] = pool.submit(_worker_replay, (f"seed={s}", decision_reached(s)))

    t = time.time()
    if_only = {}
    for s in args.seeds:
        s_tr, _, s_al = scores[s]
        d_all = s_al - np.percentile(s_tr, 100.0 * chosen)
        if_only[s] = full_report(if_only_replay_result(events, d_all), events, truth,
                                 parts, ph_idx, d_all)
    tick("Isolation Forest only metrics (3 seeds)", t)

    t = time.time()
    hybrid = {s: f.result() for s, f in futures.items()}
    pool.shutdown()
    shutil.rmtree(shared, ignore_errors=True)
    tick("wait for hybrid replays", t)
    timings["hybrid replays wall clock (from first submit)"] = round(time.time() - t_h, 1)
    for s in args.seeds:
        timings[f"hybrid seed {s}: replay / metrics in worker"] = (
            f"{hybrid[s]['replay_seconds']} / {hybrid[s]['metrics_seconds']}")

    per_seed = [{"seed": s, "if_only": if_only[s], "hybrid": hybrid[s]["report"]}
                for s in args.seeds]
    names = list(parts)

    def mean_of(cfg, part):
        rows = [headline(p[cfg][part]) for p in per_seed]
        return {k: (float(np.mean([r[k] for r in rows]))
                    if all(r[k] is not None for r in rows) else None) for k in rows[0]}

    out = {
        "protocol": "backend/eval/PROTOCOL.md (amendment 1: contamination by IF event F1)",
        "config": {"ML_ALERT_MARGIN": config.ML_ALERT_MARGIN,
                   "CONFIDENCE_HIGH_CUTOFF": config.CONFIDENCE_HIGH_CUTOFF,
                   "CONFIDENCE_MEDIUM_CUTOFF": config.CONFIDENCE_MEDIUM_CUTOFF,
                   "BRUTE_FORCE_THRESHOLD": config.BRUTE_FORCE_THRESHOLD,
                   "forest": FOREST},
        "stream": {"dev_events": len(events), "dev_train_events": n_train,
                   **{f"{k}_events": int(len(v)) for k, v in parts.items()},
                   "placeholder_dev_val_events": int(len(ph_idx)),
                   "ml_reached_events": int(len(reached)),
                   "training_rows": prepared.n_train_rows,
                   "training_users": prepared.n_train_users,
                   "training_user_fraction": 1.0},
        "placeholder_user": PLACEHOLDER_USER,
        "sweep_seed": SWEEP_SEED, "sweep_rule": "max IF event F1 (predict == -1) on dev_val",
        "sweep": sweep, "chosen_contamination": chosen,
        "rules_only": rules,
        "per_seed": per_seed,
        "mean_over_seeds": {cfg: {part: mean_of(cfg, part) for part in names}
                            for cfg in ("if_only", "hybrid")},
        "timings_seconds": {**timings, "total": round(time.time() - T0, 1)},
    }
    with open(OUT_JSON, "w", encoding="utf-8", newline="\n") as f:
        json.dump(out, f, indent=2)
        f.write("\n")
    write_summary(out)
    print(open(OUT_TXT, encoding="utf-8").read())
    return 0


def _fmt(v):
    if v is None:
        return "not reached"
    if isinstance(v, float):
        return f"{v:.4f}"
    return str(v)


def write_summary(out):
    seeds = [p["seed"] for p in out["per_seed"]]
    L = ["Phase 2 baseline (eval/PROTOCOL.md): current rules, response policy and model design,",
         f"retrained on dev_train; metrics on dev_val. Seeds {seeds}; IF and hybrid values are",
         "means over seeds. Placeholder = user ID " + out["placeholder_user"] + ".",
         f"stream: {out['stream']}", "",
         f"Contamination sweep (seed {out['sweep_seed']}; {out['sweep_rule']}):",
         f"  {'c':>5} {'IF F1':>7} {'prec':>7} {'recall':>7} {'FPR':>7} {'F1 excl ph':>11}"]
    for r in out["sweep"]:
        L.append(f"  {r['contamination']:>5} {r['if_f1']:7.4f} {r['precision']:7.4f} "
                 f"{r['recall']:7.4f} {r['fpr']:7.4f} {r['if_f1_excl_placeholder']:11.4f}")
    L += [f"  chosen: {out['chosen_contamination']}", ""]
    for part in out["mean_over_seeds"]["hybrid"]:
        rows = {"rules only": headline(out["rules_only"][part]),
                "IF only": out["mean_over_seeds"]["if_only"][part],
                "hybrid": out["mean_over_seeds"]["hybrid"][part]}
        L.append(f"[{part}]")
        L.append(f"  {'metric':36s}" + "".join(f"{k:>14s}" for k in rows))
        for k in rows["IF only"]:
            L.append(f"  {k:36s}" + "".join(f"{_fmt(r.get(k, 'n/a')):>14s}" for r in rows.values()))
        L.append(f"  per-type alert precision (alerts, precision): hybrid seed {seeds[0]} | rules only")
        h = out["per_seed"][0]["hybrid"][part]["per_type"]
        ro = out["rules_only"][part]["per_type"]
        for t in sorted(set(h) | set(ro)):
            a, b = h.get(t, {}), ro.get(t, {})
            L.append(f"    {t:24s} {a.get('alerts', 0):>9} {a.get('precision', 0):.4f} | "
                     f"{b.get('alerts', 0):>9} {b.get('precision', 0):.4f}")
        L.append("")
    L.append("Placeholder user, dev_val events (alerts by type, of which on attack events):")
    for name, rep in [("rules only", out["rules_only"])] + [
            (f"hybrid seed {p['seed']}", p["hybrid"]) for p in out["per_seed"]]:
        ph = rep["placeholder_user_dev_val"]
        L.append(f"  {name:16s} events {ph['events']}, attack share {ph['attack_share']:.4f}, "
                 f"alerts {ph['alerts']}: " + ", ".join(
                     f"{t} {v['alerts']} ({v['on_attack_events']})"
                     for t, v in ph["alerts_by_type"].items()))
    L.append("Credential Stuffing alerts on dev_val and the placeholder:")
    for name, rep in [("rules only", out["rules_only"])] + [
            (f"hybrid seed {p['seed']}", p["hybrid"]) for p in out["per_seed"]]:
        L.append(f"  {name:16s} {rep['credential_stuffing_dev_val']}")
    L.append("")
    L.append("Per seed (dev_val): " + "; ".join(
        f"seed {p['seed']}: IF ROC-AUC {p['if_only']['dev_val']['roc_auc']:.4f} "
        f"PR-AUC {p['if_only']['dev_val']['pr_auc']:.4f}, hybrid recall "
        f"{p['hybrid']['dev_val']['event_recall']:.4f} FPR {p['hybrid']['dev_val']['fpr']:.4f} "
        f"campaign {p['hybrid']['dev_val']['campaign_recall']:.4f}"
        for p in out["per_seed"]))
    L.append(f"timings (s): {out['timings_seconds']}")
    with open(OUT_TXT, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(L) + "\n")


if __name__ == "__main__":
    sys.exit(main())
