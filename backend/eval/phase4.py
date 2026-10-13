# backend/eval/phase4.py
"""
Phase 4: the ML redesign under eval/PROTOCOL.md amendment 4. The rules are
frozen at the amendment 3 settings; val_a chooses, val_b confirms. The
locked test month is never read.

Stages (run from backend/, in order):
  python -m eval.phase4 features   causal feature matrix (ml/features_v4.py)
                                   and Freeman risks for every development
                                   event, one streaming pass
  python -m eval.phase4 fit        Isolation Forests (seed 42, 11 feature sets
                                   x 4 settings; --sets to run a subset) and
                                   the supervised reference (--part hgb); each
                                   model's dev_train quantile thresholds.
                                   --chosen-seeds fits seeds 43 and 44 of the
                                   chosen forest after `select`.
  python -m eval.phase4 select     every candidate x threshold on val_a; the
                                   choice, ablations, strata, overlap,
                                   importance, latency; writes the selection
                                   and data/model_v4.pkl. Never computes a
                                   val_b metric.
  python -m eval.phase4 confirm    val_b metrics of the choice, read from disk
  python -m eval.phase4 workload   val_b incidents and budget curves
  python -m eval.phase4 replay     real agents in v3 + v4 mode; equivalence

Inputs reused: results/phase3b_cache/chosen_rules.npz (frozen rule alerts)
and results/phase3_cache/ml_decision_v3.npy (Phase 2 forest, seed 42).
Intermediates: results/phase4_cache/ (gitignored). PHASE4_OUT redirects the
results and the cache (smoke tests, with PHASE3_LIMIT and PHASE3B_OUT).
"""

import argparse
import contextlib
import ctypes
import io
import json
import os
import re
import sys
import time
from collections import OrderedDict

import numpy as np

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

import config  # noqa: E402
from agents import rules_v3 as R  # noqa: E402
from eval import datasets  # noqa: E402
from eval import phase3_rules as P3  # noqa: E402
from eval import phase3b as P3B  # noqa: E402
from eval.phase3_rules import Clock, emit  # noqa: E402
from ml import features_v4 as F  # noqa: E402

RESULTS = os.environ.get("PHASE4_OUT") or P3.RESULTS
CACHE = os.path.join(RESULTS, "phase4_cache")
MODEL_V4 = (os.path.join(RESULTS, "model_v4.pkl") if os.environ.get("PHASE4_OUT")
            else os.path.join(BACKEND, "data", "model_v4.pkl"))
EXTRA = ["index", "Region", "User Agent String", "Browser Name and Version",
         "OS Name and Version", "Round-Trip Time [ms]"]

# ── Amendment 4 ──────────────────────────────────────────────────────────────
QUANTILES = (0.001, 0.005, 0.01, 0.02, 0.05, 0.10, 0.20, 0.30)
GROUPS = "ABCDE"
FEATURE_SETS = OrderedDict([("A-E", GROUPS)]
                           + [(f"-{g}", GROUPS.replace(g, "")) for g in GROUPS]
                           + [(g, g) for g in GROUPS])
IF_GRID = ((100, 256), (100, 4096), (300, 256), (300, 4096))
SEEDS = (42, 43, 44)
FIT_SAMPLE = 1_000_000
HGB_GRID = ((0.05, 15), (0.05, 63), (0.1, 15), (0.1, 63))
HGB_SETS = OrderedDict([("A-E", GROUPS), ("-D", "ABCE")])
THRESHOLD = {"val_a": 0.2149, "val_b": 0.1915}
MIN_INCIDENTS = 30
DEDUP = P3.DEDUP
BUDGETS = P3B.BUDGETS
P2_NAME = "phase2_iforest"


def save_json(name, obj):
    os.makedirs(RESULTS, exist_ok=True)
    path = os.path.join(RESULTS, name)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, indent=2, default=P3._jsonable)
        f.write("\n")
    return path


def load_json(name):
    with open(os.path.join(RESULTS, name), encoding="utf-8") as f:
        return json.load(f)


def cache(name):
    """Path in the cache; candidate names are made file-safe."""
    os.makedirs(CACHE, exist_ok=True)
    return os.path.join(CACHE, re.sub(r"[^A-Za-z0-9._-]", "_", name))


def peak_rss_mb():
    """Peak working set of this process (Windows), in MB; None elsewhere."""
    try:
        class PMC(ctypes.Structure):
            _fields_ = [("cb", ctypes.c_ulong), ("PageFaultCount", ctypes.c_ulong),
                        ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                        ("a", ctypes.c_size_t), ("b", ctypes.c_size_t), ("c", ctypes.c_size_t),
                        ("d", ctypes.c_size_t), ("PagefileUsage", ctypes.c_size_t),
                        ("PeakPagefileUsage", ctypes.c_size_t)]
        pmc = PMC()
        pmc.cb = ctypes.sizeof(PMC)
        k32 = ctypes.windll.kernel32
        k32.GetCurrentProcess.restype = ctypes.c_void_p
        gpmi = ctypes.windll.psapi.GetProcessMemoryInfo
        gpmi.argtypes = [ctypes.c_void_p, ctypes.POINTER(PMC), ctypes.c_ulong]
        if not gpmi(k32.GetCurrentProcess(), ctypes.byref(pmc), pmc.cb):
            return None
        return round(pmc.PeakWorkingSetSize / 2**20)
    except Exception:
        return None


# ── The stream ───────────────────────────────────────────────────────────────

def stream():
    """phase3b.stream() plus the Phase 4 strata."""
    S = P3B.stream()
    in_train = np.zeros(S.n_ip, bool)
    in_train[S.ip[:S.n_train]] = True
    import pandas as pd
    hist = pd.Series(S.user).groupby(S.user).cumcount().to_numpy()
    S.hist = hist
    S.end_a = S.val_b.argmax() if S.val_b.any() else S.n      # first val_b position
    strata = OrderedDict([
        ("all", np.ones(S.n, bool)),
        ("excl_placeholder", ~S.unknown),
        ("cold_users", S.cold),
        ("cold_ips", ~in_train[S.ip]),
        ("successful", S.success),
        ("history_0", hist == 0),
        ("history_1_4", (hist >= 1) & (hist <= 4)),
        ("history_5_19", (hist >= 5) & (hist <= 19)),
        ("history_20_plus", hist >= 20),
    ])
    S.strata = {h: OrderedDict((k, v & m) for k, v in strata.items()) for h, m in S.halves.items()}
    return S


def events(S, with_id=False):
    """Event dicts for the real agents and the feature extractor, in stream
    order: the eval/PROTOCOL.md field mapping plus the Phase 4 fields."""
    df = datasets.load("dev", columns=EXTRA)
    if len(df) != S.n:
        df = df.iloc[:S.n].reset_index(drop=True)
    assert np.array_equal(df["index"].to_numpy(), S.event_id), "extra columns out of step"

    def col(name):
        s = df[name]
        if hasattr(s, "cat"):
            names = s.cat.categories.astype(str).to_numpy(dtype=object)
            codes = s.cat.codes.to_numpy()
            return np.where(codes < 0, None, names[np.maximum(codes, 0)]).tolist()
        return s.astype(object).where(s.notna(), None).tolist()

    region, ua = col("Region"), col("User Agent String")
    browser, os_, rtt = col("Browser Name and Version"), col("OS Name and Version"), col("Round-Trip Time [ms]")
    del df
    stamps = S.timestamps()
    users = [str(u) for u in S.user_ids]
    countries = S.df["Country"].astype(str).replace("", "XX").to_numpy(dtype=object)
    devices = S.df["Device Type"].astype(str).replace("", "Unknown").to_numpy(dtype=object)
    status = ["SUCCESS" if ok else "FAILED" for ok in S.success.tolist()]
    asn = S.asn.tolist()
    ipn, ipc, uc = S.ip_names, S.ip.tolist(), S.user.tolist()
    eid = S.event_id.tolist()
    for i in range(S.n):
        e = {"timestamp": stamps[i], "user": users[uc[i]], "ip": ipn[ipc[i]], "status": status[i],
             "country": countries[i], "device_type": devices[i], "asn": asn[i],
             "region": region[i], "user_agent": ua[i], "browser": browser[i], "os": os_[i],
             "rtt": rtt[i]}
        if with_id:
            e["event_id"] = eid[i]
        yield e


# ── Stage: features ──────────────────────────────────────────────────────────

def stage_features(args):
    clk = Clock()
    t = time.time()
    S = P3B.stream()
    clk.tick("load dev stream", t)
    X = np.lib.format.open_memmap(cache("X.npy"), mode="w+", dtype=np.float64,
                                  shape=(S.n, F.N_FEATURES))
    FR = np.empty((S.n, len(F.FREEMAN_BETAS)), np.float64)
    fx = F.FeatureExtractorV4()
    t = time.time()
    t_ext = 0.0
    for i, e in enumerate(events(S)):
        t1 = time.perf_counter()
        X[i] = fx.update_and_extract(e)
        t_ext += time.perf_counter() - t1
        FR[i] = fx.last_freeman
        if i % 1_000_000 == 0 and i:
            print(f"  {i:,} events, {time.time() - t:.0f} s", flush=True)
    X.flush()
    np.save(cache("freeman.npy"), FR)
    clk.tick("feature extraction (one streaming pass)", t)
    out = {"events": int(S.n), "features": F.FEATURE_NAMES, "groups": F.FEATURE_GROUPS,
           "freeman_betas": list(F.FREEMAN_BETAS),
           "extract_us_per_event": round(1e6 * t_ext / S.n, 1),
           "state_sizes_end": fx.state_sizes(), "peak_rss_mb": peak_rss_mb(),
           "timings_seconds": clk.total()}
    save_json("phase4_features.json", out)
    print(json.dumps({k: v for k, v in out.items() if k not in ("features", "groups")}, indent=1))


# ── Candidates and scores ────────────────────────────────────────────────────

def if_name(fs, ne, ms, seed=42):
    return f"if[{fs}|{ne}|{ms}|s{seed}]"


def candidates():
    """Deployable candidates in amendment 4 order: (name, family, meta)."""
    out = [(P2_NAME, "phase2_iforest", {"with_D": False})]
    for fs, groups in FEATURE_SETS.items():
        for ne, ms in IF_GRID:
            out.append((if_name(fs, ne, ms), "iforest",
                        {"feature_set": fs, "groups": groups, "n_estimators": ne,
                         "max_samples": ms, "seed": 42, "with_D": "D" in groups}))
    for bi, b in enumerate(F.FREEMAN_BETAS):
        out.append((f"freeman[beta={b:g}]", "freeman", {"beta": b, "beta_index": bi, "with_D": False}))
    out.append(("new_ip", "new_ip", {"with_D": False}))
    return out


def references():
    return [(f"hgb[{fs}|lr={lr:g}|leaves={nl}]", "hgb",
             {"feature_set": fs, "groups": g, "learning_rate": lr, "max_leaf_nodes": nl,
              "with_D": "D" in g})
            for fs, g in HGB_SETS.items() for lr, nl in HGB_GRID]


def score(S, name, family, meta):
    """Per-event score of a candidate, higher = more suspicious."""
    if family == "phase2_iforest":
        return -np.asarray(np.load(P3B.ML_DECISION, mmap_mode="r")[:S.n], dtype=np.float64)
    if family == "freeman":
        return np.load(cache("freeman.npy"), mmap_mode="r")[:, meta["beta_index"]].astype(np.float64)
    if family == "new_ip":
        X = np.load(cache("X.npy"), mmap_mode="r")
        return np.asarray(X[:, F.FEATURE_NAMES.index("a_new_ip")], dtype=np.float64)
    return np.load(cache(f"score_{name}.npy"))


def thresholds(train_scores):
    return [float(np.quantile(train_scores, 1 - q, method="inverted_cdf")) for q in QUANTILES]


# ── Stage: fit ───────────────────────────────────────────────────────────────

def fit_forest(X, cols, ne, ms, seed, n_train):
    from sklearn.ensemble import IsolationForest
    from ml.model_v4 import iforest_scores
    rng = np.random.default_rng(seed)
    k = min(FIT_SAMPLE, n_train)
    sample = np.sort(rng.choice(n_train, size=k, replace=False))
    Xs = np.ascontiguousarray(X[:, cols], dtype=np.float32)
    model = IsolationForest(n_estimators=ne, max_samples=ms, max_features=1.0,
                            random_state=seed, n_jobs=8).fit(Xs[sample])
    model.n_jobs = None
    return model, iforest_scores(model, Xs)


def stage_fit(args):
    import pickle
    clk = Clock()
    t = time.time()
    S = P3B.stream()
    X = np.load(cache("X.npy"), mmap_mode="r")
    assert X.shape[0] == S.n
    clk.tick("load stream and feature matrix", t)
    thr_path = os.path.join(RESULTS, "phase4_thresholds.json")
    thr = load_json("phase4_thresholds.json") if os.path.exists(thr_path) else {}
    train = slice(0, S.n_train)

    if args.part in ("all", "fixed"):
        for name, family, meta in candidates():
            if family != "iforest" and name not in thr:
                thr[name] = thresholds(score(S, name, family, meta)[train])

    if args.chosen_seeds:
        sel = load_json("phase4_selection.json")
        c = sel["deployment"]["candidate"]
        if c["family"] != "iforest":
            print("chosen candidate is not a forest; no extra seeds")
        else:
            m = c["meta"]
            for seed in SEEDS[1:]:
                t = time.time()
                name = if_name(m["feature_set"], m["n_estimators"], m["max_samples"], seed)
                model, s = fit_forest(X, F.columns(m["groups"]), m["n_estimators"],
                                      m["max_samples"], seed, S.n_train)
                np.save(cache(f"score_{name}.npy"), s)
                thr[name] = thresholds(s[train])
                clk.tick(f"fit + score {name}", t)
    elif args.part in ("all", "if"):
        sets = args.sets.split(",") if args.sets else list(FEATURE_SETS)
        for fs in sets:
            Xs_cols = F.columns(FEATURE_SETS[fs])
            for ne, ms in IF_GRID:
                t = time.time()
                name = if_name(fs, ne, ms)
                model, s = fit_forest(X, Xs_cols, ne, ms, 42, S.n_train)
                np.save(cache(f"score_{name}.npy"), s)
                with open(cache(f"model_{name}.pkl"), "wb") as f:
                    pickle.dump(model, f, protocol=pickle.HIGHEST_PROTOCOL)
                thr[name] = thresholds(s[train])
                clk.tick(f"fit + score {name}", t)
    if args.part in ("all", "hgb") and not args.chosen_seeds:
        from sklearn.ensemble import HistGradientBoostingClassifier
        y = S.truth
        cut = int(0.9 * S.n_train)
        info_path = os.path.join(RESULTS, "phase4_hgb_fit.json")
        info = load_json("phase4_hgb_fit.json") if os.path.exists(info_path) else {}
        hsets = args.sets.split(",") if args.sets else list(HGB_SETS)
        for name, family, meta in references():
            gi = HGB_GRID.index((meta["learning_rate"], meta["max_leaf_nodes"]))
            if meta["feature_set"] not in hsets or (args.grid and str(gi) not in args.grid.split(",")):
                continue
            t = time.time()
            cols = F.columns(meta["groups"])
            Xs = np.ascontiguousarray(X[:, cols], dtype=np.float32)
            model = HistGradientBoostingClassifier(
                learning_rate=meta["learning_rate"], max_leaf_nodes=meta["max_leaf_nodes"],
                max_iter=500, early_stopping=True, n_iter_no_change=20, scoring="loss",
                class_weight="balanced", random_state=42)
            model.fit(Xs[:cut], y[:cut], X_val=Xs[cut:S.n_train], y_val=y[cut:S.n_train])
            s = model.predict_proba(Xs)[:, 1].astype(np.float64)
            np.save(cache(f"score_{name}.npy"), s)
            with open(cache(f"model_{name}.pkl"), "wb") as f:
                pickle.dump(model, f, protocol=pickle.HIGHEST_PROTOCOL)
            thr[name] = thresholds(s[train])
            info[name] = {"n_iter": int(model.n_iter_)}
            clk.tick(f"fit + score {name} ({model.n_iter_} iterations)", t)
        save_json("phase4_hgb_fit.json", info)
    save_json("phase4_thresholds.json", thr)
    t_ = clk.total()
    print(json.dumps(t_, indent=1))


# ── Metrics ──────────────────────────────────────────────────────────────────

def ml_alerts(S, s, thr, end):
    """ML matches (score >= thr) and de-duplicated alerts among the first
    `end` events (stream order; de-duplication is causal, so a prefix gives
    the same alerts as the full stream)."""
    m = np.flatnonzero(s[:end] >= thr)
    return m, m[emit(S, m, S.ip[m], DEDUP)]


def rule_keys(S):
    """(IP, day) keys of incidents with a frozen-rule alert, per half (all
    events of the half)."""
    z = np.load(os.path.join(P3B.CACHE, "chosen_rules.npz"))
    pos = np.unique(np.concatenate([z[f"alert::{d}"] for d in R.RULE_DETECTORS]))
    out = {}
    for h, m in S.halves.items():
        p = pos[m[pos]]
        out[h] = np.unique(S.ip[p] * np.int64(1 << 20) + S.day[p])
    out["_alert_pos"] = pos
    out["_by_detector"] = {d: z[f"alert::{d}"] for d in R.RULE_DETECTORS}
    return out


def ml_metrics(S, alert_pos, part, half, rkeys, att=None):
    """Primary and secondary alert/incident metrics of ML alerts on part."""
    p = alert_pos[part[alert_pos]]
    y = S.truth[p]
    ips = S.ip[p]
    if att is None:
        att = S.attacking_ips(part)
    key = ips * np.int64(1 << 20) + S.day[p]
    uk, inv = np.unique(key, return_inverse=True)
    inc_att = np.bincount(inv, weights=y, minlength=len(uk)) > 0
    inc_ip = uk >> 20
    incr = ~np.isin(uk, rkeys[half])
    lo, hi = P3B.bootstrap(inc_ip[incr], inc_att[incr])
    a_lo, a_hi = P3B.bootstrap(ips, y)
    n_inc = int(incr.sum())
    legit = p[~y & ~S.unknown[p]]
    out = {
        "incremental_incidents": n_inc,
        "incremental_attack_incidents": int(inc_att[incr].sum()),
        "incremental_precision": float(inc_att[incr].mean()) if n_inc else 0.0,
        "incremental_ci_low": lo, "incremental_ci_high": hi,
        "attacking_ips_incremental": int(len(np.unique(inc_ip[incr & inc_att]))),
        "ml_alerts": int(len(p)), "ml_attack_alerts": int(y.sum()),
        "ml_alert_precision": float(y.mean()) if len(p) else 0.0,
        "ml_alert_ci_low": a_lo, "ml_alert_ci_high": a_hi,
        "attacking_ips_flagged": int(len(np.unique(ips[y]))),
        "benign_ips_flagged": int(len(np.unique(ips[~att[ips]]))),
        "legitimate_users_alerted": int(len(np.unique(S.user[legit]))),
        "ml_incidents": int(len(uk)),
        "ml_incident_precision": float(inc_att.mean()) if len(uk) else 0.0,
    }
    out["meets_primary"] = bool(n_inc >= MIN_INCIDENTS and lo >= THRESHOLD["val_a"])
    out["meets_phase3b_alert_criterion"] = bool(len(p) >= P3B.MIN_ALERTS
                                                and a_lo >= 2 * S.base[half])
    return out


def event_metrics(S, s, part):
    from sklearn.metrics import average_precision_score, roc_auc_score, roc_curve
    y = S.truth[part]
    x = s[part]
    if y.all() or not y.any():
        return {"roc_auc": None, "pr_auc": None, "tpr_at_1pct_fpr": None}
    fpr, tpr, _ = roc_curve(y, x)
    return {"roc_auc": float(roc_auc_score(y, x)), "pr_auc": float(average_precision_score(y, x)),
            "tpr_at_1pct_fpr": float(tpr[fpr <= 0.01].max())}


def choose(rows, key="meets_primary"):
    """Amendment 4: most attacking IPs in incremental incidents among rows
    meeting the criterion; ties higher lower bound, fewer ML alerts, order.
    Fallback: the best lower bound among rows with >= 30 incremental
    incidents. Returns (row, met)."""
    meet = [(i, r) for i, r in enumerate(rows) if r["val_a"][key]]
    if meet:
        return max(meet, key=lambda ir: (ir[1]["val_a"]["attacking_ips_incremental"],
                                         ir[1]["val_a"]["incremental_ci_low"],
                                         -ir[1]["val_a"]["ml_alerts"], -ir[0]))[1], True
    pool = [(i, r) for i, r in enumerate(rows)
            if r["val_a"]["incremental_incidents"] >= MIN_INCIDENTS] or list(enumerate(rows))
    return max(pool, key=lambda ir: (ir[1]["val_a"]["incremental_ci_low"],
                                     ir[1]["val_a"]["attacking_ips_incremental"],
                                     -ir[1]["val_a"]["ml_alerts"], -ir[0]))[1], False


def short(r, half="val_a"):
    v = r[half]
    return (f"{r['name']:34s} q={r['quantile']:<6g} inc {v['incremental_incidents']:>6} "
            f"prec {v['incremental_precision']:.3f} [{v['incremental_ci_low']:.3f},"
            f"{v['incremental_ci_high']:.3f}] attIPs {v['attacking_ips_incremental']:>5} "
            f"| ML alerts {v['ml_alerts']:>7} prec {v['ml_alert_precision']:.3f}")


# ── Stage: select (val_a only) ───────────────────────────────────────────────

def stage_select(args):
    clk = Clock()
    t = time.time()
    S = stream()
    rk = rule_keys(S)
    thr = load_json("phase4_thresholds.json")
    end = int(S.end_a)                     # never look past val_a
    part = S.val_a
    att = S.attacking_ips(part)
    clk.tick("load stream, frozen rule incidents, thresholds", t)

    t = time.time()
    items = [("candidate",) + c for c in candidates()] + [("reference",) + c for c in references()]

    def evaluate(item):
        kind, name, family, meta = item
        s = score(S, name, family, meta)
        e = event_metrics(S, s, part)
        out = []
        for q, th in zip(QUANTILES, thr[name]):
            _, al = ml_alerts(S, s, th, end)
            out.append({"name": name, "family": family, "kind": kind, "meta": meta, "quantile": q,
                        "threshold": th, "val_a": ml_metrics(S, al, part, "val_a", rk, att)})
        print(f"  {name:34s} AUC {e['roc_auc']:.4f} PR {e['pr_auc']:.4f}", flush=True)
        return name, e, out

    from concurrent.futures import ThreadPoolExecutor
    rows, ev, refs = [], {}, []
    with ThreadPoolExecutor(6) as ex:            # results kept in candidate order
        for (kind, *_), (name, e, out) in zip(items, ex.map(evaluate, items)):
            ev[name] = e
            for r in out:
                r["order"] = len(rows) + len(refs)
                (rows if kind == "candidate" else refs).append(r)
    clk.tick(f"{len(rows)} candidate rows and {len(refs)} reference rows on val_a", t)

    chosen, met = choose(rows)
    best_d, met_d = choose([r for r in rows if r["meta"]["with_D"]])
    best_nd, met_nd = choose([r for r in rows if not r["meta"]["with_D"]])
    hgb_best = {}
    for fs in HGB_SETS:
        pool = [n for n, f, m in references() if m["feature_set"] == fs]
        nb = max(pool, key=lambda n: (ev[n]["pr_auc"], -pool.index(n)))
        hgb_best[fs] = {"name": nb, "event_val_a": ev[nb],
                        "rows": [r for r in refs if r["name"] == nb],
                        "best_row_by_criterion": choose([r for r in refs if r["name"] == nb])[0]}

    # ── ablation (Isolation Forest family at the best forest's settings) ──
    t = time.time()
    if_rows = [r for r in rows if r["family"] == "iforest"]
    best_if, _ = choose(if_rows)
    ne, ms = best_if["meta"]["n_estimators"], best_if["meta"]["max_samples"]
    ablation = []
    for fs in FEATURE_SETS:
        name = if_name(fs, ne, ms)
        rs = [r for r in if_rows if r["name"] == name]
        at_q = next(r for r in rs if r["quantile"] == best_if["quantile"])
        b, bm = choose(rs)
        ablation.append({"feature_set": fs, "name": name, **ev[name],
                         "at_chosen_quantile": at_q["val_a"], "best_row": {
                             "quantile": b["quantile"], "meets": bm, **b["val_a"]}})
    clk.tick("ablation table", t)

    # ── strata, overlap, importance, latency ──────────────────────────────
    t = time.time()
    focus = OrderedDict([("chosen", chosen), ("best_with_D", best_d), ("best_without_D", best_nd)])
    strata = {}
    for label, r in focus.items():
        s = score(S, r["name"], r["family"], r["meta"])
        _, al = ml_alerts(S, s, r["threshold"], end)
        strata[label] = {k: {**event_metrics(S, s, m), **ml_metrics(S, al, m, "val_a", rk)}
                         for k, m in S.strata["val_a"].items()}
    clk.tick("strata (val_a)", t)

    t = time.time()
    s = score(S, chosen["name"], chosen["family"], chosen["meta"])
    _, al = ml_alerts(S, s, chosen["threshold"], end)
    overlap = overlap_ips(S, rk["_alert_pos"], al, part)
    importance = {"hgb_reference": permutation_importance_hgb(S, hgb_best["A-E"]["name"])}
    if chosen["family"] == "iforest":
        importance["chosen_iforest"] = permutation_importance_if(S, chosen)
    clk.tick("overlap and permutation importance", t)

    deployment = {"candidate": {k: chosen[k] for k in ("name", "family", "meta", "quantile", "threshold")},
                  "meets_criterion": met, "alerting": met,
                  "with_D": bool(chosen["meta"]["with_D"]),
                  "status": ("chosen: meets the amendment 4 criterion on val_a" if met else
                             "fallback: no candidate meets the criterion; no ML alerting in v4, "
                             "best lower bound reported as a ranking signal for Phase 5")}
    t = time.time()
    latency = save_model(S, deployment)
    clk.tick("model_v4 bundle and latency", t)

    out = {"thresholds_fixed": THRESHOLD, "min_incremental_incidents": MIN_INCIDENTS,
           "quantiles": QUANTILES, "base_rate_val_a": S.base["val_a"],
           "events_val_a": int(part.sum()), "attacking_ips_val_a": int(att.sum()),
           "deployment": deployment, "chosen_row": chosen, "best_with_D": {"row": best_d, "meets": met_d},
           "best_without_D": {"row": best_nd, "meets": met_nd},
           "n_rows_meeting": int(sum(r["val_a"]["meets_primary"] for r in rows)),
           "event_metrics_val_a": ev, "rows": rows, "reference_rows": refs, "hgb_best": hgb_best,
           "ablation": {"settings": {"n_estimators": ne, "max_samples": ms,
                                     "quantile": best_if["quantile"]}, "rows": ablation},
           "strata_val_a": strata, "overlap_val_a": overlap, "importance": importance,
           "latency": latency, "timings_seconds": clk.total()}
    save_json("phase4_selection.json", out)
    print(f"val_a base rate {S.base['val_a']:.5f}; fixed bar {THRESHOLD['val_a']}; "
          f"{out['n_rows_meeting']} rows meet")
    for label, r in (("CHOSEN" if met else "FALLBACK", chosen), ("best with D", best_d),
                     ("best without D", best_nd)):
        print(f"{label:15s} {short(r)}")
    for fs, h in hgb_best.items():
        print(f"reference {fs}: {h['name']} PR-AUC {h['event_val_a']['pr_auc']:.4f} | {short(h['best_row_by_criterion'])}")


def overlap_ips(S, rule_pos, ml_pos, part):
    """Attacking IPs flagged (an alert on one of their attack events in part)
    by the frozen rules only, by the ML only, by both."""
    def flagged(pos):
        p = pos[part[pos] & S.truth[pos]]
        return set(np.unique(S.ip[p]).tolist())
    r, m = flagged(rule_pos), flagged(ml_pos)
    return {"attacking_ips": int(S.attacking_ips(part).sum()), "rules_only": len(r - m),
            "ml_only": len(m - r), "both": len(r & m), "neither": int(S.attacking_ips(part).sum()) - len(r | m)}


def _perm_sample(S, n=200_000):
    pos = np.flatnonzero(S.val_a)
    rng = np.random.default_rng(42)
    return np.sort(rng.choice(pos, size=min(n, len(pos)), replace=False))


def _perm(S, cols, scorer, repeats=3):
    from sklearn.metrics import average_precision_score
    X = np.load(cache("X.npy"), mmap_mode="r")
    idx = _perm_sample(S)
    Xs = np.ascontiguousarray(X[idx][:, cols])
    y = S.truth[idx]
    base = average_precision_score(y, scorer(Xs))
    rng = np.random.default_rng(42)
    out = []
    for j, c in enumerate(cols):
        drops = []
        for _ in range(repeats):
            Xp = Xs.copy()
            Xp[:, j] = Xp[rng.permutation(len(Xp)), j]
            drops.append(base - average_precision_score(y, scorer(Xp)))
        out.append({"feature": F.FEATURE_NAMES[c], "pr_auc_drop_mean": float(np.mean(drops)),
                    "pr_auc_drop_sd": float(np.std(drops))})
    out.sort(key=lambda d: -d["pr_auc_drop_mean"])
    return {"metric": "val_a PR-AUC drop, 200,000-event sample, 3 permutations",
            "base_pr_auc": float(base), "top10": out[:10], "all": out}


def permutation_importance_hgb(S, name):
    import pickle
    with open(cache(f"model_{name}.pkl"), "rb") as f:
        model = pickle.load(f)
    groups = next(m for n, _, m in references() if n == name)["groups"]
    return {"model": name, **_perm(S, F.columns(groups), lambda Z: model.predict_proba(
        Z.astype(np.float32))[:, 1])}


def permutation_importance_if(S, row):
    import pickle
    with open(cache(f"model_{row['name']}.pkl"), "rb") as f:
        model = pickle.load(f)
    return {"model": row["name"], **_perm(S, F.columns(row["meta"]["groups"]),
                                         lambda Z: -model.decision_function(Z.astype(np.float32)))}


def save_model(S, deployment):
    """data/model_v4.pkl for ML_MODE = "v4", and the scoring latency."""
    import pickle
    from ml.model_v4 import V4Scorer
    c = deployment["candidate"]
    kind = {"iforest": "iforest", "freeman": "freeman", "new_ip": "new_ip"}.get(c["family"])
    if kind is None:
        return {"note": f"{c['family']} has no v4 runtime; model_v4.pkl not written"}
    bundle = {"name": c["name"], "kind": kind, "feature_names": F.FEATURE_NAMES,
              "threshold": c["threshold"], "quantile": c["quantile"],
              "alerting": bool(deployment["alerting"]), "status": deployment["status"],
              "columns": F.columns(c["meta"]["groups"]) if kind == "iforest" else [],
              "beta_index": c["meta"].get("beta_index"),
              "protocol": "eval/PROTOCOL.md amendment 4"}
    if kind == "iforest":
        with open(cache(f"model_{c['name']}.pkl"), "rb") as f:
            bundle["model"] = pickle.load(f)
    V4Scorer.save(bundle, MODEL_V4)
    sc = V4Scorer(bundle)
    X = np.load(cache("X.npy"), mmap_mode="r")
    idx = _perm_sample(S, 20_000)
    Xs = np.asarray(X[idx])
    FR = np.load(cache("freeman.npy"), mmap_mode="r")[idx]
    t = time.perf_counter()
    for v, fr in zip(Xs, FR):
        sc.score_vector(v, fr)
    us = 1e6 * (time.perf_counter() - t) / len(idx)
    feats = load_json("phase4_features.json")
    return {"model_v4": os.path.relpath(MODEL_V4, BACKEND), "score_us_per_event": round(us, 1),
            "extract_us_per_event": feats["extract_us_per_event"],
            "state_sizes_end": feats["state_sizes_end"], "peak_rss_mb_features": feats["peak_rss_mb"]}


# ── Stage: confirm (val_b, the choice read from disk) ────────────────────────

def confirm_row(S, rk, row, half="val_b"):
    s = score(S, row["name"], row["family"], row["meta"])
    _, al = ml_alerts(S, s, row["threshold"], S.n)
    m = ml_metrics(S, al, S.halves[half], half, rk)
    m["holds"] = bool(m["incremental_incidents"] >= MIN_INCIDENTS
                      and m["incremental_ci_low"] >= THRESHOLD[half])
    m["meets_val_a_bar"] = bool(m["incremental_incidents"] >= MIN_INCIDENTS
                                and m["incremental_ci_low"] >= THRESHOLD["val_a"])
    return m, s, al


def stage_confirm(args):
    clk = Clock()
    t = time.time()
    S = stream()
    rk = rule_keys(S)
    sel = load_json("phase4_selection.json")       # the choice is fixed on disk
    thr = load_json("phase4_thresholds.json")
    clk.tick("load stream and selection", t)
    t = time.time()
    rows = OrderedDict([("chosen", sel["chosen_row"]), ("best_with_D", sel["best_with_D"]["row"]),
                        ("best_without_D", sel["best_without_D"]["row"])])
    p2 = [r for r in sel["rows"] if r["name"] == P2_NAME]
    rows["phase2_iforest_best"] = choose(p2)[0]
    for fs, h in sel["hgb_best"].items():
        rows[f"hgb_reference_{fs}"] = h["best_row_by_criterion"]
    out = {"base_rate": S.base, "thresholds_fixed": THRESHOLD,
           "events": {h: int(S.halves[h].sum()) for h in P3B.HALVES},
           "deployment": sel["deployment"], "rows": {}}
    for label, r in rows.items():
        b, s, al = confirm_row(S, rk, r)
        out["rows"][label] = {"name": r["name"], "quantile": r["quantile"], "threshold": r["threshold"],
                              "with_D": r["meta"]["with_D"], "val_a": r["val_a"], "val_b": b,
                              "event_val_b": event_metrics(S, s, S.val_b)}
        if label == "chosen":
            out["strata_val_b"] = {k: {**event_metrics(S, s, m), **ml_metrics(S, al, m, "val_b", rk)}
                                   for k, m in S.strata["val_b"].items()}
            out["overlap_val_b"] = overlap_ips(S, rk["_alert_pos"], al, S.val_b)
    clk.tick("val_b rows and strata", t)

    c = sel["deployment"]["candidate"]
    if c["family"] == "iforest":
        t = time.time()
        m = c["meta"]
        per = {}
        for seed in SEEDS:
            name = if_name(m["feature_set"], m["n_estimators"], m["max_samples"], seed)
            if not os.path.exists(cache(f"score_{name}.npy")):
                continue
            th = thr[name][QUANTILES.index(c["quantile"])]
            row = {"name": name, "family": "iforest", "meta": dict(m, seed=seed), "threshold": th}
            s = score(S, name, "iforest", row["meta"])
            _, al = ml_alerts(S, s, th, S.n)
            per[seed] = {h: {**event_metrics(S, s, S.halves[h]),
                             **ml_metrics(S, al, S.halves[h], h, rk)} for h in P3B.HALVES}
        keys = ("attacking_ips_incremental", "incremental_incidents", "incremental_precision",
                "incremental_ci_low", "ml_alert_precision", "roc_auc", "pr_auc")
        out["seeds"] = {"per_seed": per, "summary": {
            h: {k: {"mean": float(np.mean([per[s][h][k] for s in per])),
                    "min": float(np.min([per[s][h][k] for s in per])),
                    "max": float(np.max([per[s][h][k] for s in per]))} for k in keys}
            for h in P3B.HALVES} if per else {}}
        clk.tick(f"seeds {sorted(per)}", t)
    out["timings_seconds"] = clk.total()
    save_json("phase4_confirm.json", out)
    for label, r in out["rows"].items():
        a, b = r["val_a"], r["val_b"]
        print(f"{label:22s} {r['name']:30s} q={r['quantile']:<6g} "
              f"A inc {a['incremental_incidents']:>6} {a['incremental_precision']:.3f} "
              f"[{a['incremental_ci_low']:.3f},{a['incremental_ci_high']:.3f}] att {a['attacking_ips_incremental']:>5} | "
              f"B inc {b['incremental_incidents']:>6} {b['incremental_precision']:.3f} "
              f"[{b['incremental_ci_low']:.3f},{b['incremental_ci_high']:.3f}] att {b['attacking_ips_incremental']:>5} "
              f"holds {b['holds']} (vs 0.2149: {b['meets_val_a_bar']})")


# ── Stage: workload (val_b) ──────────────────────────────────────────────────

def stage_workload(args):
    clk = Clock()
    t = time.time()
    S = stream()
    rk = rule_keys(S)
    sel = load_json("phase4_selection.json")
    sel3b = P3B.load_json("phase3b_selection.json")
    score_of = {d: sel3b["chosen"][d]["precision"] for d in R.RULE_DETECTORS}
    rules = dict(rk["_by_detector"])
    _, p2_alert = P3B.ml_arrays(S)
    c = sel["deployment"]["candidate"]
    s = score(S, c["name"], c["family"], c["meta"])
    _, v4_alert = ml_alerts(S, s, c["threshold"], S.n)
    v4_prec = sel["chosen_row"]["val_a"]["ml_alert_precision"]
    n_days = int(len(np.unique(S.day[S.val_b])))
    V4 = "ML v4"
    configs = OrderedDict([
        ("rules_v3", (rules, score_of)),
        ("rules_v3_plus_phase2_ml", (dict(rules, **{R.ML: p2_alert}),
                                     dict(score_of, **{R.ML: sel3b["chosen"][R.ML]["precision"]}))),
        ("rules_v3_plus_v4_ml", (dict(rules, **{V4: v4_alert}), dict(score_of, **{V4: v4_prec}))),
    ])
    out = {"half": "val_b", "days": n_days, "v4_ml": c["name"], "v4_ml_quantile": c["quantile"],
           "v4_ml_alerting_in_deployment": sel["deployment"]["alerting"],
           "v4_ml_score_val_a_precision": v4_prec, "configs": {}}
    for cname, (al, sc) in configs.items():
        out["configs"][cname] = {}
        for sub in P3B.SUBSETS:
            part = S.subsets["val_b"][sub]
            out["configs"][cname][sub] = P3B.workload(S, al, part, S.attacking_ips(part), n_days, sc)
    clk.tick("incidents and budgets on val_b", t)
    out["timings_seconds"] = clk.total()
    save_json("phase4_workload.json", out)
    for cname, per in out["configs"].items():
        for sub, w in per.items():
            print(f"{cname:24s} {sub:17s} inc/d {w['incidents_per_day']:>7.0f} prec "
                  f"{w['incident_precision']:.3f} att {w['attacking_ips_flagged']}/{w['attacking_ips']} | "
                  + " ".join(f"B{B}: {b['incident_precision']:.3f} {b['attacking_ips_caught']}"
                             for B, b in w["budgets"].items()))


# ── Stage: replay (real agents, v3 rules + v4 ML) ────────────────────────────

def stage_replay(args):
    from agents.analysis_agent import AnalysisAgent
    from agents.detection_agent import DetectionAgent
    from agents.response_agent import ResponseAgent
    from eval.harness import NullEmailAlerter, override_config
    from ml.model_v4 import V4Scorer
    clk = Clock()
    t = time.time()
    S = stream()
    _, settings = P3B.chosen_settings()
    sel = load_json("phase4_selection.json")
    c = sel["deployment"]["candidate"]
    off_score = score(S, c["name"], c["family"], c["meta"])
    off_match = off_score >= c["threshold"]
    alerting = sel["deployment"]["alerting"]
    off_alert = np.zeros(S.n, bool)
    if alerting:
        off_alert[ml_alerts(S, off_score, c["threshold"], S.n)[1]] = True
    X = np.load(cache("X.npy"), mmap_mode="r")
    match_r, alert_r = P3B.load_alerts(S, with_ml=False)
    scorer = V4Scorer.load(MODEL_V4)
    clk.tick("load stream, selection, offline scores, model_v4", t)

    names = list(R.RULE_DETECTORS)
    idx = {d: j for j, d in enumerate(names)}
    got_match = np.zeros((S.n, len(names)), bool)
    got_alert = np.zeros((S.n, len(names)), bool)
    got_score = np.full(S.n, np.nan)
    got_ml_alert = np.zeros(S.n, bool)
    got_blocked = np.zeros(S.n, bool)
    vec_mismatch = 0
    blocks = 0
    t = time.time()
    with override_config(RULES_MODE="v3", ML_MODE="v4", **settings), \
            contextlib.redirect_stdout(io.StringIO()):
        agent = DetectionAgent(anomaly_detector=scorer)
        analysis = AnalysisAgent()
        response = ResponseAgent(email_alerter=NullEmailAlerter())
        CH = 65536
        buf = np.empty((CH, F.N_FEATURES))
        for i, e in enumerate(events(S, with_id=True)):
            got_blocked[i] = response.block_list.is_blocked(e["ip"], int(S.t[i]))
            det = agent.analyze(e)
            got_score[i] = det.ml["score"]
            buf[i % CH] = scorer.last_vector
            if i % CH == CH - 1 or i == S.n - 1:
                lo = i - i % CH
                vec_mismatch += int((~np.equal(buf[:i - lo + 1], X[lo:i + 1])).any(1).sum())
            for d in det.matched:
                if d in idx:
                    got_match[i, idx[d]] = True
            for a in det.alerts:
                if a["type"] == R.ML:
                    got_ml_alert[i] = True
                else:
                    got_alert[i, idx[a["type"]]] = True
                a["timestamp"] = e["timestamp"]
                response.take_action(analysis.evaluate_alert(a))
                blocks += bool(response.last_response["simulated_block"])
            response.actions_log.clear()
    t_replay = time.time() - t
    clk.tick("real v3 + v4 replay (detection + analysis + response)", t)

    spans = {"dev_train": ~S.val, "val_a": S.val_a, "val_b": S.val_b}
    score_eq = np.equal(got_score, off_score)
    got_ml_match = got_score >= c["threshold"]
    check, ok = {"ml": {}}, vec_mismatch == 0
    for span, m in spans.items():
        cs, cm, ca = (int((~score_eq)[m].sum()), int((got_ml_match != off_match)[m].sum()),
                      int((got_ml_alert != off_alert)[m].sum()))
        check["ml"][span] = {"score_mismatches": cs, "match_mismatches": cm, "alert_mismatches": ca,
                             "offline_alerts": int(off_alert[m].sum()), "replay_alerts": int(got_ml_alert[m].sum()),
                             "offline_matches": int(off_match[m].sum())}
        ok &= cs == 0 and cm == 0 and ca == 0
    for d in names:
        em = np.zeros(S.n, bool)
        em[match_r[d]] = True
        ea = np.zeros(S.n, bool)
        ea[alert_r[d]] = True
        check[d] = {}
        for span, m in spans.items():
            cm, ca = int((em != got_match[:, idx[d]])[m].sum()), int((ea != got_alert[:, idx[d]])[m].sum())
            check[d][span] = {"match_mismatches": cm, "alert_mismatches": ca,
                              "replay_alerts": int(got_alert[:, idx[d]][m].sum())}
            ok &= cm == 0 and ca == 0
    ok &= blocks == 0 and not got_blocked.any()
    out = {"equivalent": bool(ok), "model": c["name"], "alerting": alerting,
           "feature_vector_mismatches": vec_mismatch, "blocks_placed": blocks,
           "blocked_source_events": int(got_blocked.sum()), "events": int(S.n),
           "per_detector": check, "state_sizes_end": agent.state_sizes(),
           "feature_state_sizes_end": scorer.extractor.state_sizes(),
           "replay_seconds": round(t_replay, 1), "replay_us_per_event": round(1e6 * t_replay / S.n, 1),
           "peak_rss_mb": peak_rss_mb(), "timings_seconds": clk.total()}
    save_json("phase4_replay_check.json", out)
    for d, per in check.items():
        print(f"{d:26s} " + "  ".join(f"{s}: " + " ".join(f"{k.split('_')[0]} {v}" for k, v in c_.items()
                                                       if k.endswith("mismatches"))
                                      for s, c_ in per.items()))
    print(f"equivalent={ok} vectors_mismatched={vec_mismatch} blocks={blocks} replay {t_replay:.0f} s")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=["features", "fit", "select", "confirm", "workload", "replay"])
    ap.add_argument("--part", choices=["all", "fixed", "if", "hgb"], default="all")
    ap.add_argument("--sets", default="", help="fit: comma-separated feature sets (default all)")
    ap.add_argument("--grid", default="", help="fit --part hgb: comma-separated HGB_GRID indices")
    ap.add_argument("--chosen-seeds", action="store_true", help="fit: seeds 43, 44 of the chosen forest")
    args = ap.parse_args()
    os.makedirs(CACHE, exist_ok=True)
    return {"features": stage_features, "fit": stage_fit, "select": stage_select,
            "confirm": stage_confirm, "workload": stage_workload,
            "replay": stage_replay}[args.stage](args) or 0


if __name__ == "__main__":
    sys.exit(main())
