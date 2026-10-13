# backend/eval/data_audit.py
"""
Phase 2 data audit, development months only (eval/datasets.py "dev": Feb to
Apr 2020). Nothing here reads the locked test file.

  - failed-login share among non-attack events, overall and by user, and the
    audit's open question 5 (56.4% failed "normal" training logins under the
    old user-disjoint sample against 23.9% for held-out normals), answered by
    rebuilding that sample from the Parquet rows in CSV order;
  - attack prevalence per week, label composition, attacking IPs that also
    carry non-attack events, per-user history length.

Writes results/phase2_data_audit.json. Run from backend/:
    python -m eval.data_audit
"""

import json
import os
import sys
import time

import numpy as np
import pandas as pd

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from eval import datasets  # noqa: E402

OUT = os.path.join(BACKEND, "results", "phase2_data_audit.json")
COLS = ["index", "Login Timestamp", "User ID", "IP Address", "Login Successful",
        "Is Attack IP", "Is Account Takeover", "Device Type", "Country"]

# Old pipeline (ml/train_from_dataset_v2.py): first 700k non-attack rows and
# first 70k attack rows of the CSV, users shuffled with RandomState(42), 30%
# held out.
OLD_NORMAL_TARGET, OLD_HELD_OUT, OLD_SEED = 700_000, 0.30, 42


def q(s, ps=(0.5, 0.9, 0.99, 0.999)):
    s = pd.Series(s)
    out = {f"p{int(p * 1000) / 10:g}": float(s.quantile(p)) for p in ps}
    out.update(min=float(s.min()), mean=float(s.mean()), max=float(s.max()))
    return out


def failure_shares(df):
    """Event-weighted and user-weighted failure share, plus per-user frame."""
    g = df.groupby("User ID", observed=True)["failed"].agg(["size", "sum"])
    g["share"] = g["sum"] / g["size"]
    return {
        "events": int(len(df)),
        "users": int(len(g)),
        "failed_share_events": float(df["failed"].mean()),
        "failed_share_mean_over_users": float(g["share"].mean()),
        "users_all_failed": int((g["share"] == 1).sum()),
        "users_never_failed": int((g["share"] == 0).sum()),
    }, g


def old_sample_question(dev):
    """Rebuild the Batch 1-5 normal sample and its user-disjoint split."""
    normal = dev[~dev["attack"]].iloc[:OLD_NORMAL_TARGET]
    assert len(normal) == OLD_NORMAL_TARGET
    users = np.array(normal["User ID"].unique(), dtype=object)
    np.random.RandomState(OLD_SEED).shuffle(users)
    held = set(users[:int(len(users) * OLD_HELD_OUT)])
    is_held = normal["User ID"].isin(held)
    train, heldout = normal[~is_held], normal[is_held]

    tr, g_tr = failure_shares(train)
    ho, g_ho = failure_shares(heldout)
    top = g_tr.sort_values("size", ascending=False)
    contrib = []
    for k in (1, 2, 3, 5, 10, 20):
        rest = train[~train["User ID"].isin(top.index[:k])]
        contrib.append({"exclude_top_k_train_users": k,
                        "train_events_left": int(len(rest)),
                        "train_failed_share": float(rest["failed"].mean())})
    g_all = normal.groupby("User ID", observed=True)["failed"].agg(["size", "sum"])
    top_all = g_all.sort_values("size", ascending=False).head(10)
    return {
        "sample_rows": int(len(normal)),
        "sample_time_range": [str(normal[datasets.TS].min()), str(normal[datasets.TS].max())],
        "sample_users": int(len(users)),
        "train": tr, "held_out": ho,
        "train_failed_share_without_top_users": contrib,
        "top10_users_in_sample": [
            {"user": str(u), "events": int(r["size"]), "failed_share": float(r["sum"] / r["size"]),
             "share_of_sample_events": float(r["size"] / len(normal)),
             "side": "held_out" if u in held else "train"}
            for u, r in top_all.iterrows()],
    }


def main():
    t0 = time.time()
    dev = datasets.load("dev", columns=COLS)
    dev["failed"] = ~dev["Login Successful"]
    dev["attack"] = dev["Is Attack IP"] | dev["Is Account Takeover"]
    is_train = dev[datasets.TS] < datasets.DEV_TRAIN_END
    t_load = time.time() - t0
    res = {"loaded_rows": int(len(dev)), "load_seconds": round(t_load, 1)}

    # File order is time order inside the window.
    res["index_increasing"] = bool(dev["index"].is_monotonic_increasing)
    res["timestamps_non_decreasing"] = bool(dev[datasets.TS].is_monotonic_increasing)

    # ── splits ──
    train_users = set(dev.loc[is_train, "User ID"].unique())
    val = dev[~is_train]
    cold = val[~val["User ID"].isin(train_users)]
    res["splits"] = {}
    for name, part in (("dev_train", dev[is_train]), ("dev_val", val), ("dev_val_cold", cold)):
        res["splits"][name] = {
            "rows": int(len(part)), "users": int(part["User ID"].nunique()),
            "ips": int(part["IP Address"].nunique()),
            "attack_events": int(part["attack"].sum()),
            "attack_prevalence": float(part["attack"].mean()),
            "is_attack_ip_events": int(part["Is Attack IP"].sum()),
            "account_takeover_events": int(part["Is Account Takeover"].sum()),
            "failed_share": float(part["failed"].mean()),
            "time_range": [str(part[datasets.TS].min()), str(part[datasets.TS].max())],
        }

    # ── (b) failures among non-attack events ──
    benign = dev[~dev["attack"]]
    overall, g = failure_shares(benign)
    by_split = {n: failure_shares(benign[m])[0]
                for n, m in (("dev_train", is_train[~dev["attack"]]),
                             ("dev_val", ~is_train[~dev["attack"]]))}
    top20 = g.sort_values("size", ascending=False).head(20)
    extra = benign[benign["User ID"].isin(top20.index)].groupby("User ID", observed=True).agg(
        ips=("IP Address", "nunique"), countries=("Country", "nunique"),
        devices=("Device Type", lambda s: ",".join(sorted(map(str, s.unique())))))
    res["failures_non_attack"] = {
        "overall": overall, "by_split": by_split,
        "per_user_share_quantiles": q(g["share"]),
        "per_user_share_quantiles_users_with_10plus_events": q(g.loc[g["size"] >= 10, "share"]),
        "top20_users": [
            {"user": str(u), "events": int(r["size"]), "failed": int(r["sum"]),
             "failed_share": float(r["share"]),
             "share_of_benign_events": float(r["size"] / len(benign)),
             "distinct_ips": int(extra.loc[u, "ips"]),
             "distinct_countries": int(extra.loc[u, "countries"]),
             "device_types": extra.loc[u, "devices"]}
            for u, r in top20.iterrows()],
        "top20_events_share": float(top20["size"].sum() / len(benign)),
        "failed_share_without_top20": float(
            benign.loc[~benign["User ID"].isin(top20.index), "failed"].mean()),
    }
    res["old_sample_question5"] = old_sample_question(dev)

    # ── (c) attacks ──
    week = ((dev[datasets.TS] - datasets.DEV_START).dt.days // 7).astype(int)
    wk = dev.groupby(week).agg(rows=("attack", "size"), attack=("attack", "sum"),
                               attack_ip=("Is Attack IP", "sum"),
                               ato=("Is Account Takeover", "sum"))
    res["weekly"] = [
        {"week": int(w), "start": str((datasets.DEV_START + pd.Timedelta(weeks=int(w))).date()),
         "split": "dev_train" if w < 8 else "dev_val",
         "rows": int(r["rows"]), "attack_events": int(r["attack"]),
         "prevalence": float(r["attack"] / r["rows"]),
         "is_attack_ip_events": int(r["attack_ip"]), "ato_events": int(r["ato"])}
        for w, r in wk.iterrows()]

    a = dev[dev["attack"]]
    aip = dev["Is Attack IP"]
    ato = dev["Is Account Takeover"]
    per_ip = a.groupby("IP Address", observed=True).size()
    per_user = a.groupby("User ID", observed=True).size()
    attack_ips = set(per_ip.index)
    ip_benign = dev[~dev["attack"] & dev["IP Address"].isin(attack_ips)]
    mixed = ip_benign["IP Address"].nunique()
    # Is Attack IP should be a property of the IP: check it is constant per IP.
    ip_flag = dev.groupby("IP Address", observed=True)["Is Attack IP"].agg(["min", "max"])
    ato_rows = dev[ato]
    res["attacks"] = {
        "label_composition": {
            "attack_ip_only": int((aip & ~ato).sum()),
            "account_takeover_only": int((~aip & ato).sum()),
            "both": int((aip & ato).sum()),
        },
        "attacking_ips": int(len(per_ip)),
        "events_per_attacking_ip": q(per_ip),
        "attacking_ips_with_1_event": int((per_ip == 1).sum()),
        "attacked_users": int(len(per_user)),
        "attack_events_per_attacked_user": q(per_user),
        "attack_success_share": float((~a["failed"]).mean()),
        "attack_ip_success_share": float((~dev.loc[aip, "failed"]).mean()),
        "ato": {
            "events": int(ato.sum()), "users": int(ato_rows["User ID"].nunique()),
            "ips": int(ato_rows["IP Address"].nunique()),
            "successful": int((~ato_rows["failed"]).sum()),
            "also_attack_ip": int(ato_rows["Is Attack IP"].sum()),
        },
        "attacking_ips_also_in_non_attack_events": int(mixed),
        "non_attack_events_on_attacking_ips": int(len(ip_benign)),
        "ips_with_inconsistent_is_attack_ip_flag": int((ip_flag["min"] != ip_flag["max"]).sum()),
        "attacked_users_with_benign_events": int(
            dev.loc[~dev["attack"] & dev["User ID"].isin(per_user.index), "User ID"].nunique()),
        "attacked_users_attack_only": int(len(set(per_user.index) - set(
            dev.loc[~dev["attack"], "User ID"].unique()))),
    }

    # ── per-user history ──
    epu = dev.groupby("User ID", observed=True).size()
    prior = dev.groupby("User ID", observed=True).cumcount()   # events of the user before this one
    pv = prior[~is_train]
    pv_benign = prior[~is_train & ~dev["attack"]]
    res["history"] = {
        "users_dev": int(len(epu)),
        "events_per_user_dev": q(epu),
        "users_with_1_event": int((epu == 1).sum()),
        "users_with_le_5_events": int((epu <= 5).sum()),
        "users_with_ge_20_events": int((epu >= 20).sum()),
        "events_per_user_dev_train": q(dev[is_train].groupby("User ID", observed=True).size()),
        "dev_val_prior_events_of_user": q(pv),
        "dev_val_events_with_0_prior": float((pv == 0).mean()),
        "dev_val_events_with_lt_5_prior": float((pv < 5).mean()),
        "dev_val_events_with_ge_20_prior": float((pv >= 20).mean()),
        "dev_val_benign_events_with_0_prior": float((pv_benign == 0).mean()),
        "dev_val_attack_events_with_0_prior": float((prior[~is_train & dev["attack"]] == 0).mean()),
        "events_per_ip_dev": q(dev.groupby("IP Address", observed=True).size()),
    }
    # ── the dominant user ID (question 5) ──
    top_user = epu.idxmax()
    is_top = dev["User ID"] == top_user
    top = dev[is_top]
    pv_rest = prior[~is_train & ~is_top]
    res["dominant_user"] = {
        "user": str(top_user),
        "events": int(len(top)), "share_of_dev_events": float(is_top.mean()),
        "share_of_dev_val_events": float(is_top[~is_train].mean()),
        "attack_events": int(top["attack"].sum()),
        "share_of_all_attack_events": float(top["attack"].sum() / dev["attack"].sum()),
        "benign_events": int((~top["attack"]).sum()),
        "failed_share_benign": float(top.loc[~top["attack"], "failed"].mean()),
        "failed_share_attack": float(top.loc[top["attack"], "failed"].mean()),
        "successful_events": int((~top["failed"]).sum()),
        "distinct_ips": int(top["IP Address"].nunique()),
        "distinct_countries": int(top["Country"].nunique()),
        "attack_prevalence_without_user": {
            "dev_train": float(dev.loc[is_train & ~is_top, "attack"].mean()),
            "dev_val": float(dev.loc[~is_train & ~is_top, "attack"].mean()),
        },
        "benign_failed_share_without_user": {
            "dev_train": float(dev.loc[is_train & ~is_top & ~dev["attack"], "failed"].mean()),
            "dev_val": float(dev.loc[~is_train & ~is_top & ~dev["attack"], "failed"].mean()),
        },
        "dev_val_prior_events_of_user_excluding_it": q(pv_rest),
        "dev_val_events_with_0_prior_excluding_it": float((pv_rest == 0).mean()),
        "dev_val_events_with_lt_5_prior_excluding_it": float((pv_rest < 5).mean()),
        "dev_val_events_with_ge_20_prior_excluding_it": float((pv_rest >= 20).mean()),
    }
    res["seconds"] = round(time.time() - t0, 1)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump(res, f, indent=2)
        f.write("\n")
    print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
