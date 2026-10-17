# backend/eval/amendment10_lookup.py
"""
Amendment 10 (post hoc, written after the test was scored; dev data only;
descriptive): a blocklist-lookup baseline. score = 1 if the event's IP
appears in any attack-labelled dev_train row, else 0. Reported on val_a and
val_b, all events, next to S1 construction (a) read from phase4b_diag.json.
The locked test month is never read (the stream is datasets.load("dev")).

  python -m eval.amendment10_lookup     -> results/amendment10_lookup.json
"""
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eval import phase3b as P3B  # noqa: E402
from eval import phase4 as P4  # noqa: E402

save_json, load_json = P3B.save_json, P3B.load_json


def half(S, s, part):
    y = S.truth[part]
    hit = s[part] == 1
    m = P4.event_metrics(S, s, part)
    tp = int((hit & y).sum())
    return {"events": int(part.sum()), "attack_events": int(y.sum()),
            "base_rate": float(y.mean()),
            "roc_auc": m["roc_auc"], "pr_auc": m["pr_auc"],
            "flagged_events": int(hit.sum()), "true_positives": tp,
            "precision_score_1": float(tp / hit.sum()) if hit.any() else None,
            "recall_score_1": float(tp / y.sum()),
            "share_attack_events_ip_attack_in_dev_train": float(tp / y.sum())}


def main():
    S = P3B.stream()
    train = np.zeros(S.n, bool)
    train[:S.n_train] = True
    blocked = S.attacking_ips(train)                  # per IP code
    s = blocked[S.ip].astype(np.float64)
    diag = load_json("phase4b_diag.json")["variants"]["a"]
    out = {"amendment": 10,
           "description": "score = 1 if the event's IP appears in any attack-labelled "
                          "dev_train row, else 0; all events of each half",
           "label": "Is Attack IP or Is Account Takeover (Stream.truth)",
           "dev_train_rows": int(S.n_train), "dev_train_attack_ips": int(blocked.sum()),
           "metric_notes": {"roc_auc": "sklearn roc_auc_score on the binary score (ties averaged)",
                            "pr_auc": "sklearn average_precision_score on the binary score",
                            "share_attack_events_ip_attack_in_dev_train":
                                "equal to recall_score_1 by construction"},
           "lookup": {h: half(S, s, S.halves[h]) for h in P3B.HALVES},
           "s1_construction_a": {h: {"roc_auc": diag[h]["roc_auc"], "pr_auc": diag[h]["pr_auc"],
                                     "source": f"phase4b_diag.json variants/a/{h}"}
                                 for h in P3B.HALVES}}
    print(save_json("amendment10_lookup.json", out))
    for h in P3B.HALVES:
        r = out["lookup"][h]
        print(h, {k: (round(v, 4) if isinstance(v, float) else v) for k, v in r.items()},
              "| (a) roc_auc", round(out["s1_construction_a"][h]["roc_auc"], 4))


if __name__ == "__main__":
    main()
