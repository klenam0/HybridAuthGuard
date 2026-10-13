# backend/ml/model_v4.py
"""
Phase 4 ML step for the v3 engine (config.ML_MODE = "v4"; eval/PROTOCOL.md
amendment 4). V4Scorer wraps one ml.features_v4.FeatureExtractorV4 and the
chosen model, and has the score_event() interface the v3 DetectionAgent
calls on every event. The extractor's state advances on every call.

Model kinds (bundle["kind"]):
  "iforest"   Isolation Forest on bundle["columns"] of the feature vector;
              score = -decision_function, computed by FastIForest, which is
              bit-identical to scikit-learn's batch decision_function.
  "freeman"   Freeman et al. (2016) log risk at bundle["beta_index"].
  "new_ip"    1.0 if the user has no prior event from the IP.
An event alerts if bundle["alerting"] and score >= bundle["threshold"]. If
the amendment 4 fallback applied, "alerting" is False: the model runs and
reports its score but never raises an ML alert.

data/model_v4.pkl holds the bundle. It never replaces data/model.pkl.
Loading a pickle runs code from it; set MODEL_V4_SHA256 to pin the file.
"""

import hashlib
import os
import pickle

import numpy as np

from ml.features_v4 import FEATURE_NAMES, FeatureExtractorV4

KINDS = ("iforest", "freeman", "new_ip")


class FastIForest:
    """
    Single-event Isolation Forest scoring with scikit-learn's arithmetic:
    float32 input, per-tree term (path length + average path length of the
    leaf) - 1.0, summed tree by tree in order, 2 ** -(sum / denominator).
    Returns -decision_function.
    """

    def __init__(self, model):
        from sklearn.ensemble._iforest import _average_path_length
        trees = [e.tree_ for e in model.estimators_]
        assert model._max_features == model.n_features_in_, "feature subsampling not supported"
        T, M = len(trees), max(t.node_count for t in trees)
        self.left = np.zeros((T, M), np.int64)
        self.right = np.zeros((T, M), np.int64)
        self.feature = np.full((T, M), -2, np.int64)
        self.threshold = np.zeros((T, M), np.float64)
        self.leafval = np.zeros((T, M), np.float64)
        for k, t in enumerate(trees):
            n = t.node_count
            self.left[k, :n] = t.children_left
            self.right[k, :n] = t.children_right
            self.feature[k, :n] = t.feature
            self.threshold[k, :n] = t.threshold
            self.leafval[k, :n] = (model._decision_path_lengths[k]
                                   + model._average_path_length_per_tree[k] - 1.0)
        self.depth = max(int(t.max_depth) for t in trees)
        # Flat arrays: node j of tree k is k * M + j. Leaves point to themselves
        # and test feature 0, so a fixed number of steps lands every tree on
        # its leaf.
        base = (np.arange(T) * M)[:, None]
        leaf = self.feature < 0
        idx = np.arange(M)[None, :] + base
        self.left = np.where(leaf, idx, self.left + base).ravel()
        self.right = np.where(leaf, idx, self.right + base).ravel()
        self.feature = np.where(leaf, 0, self.feature).ravel()
        self.threshold = self.threshold.ravel()
        self.leafval = self.leafval.ravel()
        self.start = base.ravel()
        self.denominator = T * _average_path_length([model._max_samples])
        self.offset = float(model.offset_)

    def score(self, x):
        x = np.asarray(x, dtype=np.float32)
        node = self.start
        feature, threshold, left, right = self.feature, self.threshold, self.left, self.right
        for _ in range(self.depth):
            node = np.where(x[feature[node]] <= threshold[node], left[node], right[node])
        depths = np.cumsum(self.leafval[node])[-1:]
        d = self.denominator
        scores = 2 ** (-np.divide(depths, d, out=np.ones_like(depths), where=d != 0))
        return -((-scores[0]) - self.offset)


def iforest_scores(model, X, n_jobs=8, chunk=200_000):
    """-decision_function of every row, in row chunks on threads (each chunk
    uses scikit-learn's sequential tree order, so results do not depend on
    the chunking)."""
    from concurrent.futures import ThreadPoolExecutor
    out = np.empty(len(X), np.float64)

    def run(s):
        out[s:s + chunk] = -model.decision_function(X[s:s + chunk])

    with ThreadPoolExecutor(n_jobs) as ex:
        list(ex.map(run, range(0, len(X), chunk)))
    return out


class V4Scorer:
    """The anomaly_detector of a v3 DetectionAgent in ML_MODE "v4"."""

    def __init__(self, bundle, extractor=None):
        if bundle["kind"] not in KINDS:
            raise ValueError(f"unknown v4 model kind {bundle['kind']!r}")
        if list(bundle["feature_names"]) != FEATURE_NAMES:
            raise ValueError("model_v4 was built for a different feature list")
        self.bundle = bundle
        self.kind = bundle["kind"]
        self.threshold = bundle.get("threshold")
        self.alerting = bool(bundle.get("alerting")) and self.threshold is not None
        self.extractor = extractor or FeatureExtractorV4()
        self.columns = list(bundle.get("columns") or [])
        self.forest = FastIForest(bundle["model"]) if self.kind == "iforest" else None
        self.new_ip_col = FEATURE_NAMES.index("a_new_ip")
        self.last_vector = None

    @classmethod
    def load(cls, path, sha256=None):
        sha256 = sha256 or os.environ.get("MODEL_V4_SHA256") or None
        with open(path, "rb") as f:
            raw = f.read()
        if sha256 and hashlib.sha256(raw).hexdigest() != sha256.lower():
            raise ValueError(f"{path}: SHA-256 does not match MODEL_V4_SHA256")
        return cls(pickle.loads(raw))

    @staticmethod
    def save(bundle, path):
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            pickle.dump(bundle, f, protocol=pickle.HIGHEST_PROTOCOL)
        os.replace(tmp, path)

    def score_vector(self, vec, freeman):
        if self.kind == "iforest":
            return float(self.forest.score(vec[self.columns]))
        if self.kind == "freeman":
            return float(freeman[self.bundle["beta_index"]])
        return float(vec[self.new_ip_col])

    def score_event(self, log_event):
        vec = self.extractor.update_and_extract(log_event)
        self.last_vector = vec
        score = self.score_vector(vec, self.extractor.last_freeman)
        alert = self.alerting and score >= self.threshold
        return {
            "is_anomaly": bool(alert),
            "anomaly_score": float(round(score, 4)),
            "confidence": "High" if alert else "Low",
            "feature_count": len(self.columns) or 1,
            "score": score,
            "model": self.bundle.get("name", self.kind),
        }
