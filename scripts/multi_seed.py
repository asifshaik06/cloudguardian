"""Repeat the controlled benchmark over many random seeds and report mean and spread."""
import os, sys
sys.path.insert(0, os.getcwd())
import numpy as np, pandas as pd
from sklearn.metrics import average_precision_score, precision_recall_fscore_support
from train_eval import TRAIN_END, VAL_END, fit, prep, score
from backend.ml_engine.pipeline import gen_attacks, gen_benign, windows

N = int(sys.argv[1]) if len(sys.argv) > 1 else 20
NAMES = {"zscore": "Z-score", "isolation_forest": "Isolation Forest", "lof": "LocalOutlierFactor", "ocsvm": "OneClassSVM"}
rows = {k: [] for k in NAMES}
for seed in range(N):
    allw = windows(pd.concat([gen_benign(seed=seed), gen_attacks(seed=seed + 1000)]).sort_values("time"))
    ben, att = allw[allw.label == 0], allw[allw.label == 1]
    tr = ben[ben.win < TRAIN_END]
    va = ben[(ben.win >= TRAIN_END) & (ben.win < VAL_END)]
    te = ben[ben.win >= VAL_END]
    sc, models = fit(prep(tr))
    thr = {k: float(np.quantile(v, 0.99)) for k, v in score(sc, models, prep(va)).items()}
    s_te, s_att = score(sc, models, prep(te)), score(sc, models, prep(att))
    y = np.r_[np.zeros(len(te)), np.ones(len(att))]
    for k in NAMES:
        s = np.r_[s_te[k], s_att[k]]
        p, r, f, _ = precision_recall_fscore_support(y, (s > thr[k]).astype(int), average="binary", zero_division=0)
        rows[k].append((p, r, f, average_precision_score(y, s), float((s_te[k] > thr[k]).mean())))
    print("seed", seed, "done", flush=True)

head = "| Detector | Precision | Recall | F1 | PR-AUC | Benign false-alarm rate |"
lines = ["Controlled synthetic benchmark, {} seeds, mean +/- standard deviation".format(N), "", head, "| --- | --- | --- | --- | --- | --- |"]
for k, n in NAMES.items():
    a = np.array(rows[k])
    cells = ["{:.3f} +/- {:.3f}".format(a[:, i].mean(), a[:, i].std()) for i in range(5)]
    lines.append("| " + n + " | " + " | ".join(cells) + " |")
os.makedirs("docs", exist_ok=True)
open("docs/multi_seed_results.md", "w").write("\n".join(lines) + "\n")
print("\n".join(lines))
