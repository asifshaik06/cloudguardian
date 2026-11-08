"""Train on a benign baseline only, pick thresholds on validation data only, and evaluate on three evidence levels:
1) controlled benchmark (exact labels, same generator), 2) newer real attack logs (recall only),
3) old real logs such as flaws.cloud (unlabelled: alert rate and top windows for manual review)."""
import argparse, glob, json, os, sys
sys.path.insert(0, os.getcwd())
import joblib, numpy as np, pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, precision_recall_fscore_support
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM
from backend.ml_engine.pipeline import FEATURES, START, gen_attacks, gen_benign, read_records, to_frame, windows

LOG = ["call_count", "call_velocity", "unique_services", "unique_events", "sensitive_count", "iam_change_count"]
TRAIN_END, VAL_END = START + pd.Timedelta(days=10), START + pd.Timedelta(days=14)


def prep(w):
    X = w[FEATURES].copy()
    X[LOG] = np.log1p(X[LOG])
    return X.to_numpy(float)


def fit(Xtr):
    sc = StandardScaler().fit(Xtr)
    Z = sc.transform(Xtr)
    return sc, {"isolation_forest": IsolationForest(n_estimators=200, random_state=0).fit(Z),
                "lof": LocalOutlierFactor(n_neighbors=20, novelty=True).fit(Z),
                "ocsvm": OneClassSVM(nu=0.01, gamma="scale").fit(Z)}


def score(sc, models, X):
    Z = sc.transform(X)
    Zf = (X - sc.mean_) / np.maximum(sc.scale_, 0.1)  # variance floor
    out = {"zscore": np.abs(Zf).max(axis=1)}
    out.update({k: -m.score_samples(Z) for k, m in models.items()})
    return out


def load_real(folder, label, limit=None):
    files = sorted(glob.glob(os.path.join(folder, "**", "*.json*"), recursive=True))
    return [(os.path.basename(f), f) for f in files[:limit]]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--new", default="datasets/raw/new", help="folder of newer attack logs (Splunk, Stratus, your own)")
    ap.add_argument("--old", default="datasets/raw/flaws", help="folder with flaws.cloud .json.gz chunks")
    ap.add_argument("--old-files", type=int, default=3, help="how many flaws chunks to use (20 = all)")
    a = ap.parse_args()

    allw = windows(pd.concat([gen_benign(), gen_attacks()]).sort_values("time"))
    ben, att = allw[allw.label == 0], allw[allw.label == 1]
    tr = ben[ben.win < TRAIN_END]
    va = ben[(ben.win >= TRAIN_END) & (ben.win < VAL_END)]
    te = ben[ben.win >= VAL_END]
    print(f"windows: train={len(tr)} validation={len(va)} benign_test={len(te)} attack_windows={len(att)}")
    sc, models = fit(prep(tr))
    thr = {k: float(np.quantile(v, 0.99)) for k, v in score(sc, models, prep(va)).items()}  # ~1% false alarms

    s_te, s_att = score(sc, models, prep(te)), score(sc, models, prep(att))
    hours = max((te.win.max() - te.win.min()).total_seconds() / 3600, 1)
    res = {k: {} for k in thr}
    for k in thr:
        y = np.r_[np.zeros(len(te)), np.ones(len(att))]
        s = np.r_[s_te[k], s_att[k]]
        pred = (s > thr[k]).astype(int)
        p, r, f, _ = precision_recall_fscore_support(y, pred, average="binary", zero_division=0)
        res[k]["controlled"] = dict(precision=round(p, 3), recall=round(r, 3), f1=round(f, 3),
                                    pr_auc=round(average_precision_score(y, s), 3),
                                    benign_fpr=round(float((s_te[k] > thr[k]).mean()), 4),
                                    false_alarms_per_hour=round(float((s_te[k] > thr[k]).sum() / hours), 3))

    new_dir = a.new if os.path.isdir(a.new) else None
    for name, f in (load_real(new_dir, 1) if new_dir else []):
        w = windows(to_frame(read_records(f), name, 1))
        if w.empty:
            continue
        s = score(sc, models, prep(w))
        for k in thr:
            res[k].setdefault("new_real_recall", {})[name] = dict(windows=len(w), recall=round(float((s[k] > thr[k]).mean()), 3))

    old = []
    for name, f in load_real(a.old, -1, a.old_files) if os.path.isdir(a.old) else []:
        print("reading", name)
        old.append(to_frame(read_records(f), "flaws", -1))
    if old:
        w = windows(pd.concat(old).sort_values("time"))
        s = score(sc, models, prep(w))
        for k in thr:
            res[k]["old_real_unlabelled"] = dict(windows=len(w), alert_rate=round(float((s[k] > thr[k]).mean()), 4))
        top = w.assign(score=s["isolation_forest"]).sort_values("score", ascending=False).head(50)
        os.makedirs("datasets/processed", exist_ok=True)
        top.to_csv("datasets/processed/flaws_top_alerts_for_review.csv", index=False)

    os.makedirs("models", exist_ok=True); os.makedirs("docs", exist_ok=True)
    joblib.dump(dict(scaler=sc, models=models, thresholds=thr, features=FEATURES, log_features=LOG,
                     window="5min", threshold_rule="99th percentile of benign validation scores"), "models/baseline_v1.joblib")
    json.dump(res, open("docs/ml_results.json", "w"), indent=2)
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()

