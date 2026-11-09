import json

r = json.load(open("docs/ml_results.json"))
names = {"zscore": "Z-score", "isolation_forest": "Isolation Forest", "lof": "LocalOutlierFactor", "ocsvm": "OneClassSVM"}
lines = ["| Detector | Controlled F1 (synthetic) | False alarms per hour (synthetic) | Real attack windows flagged | flaws.cloud alert rate (unlabelled) |",
         "| --- | --- | --- | --- | --- |"]
for k, n in names.items():
    c = r[k]["controlled"]
    nr = r[k].get("new_real_recall", {})
    tot = sum(v["windows"] for v in nr.values())
    hit = round(sum(v["windows"] * v["recall"] for v in nr.values()))
    old = r[k].get("old_real_unlabelled")
    rate = "n/a" if not old else "{:.1f}%".format(old["alert_rate"] * 100)
    lines.append("| {} | {} | {} | {} of {} | {} |".format(n, c["f1"], c["false_alarms_per_hour"], hit, tot, rate))
open("docs/results_table.md", "w").write("\n".join(lines) + "\n")
print("\n".join(lines))
