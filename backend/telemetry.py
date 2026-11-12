"""Telemetry for the dashboard. Everything here is measured from the running system or labelled as simulated."""
import os, random, re, threading, time
from collections import deque
import numpy as np
from flask import jsonify, request

# Reference data (MITRE ATT&CK names and tactics) and project-defined risk inputs. Not measurements.
MITRE = {"T1530": ("Data from Cloud Storage", "Collection"),
         "T1562.008": ("Impair Defenses: Disable or Modify Cloud Logs", "Defense Evasion"),
         "T1133": ("External Remote Services", "Initial Access, Persistence"),
         "T1078.004": ("Valid Accounts: Cloud Accounts", "Initial Access, Persistence, Privilege Escalation, Defense Evasion")}
ASSET = {"s3": ("Holds student records", 1.0), "ct": ("Account-wide audit log", 0.9),
         "sg": ("Remote access to servers", 0.7), "key": ("Employee credential", 0.7)}
SEVW = {"Critical": 1.0, "High": 0.75, "Medium": 0.5, "Low": 0.25}
W = dict(cspm=0.35, ml=0.35, asset=0.30)  # project-defined weights, not learned
EVMAP = {"s3": "DeleteBucketPublicAccessBlock", "ct": "StopLogging", "sg": "AuthorizeSecurityGroupIngress", "key": "ListBuckets x90"}


def register_telemetry(app, g):
    R, F, LIVE, MODE, now = g["R"], g["F"], g["LIVE"], g["MODE"], g["now"]
    THR = float(-g["MODEL"].offset_)  # Isolation Forest flags an event when its anomaly score exceeds this
    POSTURE, ASC, EVLOG, seq = deque(maxlen=720), deque(maxlen=600), deque(maxlen=3000), [0]

    def score(hour, country, calls):
        return float(-g["MODEL"].score_samples(np.array([[hour, g["CTRY"][country], calls]]))[0])

    def log_event(name, src, user, country, kind):
        seq[0] += 1
        EVLOG.appendleft(dict(id=seq[0], ts=time.time(), t=now(), name=name, src=src, user=user, country=country, kind=kind, mode=MODE))

    orig_emit, orig_ml = g["emit"], g["ml_check"]

    def emit(name, src, user, country="IN"):
        orig_emit(name, src, user, country)
        log_event(name, src, user, country, "attack")

    def ml_check(hour, country, calls):
        ASC.append(dict(t=time.time(), score=round(score(hour, country, calls), 4), kind="attack"))
        orig_ml(hour, country, calls)
    g["emit"], g["ml_check"] = emit, ml_check

    if LIVE:  # never run attack simulations against a real account
        def blocked():
            raise RuntimeError("Attack simulation is disabled in Live AWS mode")
        for k in R:
            R[k]["attack"] = blocked

    def posture_loop():
        time.sleep(3)
        while True:
            try:
                ok = sum(bool(r["check"]()) for r in R.values())
                POSTURE.append(dict(t=time.time(), score=round(100 * ok / len(R)), open=sum(1 for f in F.values() if f["status"] == "pending")))
            except Exception as e:
                print("telemetry posture error:", repr(e))
            time.sleep(5)

    def baseline_loop():  # simulated normal traffic, scored by the real model. Simulator mode only.
        rng = random.Random(7)
        ops = [("s3", "GetObject"), ("s3", "ListBuckets"), ("ec2", "DescribeInstances"), ("cloudwatch", "GetMetricData"), ("lambda", "ListFunctions")]
        while True:
            time.sleep(rng.uniform(2.5, 5))
            svc, op = rng.choice(ops)
            s = score(rng.randint(8, 18), "IN", rng.randint(1, 11))
            log_event(op, svc, "user-%03d" % rng.randint(1, 8), "IN", "baseline")
            ASC.append(dict(t=time.time(), score=round(s, 4), kind="baseline"))
    threading.Thread(target=posture_loop, daemon=True).start()
    if not LIVE and os.getenv("CG_BASELINE", "1") == "1":
        threading.Thread(target=baseline_loop, daemon=True).start()

    def buckets():
        cur, out = int(time.time() // 60), {}
        for e in EVLOG:
            m = int(e["ts"] // 60)
            if cur - m < 30:
                out.setdefault(m, dict(baseline=0, attack=0))[e["kind"]] += 1
        return [dict(t=m * 60, **v) for m, v in sorted(out.items())]

    def audit_lines():
        with g["audit_lock"]:
            return [r[0] for r in g["audit_db"].execute("SELECT text FROM audit ORDER BY i").fetchall()]

    @app.get("/api/metrics")
    def metrics():
        with g["audit_lock"]:
            rb = g["audit_db"].execute("SELECT COUNT(*) FROM audit WHERE text LIKE ?", ("%ROLLED BACK%",)).fetchone()[0]
        items = [dict(id=k, status=f["status"], ttd=f.get("tdetect"), verified=f.get("verified"),
                      ttr=round(f["t_fix"] - f["t0"], 1) if f.get("t_fix") and f.get("t0") else None) for k, f in F.items()]
        done = [i for i in items if i["status"] == "fixed"]
        return jsonify(posture=list(POSTURE), anomaly=list(ASC)[-400:], threshold=round(THR, 4), buckets=buckets(), events_total=len(EVLOG),
                       rem=dict(items=items, fixed=len(done), verified=sum(1 for i in done if i["verified"]), rolled_back=rb))

    @app.get("/api/events")
    def events_api():
        q, kind = (request.args.get("q") or "").lower(), request.args.get("kind") or ""
        rows = [e for e in EVLOG if (not kind or e["kind"] == kind) and (not q or q in (e["name"] + e["user"] + e["src"] + e["country"]).lower())]
        return jsonify(total=len(EVLOG), matched=len(rows), rows=rows[:300])

    @app.get("/api/finding/<k>")
    def finding(k):
        f = F.get(k)
        if not f:
            return jsonify(error="unknown finding"), 404
        r = R[k]
        m = re.search(r"T\d{4}(?:\.\d{3})?", r["ref"])
        tid = m.group(0) if m else None
        name, tactics = MITRE.get(tid, (None, None))
        asc = [a for a in ASC if a["kind"] == "attack"]
        parts = {"CSPM severity": (W["cspm"], SEVW.get(r["sev"], .5))}
        if k == "key" and asc:
            parts["ML anomaly score"] = (W["ml"], asc[-1]["score"])
        parts["Asset sensitivity"] = (W["asset"], ASSET[k][1])
        tot = sum(w for w, _ in parts.values())
        rows = [dict(name=n, weight=round(w / tot, 2), value=round(v, 2), points=round(w / tot * v * 100, 1)) for n, (w, v) in parts.items()]
        lines = [t for t in audit_lines() if re.search(r"\b%s\b" % re.escape(k), t) or r["title"] in t]
        return jsonify(id=k, title=r["title"], sev=r["sev"], status=f["status"], ref=r["ref"], what=r["what"], why=r["why"], fix=r["fixtxt"],
                       mitre=dict(id=tid, name=name, tactics=tactics), explain=f.get("explain"), verified=f.get("verified"),
                       detected=f.get("detected"), before=f.get("before"), after=f.get("after"), current=g["state_fn"](k),
                       risk=dict(score=round(sum(x["points"] for x in rows)), rows=rows, note="Weights are project-defined, not learned.",
                                 excluded="Graph exposure is not included because the IAM graph is not built yet."),
                       events=[e for e in EVLOG if e["name"] == EVMAP[k]][:5], timeline=lines[-14:], asset=ASSET[k][0])
