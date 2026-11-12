"""Extra dashboard API: hash-chained audit (SQLite, WAL), version-checked approvals, rollback, ML results."""
import csv, glob, hashlib, json, os, sqlite3, threading, time
import joblib
from flask import jsonify, request


def register(app, g):
    now, R, F, ANOM, AUDIT = g["now"], g["R"], g["F"], g["ANOM"], g["AUDIT"]
    redact = g.get("redact", lambda t: t)
    s3, ct, ec2, iam, ID = g["s3"], g["ct"], g["ec2"], g["iam"], g["ID"]
    BUCKET, TRAIL, USER, PERM = g["BUCKET"], g["TRAIL"], g["USER"], g["PERM"]

    db = sqlite3.connect("cg_audit.db", check_same_thread=False)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("CREATE TABLE IF NOT EXISTS audit(i INTEGER PRIMARY KEY, text TEXT, prev TEXT, hash TEXT)")
    db.commit()
    lock = threading.Lock()
    g["audit_db"], g["audit_lock"] = db, lock

    def audit(t):
        with lock:
            row = db.execute("SELECT hash, i FROM audit ORDER BY i DESC LIMIT 1").fetchone()
            prev, i = (row[0], row[1] + 1) if row else ("0" * 64, 0)
            text = "[{}] {}".format(now(), redact(str(t)))
            h = hashlib.sha256((prev + text).encode()).hexdigest()
            db.execute("INSERT INTO audit VALUES (?,?,?,?)", (i, text, prev, h))
            db.commit()
            AUDIT.appendleft(text)
    g["audit"] = audit

    def pab():
        try:
            return s3.get_public_access_block(Bucket=BUCKET)["PublicAccessBlockConfiguration"]
        except Exception:
            return None

    def cidrs():
        gp = ec2.describe_security_groups(GroupIds=[ID["sg"]])["SecurityGroups"][0]
        return sorted(r["CidrIp"] for p in gp["IpPermissions"] for r in p["IpRanges"])

    STATE = {"s3": pab, "ct": lambda: ct.get_trail_status(Name=TRAIL)["IsLogging"], "sg": cidrs,
             "key": lambda: [iam.list_access_keys(UserName=USER)["AccessKeyMetadata"][0]["Status"], ANOM["on"]]}

    g["state_fn"] = lambda k: STATE[k]()

    def ver(k):
        return hashlib.sha256(json.dumps(STATE[k](), sort_keys=True).encode()).hexdigest()[:12]

    def u_key():
        iam.update_access_key(UserName=USER, AccessKeyId=ID["key"], Status="Active")
        ANOM["on"] = True

    UNDO = {"s3": lambda: s3.delete_public_access_block(Bucket=BUCKET), "ct": lambda: ct.stop_logging(Name=TRAIL),
            "sg": lambda: ec2.authorize_security_group_ingress(GroupId=ID["sg"], IpPermissions=PERM("0.0.0.0/0")),
            "key": u_key}

    def wrap(k, fix):
        def w():
            F[k]["before"] = STATE[k]()
            fix()
            F[k]["after_ver"] = ver(k)
            F[k]["after"] = STATE[k]()
            F[k]["t_fix"] = time.time()
        return w
    for k in R:
        R[k]["fix"] = wrap(k, R[k]["fix"])

    orig_raise, orig_decide = g["raise_finding"], g["decide"]

    def raise_finding(k, explain=None):
        orig_raise(k, explain)
        F[k]["ver"] = ver(k)
        F[k]["t0"] = time.time()
        F[k]["detected"] = STATE[k]()

    def decide(k, ok, via):
        f = F.get(k)
        if f and f["status"] == "pending" and ok and f.get("ver") != ver(k):
            audit("STALE approval rejected for {}: the resource changed after detection, re-detecting".format(k))
            F.pop(k, None)
            return
        orig_decide(k, ok, via)
    g["raise_finding"], g["decide"] = raise_finding, decide

    @app.post("/api/rollback/<k>")
    def rollback(k):
        f = F.get(k)
        if not f or f.get("status") != "fixed":
            return jsonify(ok=False, error="nothing to roll back"), 400
        if ver(k) != f.get("after_ver"):
            audit("ROLLBACK refused for {}: the resource changed after the fix".format(k))
            return jsonify(ok=False, error="the resource changed after the fix, so rollback was refused"), 409
        UNDO[k]()
        f["status"], f["ver"] = "pending", ver(k)
        audit("ROLLED BACK {} to its pre-fix state, awaiting approval again".format(k))
        return jsonify(ok=True)

    @app.get("/api/audit")
    def audit_api():
        rows = db.execute("SELECT i, text, prev, hash FROM audit ORDER BY i").fetchall()
        prev, ok, bad = "0" * 64, True, None
        for i, text, p, h in rows:
            if p != prev or hashlib.sha256((p + text).encode()).hexdigest() != h:
                ok, bad = False, i
                break
            prev = h
        q = (request.args.get("q") or "").lower()
        sel = [r for r in rows if q in r[1].lower()]
        return jsonify(chain_ok=ok, first_bad=bad, count=len(rows), matched=len(sel),
                       rows=[dict(i=r[0], text=r[1], hash=r[3][:12]) for r in sel[-200:]][::-1])

    @app.get("/api/rules")
    def rules():
        return jsonify([dict(id=k, name=r["res"], title=r["title"], ref=r["ref"], sev=r["sev"], ok=bool(r["check"]())) for k, r in R.items()])

    def read(p):
        return open(p, encoding="utf-8").read() if os.path.exists(p) else ""

    @app.get("/api/ml")
    def ml():
        res = json.loads(read("docs/ml_results.json") or "{}")
        card = {}
        if os.path.exists("models/baseline_v1.joblib"):
            m = joblib.load("models/baseline_v1.joblib")
            card = dict(features=m["features"], thresholds={k: round(v, 3) for k, v in m["thresholds"].items()},
                        window=m["window"], threshold_rule=m["threshold_rule"])
        top = []
        p = "datasets/processed/flaws_top_alerts_for_review.csv"
        if os.path.exists(p):
            top = list(csv.DictReader(open(p, encoding="utf-8")))[:10]
        return jsonify(results=res, card=card, multi=read("docs/multi_seed_results.md"), top=top)

    @app.get("/api/datasets")
    def datasets():
        return jsonify([dict(name=os.path.basename(f), text=read(f)) for f in sorted(glob.glob("datasets/metadata/*.md"))])
