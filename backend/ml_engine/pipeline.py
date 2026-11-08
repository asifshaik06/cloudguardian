"""Load CloudTrail events, build five-minute windows per principal, extract behavioural features."""
import gzip, json, math
from collections import Counter
import numpy as np
import pandas as pd

FEATURES = ["call_count", "call_velocity", "error_ratio", "unique_services", "unique_events",
            "enumeration_ratio", "sensitive_count", "iam_change_count", "first_service_ratio",
            "first_ip", "off_hours", "event_entropy"]
SENSITIVE = {"CreateAccessKey", "CreateUser", "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy",
             "PutRolePolicy", "CreateLoginProfile", "UpdateAssumeRolePolicy", "StopLogging", "DeleteTrail",
             "UpdateTrail", "PutBucketPolicy", "DeleteBucketPublicAccessBlock", "PutBucketAcl",
             "AuthorizeSecurityGroupIngress", "DisableKey", "ScheduleKeyDeletion", "DeleteFlowLogs",
             "GetSecretValue", "GetPasswordData"}
READ = ("List", "Describe", "Get")
COLS = ["time", "principal", "event", "service", "ip", "error", "source", "label"]


def read_records(path):
    """Read one CloudTrail file: .json or .json.gz, a {"Records": [...]} object, a list, or JSON lines."""
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as f:
        text = f.read().strip()
    if not text:
        return []
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        out = []
        for line in text.splitlines():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return out
    if isinstance(obj, dict):
        return obj.get("Records", [obj] if "eventName" in obj else [])
    return obj if isinstance(obj, list) else []


def _principal(r):
    u = r.get("userIdentity") or {}
    return u.get("arn") or u.get("userName") or u.get("principalId") or u.get("accessKeyId") or u.get("type") or "unknown"


def to_frame(records, source, label):
    """label: 0 benign, 1 attack, -1 unknown."""
    rows = []
    for r in records:
        if not isinstance(r, dict):
            continue
        if "eventName" not in r and isinstance(r.get("event"), dict):
            r = r["event"]
        if not r.get("eventTime") or not r.get("eventName"):
            continue
        rows.append((r["eventTime"], _principal(r), r["eventName"], (r.get("eventSource") or "").split(".")[0],
                     r.get("sourceIPAddress"), 1 if r.get("errorCode") else 0, source, label))
    df = pd.DataFrame(rows, columns=COLS)
    df["time"] = pd.to_datetime(df["time"], utc=True, errors="coerce")
    return df.dropna(subset=["time"]).sort_values("time").reset_index(drop=True)


def windows(df):
    """One row per (principal, 5-minute window). History features use only EARLIER windows (no leakage).
    Cold start: until a principal has 3 earlier windows, history features stay neutral instead of alerting."""
    if df.empty:
        return pd.DataFrame(columns=["principal", "win", "source", "label"] + FEATURES)
    df = df.assign(win=df["time"].dt.floor("5min"))
    ev, svc, ip = df["event"].to_numpy(), df["service"].to_numpy(), df["ip"].to_numpy()
    err, lab, src = df["error"].to_numpy(), df["label"].to_numpy(), df["source"].to_numpy()
    groups = df.groupby(["principal", "win"]).indices
    hist, out = {}, []
    for (p, w) in sorted(groups):
        idx = groups[(p, w)]
        h = hist.setdefault(p, dict(svc=set(), ips=set(), hours=Counter(), counts=[]))
        names, n = ev[idx], len(idx)
        cnt = Counter(names)
        services = set(svc[idx])
        ips = {x for x in ip[idx] if x is not None and x == x}
        warm = len(h["counts"]) >= 3
        prev = float(np.mean(h["counts"])) if h["counts"] else float(n)
        out.append(dict(
            principal=p, win=w, source=src[idx[0]], label=int(lab[idx].max()),
            call_count=n, call_velocity=(n / (prev + 1.0)) if warm else 1.0,
            error_ratio=float(err[idx].mean()), unique_services=len(services), unique_events=len(cnt),
            enumeration_ratio=sum(1 for x in names if x.startswith(READ)) / n,
            sensitive_count=sum(1 for x in names if x in SENSITIVE),
            iam_change_count=sum(1 for x, s in zip(names, svc[idx]) if s == "iam" and not x.startswith(READ)),
            first_service_ratio=(len(services - h["svc"]) / max(len(services), 1)) if warm else 0.0,
            first_ip=float(bool(ips - h["ips"])) if warm else 0.0,
            off_hours=float(h["hours"][w.hour] == 0) if warm else 0.0,
            event_entropy=-sum(c / n * math.log2(c / n) for c in cnt.values())))
        h["svc"] |= services; h["ips"] |= ips; h["hours"][w.hour] += 1; h["counts"].append(n)
    return pd.DataFrame(out)


# ---- Generated data (same schema, so the controlled benchmark has exact labels) ----
START = pd.Timestamp("2026-01-05", tz="UTC")  # a Monday
EVENTS = {"s3": ["GetObject", "PutObject", "ListBuckets", "ListObjects"],
          "ec2": ["DescribeInstances", "RunInstances", "DescribeSecurityGroups"],
          "iam": ["GetUser", "ListAccessKeys"], "cloudwatch": ["GetMetricData", "DescribeAlarms"],
          "lambda": ["ListFunctions", "InvokeFunction"]}


def gen_benign(days=21, users=25, seed=0):
    rng = np.random.default_rng(seed)
    rows = []
    for u in range(users):
        name, ip = f"user-{u:03d}", f"10.0.{u % 8}.{u + 10}"
        mine = list(rng.choice(list(EVENTS), size=int(rng.integers(2, 4)), replace=False))
        for d in range(days):
            day = START + pd.Timedelta(days=d)
            if day.weekday() >= 5:
                continue
            for _ in range(int(rng.integers(3, 9))):
                t0 = day + pd.Timedelta(hours=int(rng.integers(8, 18)), minutes=int(rng.integers(0, 60)))
                for _ in range(int(rng.integers(1, 12))):
                    s = mine[int(rng.integers(len(mine)))]
                    e = EVENTS[s][int(rng.integers(len(EVENTS[s])))]
                    rows.append((t0 + pd.Timedelta(seconds=int(rng.integers(0, 280))), name, e, s, ip,
                                 int(rng.random() < 0.03), "generated", 0))
    return pd.DataFrame(rows, columns=COLS)


def gen_attacks(seed=1, days=21):
    """Four scenarios injected in the test period (after day 14) for existing users, from a new IP, at night."""
    rng = np.random.default_rng(seed)
    rows = []
    for i in range(16):
        user = f"user-{int(rng.integers(0, 25)):03d}"
        t0 = START + pd.Timedelta(days=int(rng.integers(14, days)), hours=3, minutes=int(rng.integers(0, 50)))
        ip, kind = f"203.0.113.{i + 1}", ["recon", "exfil", "privesc", "evasion"][i % 4]
        if kind == "recon":
            ev = [(EVENTS[s][int(rng.integers(len(EVENTS[s])))] if s != "x" else "x", s)
                  for s in list(EVENTS) * 30]
            ev = [(("List" + e[4:]) if e.startswith("Describe") else e, s) for e, s in ev]
            errp = 0.4
        elif kind == "exfil":
            ev, errp = [("GetObject", "s3")] * 200, 0.02
        elif kind == "privesc":
            ev = [("CreateUser", "iam"), ("AttachUserPolicy", "iam"), ("CreateAccessKey", "iam"),
                  ("PutUserPolicy", "iam"), ("ListUsers", "iam")] * 4
            errp = 0.1
        else:
            ev = [("StopLogging", "cloudtrail"), ("DeleteTrail", "cloudtrail"), ("DeleteFlowLogs", "ec2"),
                  ("PutBucketPolicy", "s3"), ("DescribeTrails", "cloudtrail")] * 3
            errp = 0.1
        for e, s in ev:
            rows.append((t0 + pd.Timedelta(seconds=int(rng.integers(0, 280))), user, e, s, ip,
                         int(rng.random() < errp), "synthetic_attack", 1))
    return pd.DataFrame(rows, columns=COLS)
