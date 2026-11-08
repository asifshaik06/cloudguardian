import os, re, time, threading
from collections import deque
import boto3, numpy as np, requests
from flask import Flask, jsonify, send_from_directory
from sklearn.ensemble import IsolationForest
from dotenv import load_dotenv
load_dotenv()

LIVE = os.getenv("CG_LIVE_AWS") == "1"
BUCKET = os.getenv("CG_BUCKET") or "student-records-demo"
TRAIL, USER, ID = "main-trail", "intern-dev", {}

def cli(s):
    kw = {} if LIVE else dict(endpoint_url=os.getenv("AWS_ENDPOINT_URL", "http://127.0.0.1:5000"),
                              aws_access_key_id="test", aws_secret_access_key="test")
    return boto3.client(s, region_name="us-east-1", **kw)
s3, ct, ec2, iam, sts = cli("s3"), cli("cloudtrail"), cli("ec2"), cli("iam"), cli("sts")
MODE = "Live AWS" if LIVE else "Simulator"
POLLS, ACCT = {"n": 0, "ms": 0}, "connecting"
def acct():
    try:
        a = sts.get_caller_identity()["Account"]
        return a[:4] + "****" + a[-4:] if LIVE else a
    except Exception: return "unknown"

BLOCK = dict(BlockPublicAcls=True, IgnorePublicAcls=True, BlockPublicPolicy=True, RestrictPublicBuckets=True)
PERM = lambda cidr: [dict(IpProtocol="tcp", FromPort=22, ToPort=22, IpRanges=[{"CidrIp": cidr}])]
EVENTS, AUDIT, F, T0 = deque(maxlen=15), deque(maxlen=30), {}, {}
ANOM = {"on": False}

def now(): return time.strftime("%H:%M:%S")
MASK = os.getenv("CG_MASK_IDS", "1") == "1"
def redact(t):
    if not MASK: return t
    t = re.sub(r"\b\d{12}\b", "************", t)
    t = re.sub(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b", "AKIA****************", t)
    return re.sub(r"\b\d{6,10}:[A-Za-z0-9_-]{30,}\b", "<telegram-token>", t)
def audit(t): AUDIT.appendleft(f"[{now()}] {redact(str(t))}")
def emit(name, src, user, country="IN"):
    EVENTS.appendleft(dict(t=now(), name=name, src=src, user=user, country=country, mode=MODE))

def setup():
    s3.create_bucket(Bucket=BUCKET); s3.create_bucket(Bucket=BUCKET + "-trail")
    s3.put_public_access_block(Bucket=BUCKET, PublicAccessBlockConfiguration=BLOCK)
    ct.create_trail(Name=TRAIL, S3BucketName=BUCKET + "-trail"); ct.start_logging(Name=TRAIL)
    ID["sg"] = ec2.create_security_group(GroupName="web-sg", Description="web")["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=ID["sg"], IpPermissions=PERM("10.0.0.0/8"))
    iam.create_user(UserName=USER)
    ID["key"] = iam.create_access_key(UserName=USER)["AccessKey"]["AccessKeyId"]

def c_s3():
    try: return all(s3.get_public_access_block(Bucket=BUCKET)["PublicAccessBlockConfiguration"].values())
    except Exception: return False
def c_ct(): return ct.get_trail_status(Name=TRAIL)["IsLogging"]
def c_sg():
    g = ec2.describe_security_groups(GroupIds=[ID["sg"]])["SecurityGroups"][0]
    return not any(r["CidrIp"] == "0.0.0.0/0" for p in g["IpPermissions"] for r in p["IpRanges"])
def c_key(): return not ANOM["on"]

def a_s3(): s3.delete_public_access_block(Bucket=BUCKET); emit("DeleteBucketPublicAccessBlock", "s3", "dev-admin")
def a_ct(): ct.stop_logging(Name=TRAIL); emit("StopLogging", "cloudtrail", "dev-admin")
def a_sg():
    ec2.authorize_security_group_ingress(GroupId=ID["sg"], IpPermissions=PERM("0.0.0.0/0"))
    emit("AuthorizeSecurityGroupIngress", "ec2", "dev-admin")
def a_key():
    emit("ListBuckets x90", "s3", USER, "RU"); ml_check(3, "RU", 90)

def f_s3(): s3.put_public_access_block(Bucket=BUCKET, PublicAccessBlockConfiguration=BLOCK)
def f_ct(): ct.start_logging(Name=TRAIL)
def f_sg(): ec2.revoke_security_group_ingress(GroupId=ID["sg"], IpPermissions=PERM("0.0.0.0/0"))
def f_key():
    iam.update_access_key(UserName=USER, AccessKeyId=ID["key"], Status="Inactive"); ANOM["on"] = False

R = {
 "s3": dict(res="Customer data storage", desc="A storage bucket holding student records.", good="Private and locked", bad="Open to the public internet",
   title="Storage bucket opened to the public", sev="High", ref="CIS 2.1.4 / MITRE T1530", check=c_s3, fix=f_s3, attack=a_s3,
   how="Removes the bucket's public-access lock.", what="The lock that keeps this bucket private was removed.",
   why="Anyone on the internet could read the student records. Bots find open buckets within minutes.", fixtxt="Turn the public-access lock back on"),
 "ct": dict(res="Activity log", desc="The record of everything done in the account.", good="Recording", bad="Switched off",
   title="Activity logging was switched off", sev="Critical", ref="CIS 3.1 / MITRE T1562.008", check=c_ct, fix=f_ct, attack=a_ct,
   how="Stops the audit log, as an intruder would to hide.", what="Someone turned off the account's activity recording.",
   why="Without a log nobody can tell what happens next. Attackers do this first to hide their tracks.", fixtxt="Start recording again"),
 "sg": dict(res="Network door (SSH)", desc="The remote-login door to the servers.", good="Open to the office network only", bad="Open to the whole world",
   title="Remote-login door opened to everyone", sev="High", ref="CIS 5.2 / MITRE T1133", check=c_sg, fix=f_sg, attack=a_sg,
   how="Allows remote login from any address.", what="The server login door now accepts connections from anywhere.",
   why="Attackers scan the internet constantly for open login doors and try stolen passwords.", fixtxt="Close the door to outside addresses"),
 "key": dict(res="Employee access key", desc="A password-like key used by the intern's tools.", good="Normal use", bad="Used from abroad at 3 AM",
   title="Access key behaving strangely", sev="High", ref="ML anomaly / MITRE T1078.004", check=c_key, fix=f_key, attack=a_key,
   how="Replays a login pattern the key has never shown.", what="A key was used at an odd hour, from a new country, with 90 requests a minute.",
   why="This usually means the key was stolen. A thief can read data or run costly servers.", fixtxt="Disable the key until the owner confirms"),
}

CTRY, FEAT = {"IN": 0, "US": 1, "RU": 2, "CN": 3}, ["Hour of day", "Country", "Requests per minute"]
rng = np.random.default_rng(1)
BASE = np.c_[rng.integers(8, 19, 400), rng.choice([0, 0, 0, 1], 400), rng.integers(1, 12, 400)]
MODEL = IsolationForest(contamination=0.01, random_state=1).fit(BASE)
MU, SD = BASE.mean(0), BASE.std(0) + 1e-6

def ml_check(hour, country, calls):
    x = np.array([[hour, CTRY[country], calls]])
    if MODEL.predict(x)[0] == -1:
        z = np.abs((x[0] - MU) / SD); sh = z / z.sum()
        val = [f"{hour}:00", country, f"{calls}"]
        ANOM["on"] = True
        raise_finding("key", [[f"{FEAT[i]}: {val[i]}", float(sh[i])] for i in np.argsort(-sh)])

TG, CHAT = os.getenv("TG_TOKEN"), os.getenv("TG_CHAT_ID")
def tg_alert(k):
    if not TG: return
    kb = {"inline_keyboard": [[{"text": "Approve fix", "callback_data": "ok:" + k}, {"text": "Reject", "callback_data": "no:" + k}]]}
    requests.post(f"https://api.telegram.org/bot{TG}/sendMessage", timeout=10, json={"chat_id": CHAT,
        "text": f"CloudGuardian: {R[k]['title']} ({R[k]['sev']})\nProposed fix: {R[k]['fixtxt']}", "reply_markup": kb})
def tg_poll():
    off = 0
    while True:
        try:
            for u in requests.get(f"https://api.telegram.org/bot{TG}/getUpdates", params={"offset": off, "timeout": 20}, timeout=30).json().get("result", []):
                off = u["update_id"] + 1
                if "callback_query" in u:
                    a, k = u["callback_query"]["data"].split(":"); decide(k, a == "ok", "Telegram")
        except Exception: time.sleep(3)

def raise_finding(k, explain=None):
    F[k] = dict(status="pending", explain=explain or [[R[k]["ref"], 1.0]], tdetect=round(time.time() - T0.get(k, time.time()), 1))
    audit(f"DETECTED {R[k]['title']}"); tg_alert(k)

def decide(k, ok, via):
    f = F.get(k)
    if not f or f["status"] != "pending": return
    if not ok: f["status"] = "rejected"; audit(f"REJECTED {k} via {via}, accepted risk"); return
    audit(f"APPROVED {k} via {via}"); R[k]["fix"]()
    f["verified"] = bool(R[k]["check"]()); f["status"] = "fixed"
    audit(f"FIXED {k}, verified by re-checking the cloud: {f['verified']}")

def scan():
    while True:
        t = time.time(); POLLS["n"] += 1
        for k in ("s3", "ct", "sg"):
            try:
                if not R[k]["check"]() and (k not in F or F[k]["status"] == "fixed"): raise_finding(k)
            except Exception as e: audit(f"scan error {k}: {e}")
        POLLS["ms"] = round((time.time() - t) * 1000 / 3)
        time.sleep(2)

def evidence():
    out = {}
    try: out["s3.get_public_access_block"] = s3.get_public_access_block(Bucket=BUCKET)["PublicAccessBlockConfiguration"]
    except Exception as e: out["s3.get_public_access_block"] = str(e)[:120]
    out["cloudtrail.get_trail_status"] = {"IsLogging": ct.get_trail_status(Name=TRAIL)["IsLogging"]}
    g = ec2.describe_security_groups(GroupIds=[ID["sg"]])["SecurityGroups"][0]
    out["ec2.describe_security_groups (ingress CIDRs)"] = [r["CidrIp"] for p in g["IpPermissions"] for r in p["IpRanges"]]
    return out

app = Flask(__name__, static_folder="static")
@app.get("/")
def home(): return send_from_directory("static", "index.html")
@app.get("/api/state")
def state():
    res = [dict(id=k, name=r["res"], desc=r["desc"], good=r["good"], badtxt=r["bad"], attack=r["how"], ok=bool(r["check"]())) for k, r in R.items()]
    fs = [dict(id=k, **{x: R[k][x] for x in ("title", "sev", "ref", "what", "why", "fixtxt")}, **f) for k, f in F.items()]
    return jsonify(resources=res, findings=fs, events=list(EVENTS), audit=list(AUDIT), score=round(100 * sum(r["ok"] for r in res) / len(res)),
                   mode=MODE, account=ACCT, region="us-east-1", polls=POLLS["n"], latency=POLLS["ms"], checked=now(), evidence=evidence(), video=os.getenv("CG_VIDEO_URL", ""))
@app.post("/api/attack/<k>")
def attack(k): T0[k] = time.time(); audit(f"SIMULATED ATTACK {k}"); R[k]["attack"](); return jsonify(ok=True)
@app.post("/api/decide/<k>/<d>")
def dec(k, d): decide(k, d == "ok", "dashboard"); return jsonify(ok=True)

if __name__ == "__main__":
    setup(); ACCT = acct(); threading.Thread(target=scan, daemon=True).start()
    if TG: threading.Thread(target=tg_poll, daemon=True).start()
    app.run(port=8000)

