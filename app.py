from flask import Flask, render_template

app = Flask(__name__)

# Sample data for now. Later, get_findings() will read from DynamoDB instead.
SAMPLE_FINDINGS = [
    {"id": "F-001", "rule": "s3-bucket-public-read-prohibited", "resource": "demo-bucket-01", "severity": "Critical", "score": 92, "status": "Auto-fixed"},
    {"id": "F-002", "rule": "restricted-ssh", "resource": "sg-0a12b34c", "severity": "High", "score": 78, "status": "Auto-fixed"},
    {"id": "F-003", "rule": "encrypted-volumes", "resource": "vol-0f91e22d", "severity": "Medium", "score": 55, "status": "Open"},
    {"id": "F-004", "rule": "restricted-ssh", "resource": "sg-0b77c10e", "severity": "High", "score": 74, "status": "Open"},
    {"id": "F-005", "rule": "encrypted-volumes", "resource": "vol-03a8d5f1", "severity": "Low", "score": 28, "status": "Auto-fixed"},
]


def get_findings():
    return SAMPLE_FINDINGS


@app.route('/')
def dashboard():
    findings = get_findings()
    total = len(findings)
    stats = {
        "total": total,
        "critical": sum(1 for f in findings if f["severity"] == "Critical"),
        "fixed": sum(1 for f in findings if f["status"] == "Auto-fixed"),
        "avg_score": round(sum(f["score"] for f in findings) / total) if total else 0,
    }
    return render_template('dashboard.html', findings=findings, stats=stats)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)