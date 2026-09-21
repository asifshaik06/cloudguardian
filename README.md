<div align="center">

# CloudGuardian

### AI-Driven Cloud Security & Compliance Platform

*A real-time, self-healing cloud security system built entirely on AWS Free Tier*

[![Python](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.1-black.svg)](https://flask.palletsprojects.com/)
[![AWS](https://img.shields.io/badge/AWS-Free%20Tier-orange.svg)](https://aws.amazon.com/free/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-In%20Development-brightgreen.svg)]()

</div>

---

## Table of Contents

- [Overview](#overview)
- [Problem Statement](#problem-statement)
- [Key Features](#key-features)
- [System Architecture](#system-architecture)
- [Tech Stack](#tech-stack)
- [Project Modules](#project-modules)
- [Getting Started](#getting-started)
- [Project Status](#project-status)
- [Future Scope](#future-scope)
- [Author](#author)
- [License](#license)

---

## Overview

**CloudGuardian** is a final year B.Tech capstone project that continuously monitors an AWS cloud account in real time, detects security misconfigurations and privilege-escalation risks using machine learning, automatically remediates critical issues, and generates plain-English incident reports — all visible on a live, publicly deployable dashboard.

The project is designed to run entirely within **AWS Free Tier**, making it a zero-cost, production-style demonstration of cloud security engineering combined with applied AI/ML.

---

## Problem Statement

Cloud misconfigurations — such as publicly exposed storage buckets, over-permissive IAM roles, and unencrypted resources — remain one of the leading causes of real-world data breaches. Most organizations detect these issues reactively, often after damage has occurred, and lack automated, intelligent systems to assess how dangerous a misconfiguration truly is before responding.

CloudGuardian addresses this gap by combining real-time detection, AI-based risk scoring, and automated remediation into a single, cohesive platform.

---

## Key Features

| Feature | Description |
|---|---|
| Real-Time Detection | Continuously scans AWS resources (S3, EC2, Security Groups) for misconfigurations the moment they occur |
| IAM Privilege Graph | Maps identity relationships to uncover hidden privilege-escalation paths using graph analysis |
| AI Risk Scoring | Machine learning models score findings by real-world exploitability and detect anomalous account behavior |
| Auto-Remediation | Automatically fixes critical issues (revokes public access, closes open ports) within seconds |
| Cost Anomaly Detection | Identifies unexpected AWS spending spikes and halts runaway resources automatically |
| AI-Generated Reporting | A locally-hosted NLP model translates technical findings into clear, human-readable incident reports |

---

## System Architecture

Full architecture diagram available at [`docs/architecture.md`](docs/architecture.md).

High-level flow:
   AWS Activity -> CloudTrail / Config / IAM / Cost Explorer APIs
-> EventBridge (real-time trigger)
-> Lambda (orchestration)
-> AI Models (risk scoring + anomaly detection)
-> Local NLP Model (plain-English explanation)
-> Step Functions (automated remediation)
-> Flask Dashboard (live visualization)

---

## Tech Stack

**Backend & Frontend**
Python, Flask, Jinja2, Gunicorn, Nginx

**Cloud & Infrastructure (AWS)**
AWS Config, CloudTrail, EventBridge, Lambda, Step Functions, DynamoDB, S3, IAM, Cost Explorer API, EC2

**AI / Machine Learning**
XGBoost (risk scoring), Isolation Forest (anomaly detection), NetworkX (privilege graph analysis), Hugging Face Transformers (local NLP summarization)

**Tools**
Git, GitHub, VS Code, boto3

---

## Project Modules

| # | Module | Purpose |
|---|---|---|
| 1 | Detection Engine | Real-time misconfiguration scanning via AWS Config and CloudTrail |
| 2 | IAM Privilege Graph | Privilege-escalation path detection using NetworkX |
| 3 | AI Risk Scoring and Anomaly Detection | XGBoost and Isolation Forest models |
| 4 | Auto-Remediation | Lambda and Step Functions automated response workflows |
| 5 | NLP Reporting and Dashboard | Local summarization model and Flask live dashboard |
| 6 | Cost Anomaly Detection | AWS Cost Explorer monitoring with auto-remediation |

---

## Getting Started

```bash
git clone https://github.com/asifshaik06/cloudguardian.git
cd cloudguardian

python -m venv cloudguardian-env
cloudguardian-env\Scripts\Activate.ps1

pip install -r requirements.txt

cp .env.example .env

python app.py
```

Requires an AWS account with appropriate IAM permissions. See [`docs/architecture.md`](docs/architecture.md) for full setup details.

---

## Project Status

In active development — built as part of a B.Tech final year project.

Detailed weekly progress is tracked in [`docs/build-log.md`](docs/build-log.md).

---

## Future Scope

- Multi-account and multi-region support
- Integration with AWS Security Hub for centralized findings
- Slack and Teams alerting integration
- Expanded compliance framework mapping (CIS AWS Foundations Benchmark)

---

## Author

**Shaik Asif Basha**
B.Tech CSE (AI & ML), Sri Venkateswara College of Engineering, JNTUA

[LinkedIn](https://linkedin.com/in/asif-shaik-241915289) | [GitHub](https://github.com/asifshaik06)

---

## License

This project is licensed under the [MIT License](LICENSE).