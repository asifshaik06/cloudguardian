## Week 1 - Project Setup
- Created GitHub repo (cloudguardian, public, MIT license)
- Built full project folder structure (modules/, aws/, lambda_functions/, templates/, static/, docs/)
- Created and activated virtual environment (cloudguardian-env)
- Installed core packages: Flask, boto3, gunicorn, python-dotenv
- Configured .gitignore (.env, *.pem, __pycache__/, cloudguardian-env/, *.pyc)
- Generated requirements.txt
- Wrote basic app.py with home route, confirmed working locally at http://127.0.0.1:5000

## Week 2 - AWS Config Setup
- Enabled AWS Config in ap-south-2, recording specific resource types only (cost control)
- Resource types: AWS S3 Bucket, AWS EC2 Instance, AWS EC2 SecurityGroup - all set to Daily recording frequency
- Skipped IAM resource types (not available for per-type recording in this setup) - IAM analysis will be handled in Module 2 (IAM Privilege Graph) via direct boto3 calls instead
- Added 3 managed rules: s3-bucket-public-read-prohibited, encrypted-volumes, restricted-ssh
- Config delivery bucket: config-bucket-388371826759
- Setup confirmed, resource discovery in progress