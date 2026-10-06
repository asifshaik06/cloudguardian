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


## Week 3 - EventBridge + Lambda Detection Pipeline
- Created DynamoDB table cloudguardian-findings (partition key: finding_id)
- Created Lambda function cloudguardian-detection-handler (Python 3.12)
- Attached AmazonDynamoDBFullAccess policy to Lambda's execution role
- Wrote Lambda handler to parse Config compliance events and write findings to DynamoDB
- Created EventBridge rule cloudguardian-config-trigger (event source: aws.config, detail-type: Config Rules Compliance Change)
- Connected rule to cloudguardian-detection-handler Lambda as target
- Rule confirmed Enabled on default event bus
- End-to-end test pending verification (Config recording set to Daily frequency, so results may take up to 24 hours to appear in CloudWatch Logs and DynamoDB)