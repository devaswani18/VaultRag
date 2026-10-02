# VaultRAG Infrastructure Teardown & Cost Management Guide

This document outlines the exact, step-by-step procedure to completely decommission and destroy all VaultRAG AWS cloud resources, followed by an operational cost checklist.

---

## Part 1: Destruction Sequence

Because AWS S3 enforces that non-empty buckets cannot be deleted by Terraform, and because the `dev` environment depends on IAM roles and state storage provisioned by `bootstrap`, resources must be torn down in the exact sequence below.

### Step 1: Empty All S3 Buckets

Retrieve the bucket names or use the project prefix to purge all stored objects, presigned uploads, lambda build artifacts, and static site assets:

```bash
# Set your AWS region and account ID
export AWS_REGION="ap-south-1"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# 1. Empty Documents Bucket
DOCS_BUCKET="vaultrag-docs-${ACCOUNT_ID}-${AWS_REGION}"
echo "Emptying ${DOCS_BUCKET}..."
aws s3 rm "s3://${DOCS_BUCKET}" --recursive

# 2. Empty Artifacts Bucket (Lambda deployment packages)
ARTIFACTS_BUCKET="vaultrag-artifacts-${ACCOUNT_ID}-${AWS_REGION}"
echo "Emptying ${ARTIFACTS_BUCKET}..."
aws s3 rm "s3://${ARTIFACTS_BUCKET}" --recursive

# 3. Empty Web Static Site Bucket
WEB_BUCKET="vaultrag-web-${ACCOUNT_ID}-${AWS_REGION}"
echo "Emptying ${WEB_BUCKET}..."
aws s3 rm "s3://${WEB_BUCKET}" --recursive
```

### Step 2: Destroy Dev Environment Infrastructure (`infra/envs/dev`)

Run `terraform destroy` within the dev environment module. This removes CloudFront distributions, Lambda functions, Function URLs, DynamoDB tables, Cognito user pools, and dev S3 buckets:

```bash
cd infra/envs/dev

# Initialize backend if not already active
terraform init

# Review and execute destruction plan
terraform destroy -auto-approve \
  -var="lambda_zip_path=../../../backend/dist/lambda.zip"
```

> **Note on CloudFront**: CloudFront distribution teardown involves disabling the distribution before deletion, which may take 3–5 minutes. Terraform automatically handles this lifecycle.

### Step 3: Empty Terraform State Bucket

Before destroying the bootstrap module, empty the remote state bucket:

```bash
STATE_BUCKET="vaultrag-tfstate-${ACCOUNT_ID}-${AWS_REGION}"
echo "Emptying ${STATE_BUCKET}..."
aws s3 rm "s3://${STATE_BUCKET}" --recursive
```

### Step 4: Destroy Bootstrap Infrastructure (`infra/bootstrap`)

Run `terraform destroy` in the bootstrap module to remove GitHub Actions OIDC roles, IAM policies, and the AWS Budget:

```bash
cd ../../bootstrap

terraform destroy -auto-approve
```

---

## Part 2: Cost Control & Free-Tier Checklist

VaultRAG was engineered from the ground up for a **zero-cost idle base**. Verify that your deployment satisfies every item on this checklist:

### 1. Zero Fixed-Cost Architecture
- [x] **No NAT Gateways**: Lambdas communicate directly with AWS public endpoints (S3, DynamoDB, Cognito) and external APIs (Gemini, Qdrant Cloud) over TLS. Saves **$32.40/month** per AZ.
- [x] **No Application/Network Load Balancers**: Replaced entirely by Lambda Function URLs with native HTTPS and CORS. Saves **$16.20/month** base fee.
- [x] **No Relational Databases (RDS/Aurora)**: Vector indexing is hosted on Qdrant Cloud Free Tier and metadata/state is on DynamoDB on-demand. Saves **$15–$50+/month**.
- [x] **No AWS WAF**: CloudFront relies on Response Headers Policy (HSTS, strict CSP) and application-layer rate limits/quotas rather than paid WAF WebACLs ($5/month + $1/rule).

### 2. Storage & Compute Capping
- [x] **DynamoDB Billing Mode**: All 5 tables (`tenants`, `documents`, `audit`, `usage`, `gaps`) configured as `PAY_PER_REQUEST` (on-demand). Zero idle cost, covered by the 25 GB free tier.
- [x] **CloudWatch Logs Retention**: All Lambda log groups (`/aws/lambda/vaultrag-dev-api`, `/aws/lambda/vaultrag-dev-ingest`) have `retention_in_days = 7` to prevent log accumulation beyond the 5 GB free tier.
- [x] **S3 Storage Lifecycle**: Artifacts bucket expires zip files after 30 days; documents bucket purges `tmp/` staging uploads after 1 day.
- [x] **Cognito User Pool**: Standard pool without Advanced Security features; covered by the 50,000 monthly active users (MAU) free tier.
- [x] **Lambda Architecture**: Runs on ARM64 (`arm64`), delivering 20% lower cost per compute-second and higher power efficiency within the 400,000 GB-seconds monthly free tier.

### 3. Monitoring & Guardrails
- [x] **AWS Budgets Alert**: Configured in `infra/bootstrap/budget.tf` to alert email immediately if monthly forecast or actual charges exceed $1.00.
- [x] **AWS Cost Explorer**: Activate AWS Cost Explorer and Cost Allocation Tags (`Project=VaultRAG`, `Env=dev`) in the AWS Billing Console to review daily spend breakdowns.
- [x] **CloudWatch Insights**: Use queries in `docs/runbook.md` to monitor query volumes, latency, and error trends without deploying third-party APM agents.
