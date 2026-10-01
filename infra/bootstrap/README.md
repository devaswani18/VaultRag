# VaultRAG Infrastructure Bootstrap

This module provisions the foundational cloud resources required for VaultRAG's CI/CD pipeline and remote Terraform state management.

> [!WARNING]
> **Local State Notice:** This bootstrap module is executed locally once by an administrator and maintains its state locally in `terraform.tfstate`. Do **not** commit `terraform.tfstate` or `terraform.tfstate.backup` to version control. Store a secure offline backup or migrate it to the created S3 bucket after provisioning.

---

## State Locking Strategy
Terraform **v1.15.8** (>= 1.10) is used in this project. It natively supports **S3 State Locking** using object-level `.tflock` files via `use_lockfile = true`. Consequently, no DynamoDB table is provisioned for state locks, saving unnecessary AWS resource overhead and guaranteeing zero cost.

---

## Provisioned Resources
1. **Encrypted S3 State Bucket:** `${project}-tfstate-<account_id>` with SSE-S3 (AES256), versioning, public access blocked, noncurrent version lifecycle expiry (90 days), and TLS-enforcing bucket policy.
2. **GitHub OIDC Provider:** `token.actions.githubusercontent.com` allowing GitHub Actions to authenticate via short-lived AWS STS tokens.
3. **Plan IAM Role:** `${project}-gha-plan` assumed only on GitHub pull request events with `ReadOnlyAccess` plus state bucket read/write permissions for lock creation.
4. **Apply IAM Role:** `${project}-gha-apply` assumed only on pushes to `main` or in the `dev` environment with strictly scoped permissions for project resources (`${project}-*`).
5. **Zero-Cost Budget:** Monthly $1 USD AWS budget alerting to `${alert_email}` at 80% actual spend and 100% forecasted spend.

---

## Deployment Instructions

### 1. Configure Variables
Create your local `terraform.tfvars` from the example:
```bash
cp terraform.tfvars.example terraform.tfvars
```
Update `alert_email` with your notification email and verify `aws_region` is set to `ap-south-1`.

### 2. Initialize and Plan
```bash
cd infra/bootstrap
terraform init
terraform plan
```

### 3. Apply Bootstrap Stack
```bash
terraform apply
```

### 4. Read Outputs
Inspect the generated outputs:
```bash
terraform output
```

### 5. Configure GitHub Actions Variables
Add the output values as **Repository Variables** (Settings > Secrets and variables > Actions > Variables) in your GitHub repository:
- `AWS_REGION` = value from `terraform output -raw region` (e.g. `ap-south-1`)
- `TF_STATE_BUCKET` = value from `terraform output -raw state_bucket`
- `AWS_ROLE_ARN_PLAN` = value from `terraform output -raw plan_role_arn`
- `AWS_ROLE_ARN_APPLY` = value from `terraform output -raw apply_role_arn`
