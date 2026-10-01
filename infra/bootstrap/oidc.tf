# ==============================================================================
# GitHub Actions OIDC Identity Provider
# ==============================================================================
# Allows GitHub Actions workflows to assume IAM roles using short-lived JWT tokens
# without storing long-lived AWS access keys in GitHub Secrets.

resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
  thumbprint_list = [
    "6938fd4d98bab03faadb97b34396831e3780aea1",
    "1c58a3a8518e8759bf075b76b750d4f2df264fcd"
  ]
}

# ==============================================================================
# GitHub Actions Plan Role ("${var.project}-gha-plan")
# ==============================================================================
# Assumed exclusively by GitHub Actions on pull_request events.
# Trust policy enforces aud == sts.amazonaws.com AND sub matches pull_request.

resource "aws_iam_role" "gha_plan" {
  name = "${var.project}-gha-plan"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "GitHubActionsPlanAssumeRole"
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.github.arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
            "token.actions.githubusercontent.com:sub" = [
              "repo:${var.github_repo}:pull_request",
              "repo:devaswani18@182419818/VaultRag@1398306952:pull_request"
            ]
          }
        }
      }
    ]
  })
}

# Attach AWS-managed ReadOnlyAccess to allow Terraform plan to read infrastructure state
resource "aws_iam_role_policy_attachment" "gha_plan_readonly" {
  role       = aws_iam_role.gha_plan.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# Allow read/write access to state bucket objects for state read and native S3 plan lock handling (.tflock files)
resource "aws_iam_role_policy" "gha_plan_state_lock" {
  name = "${var.project}-gha-plan-state-lock"
  role = aws_iam_role.gha_plan.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "StateBucketBucketAccess"
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetBucketLocation"
        ]
        Resource = aws_s3_bucket.state.arn
      },
      {
        Sid    = "StateBucketObjectReadWriteForLocking"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = "${aws_s3_bucket.state.arn}/*"
      }
    ]
  })
}

# ==============================================================================
# GitHub Actions Apply Role ("${var.project}-gha-apply")
# ==============================================================================
# Assumed on pushes to main or within the GitHub "environment:dev" deployment.
# Scoped strictly to project-prefixed resources across supported AWS services.

resource "aws_iam_role" "gha_apply" {
  name = "${var.project}-gha-apply"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "GitHubActionsApplyAssumeRole"
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.github.arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
            "token.actions.githubusercontent.com:sub" = [
              "repo:${var.github_repo}:ref:refs/heads/main",
              "repo:${var.github_repo}:environment:dev",
              "repo:devaswani18@182419818/VaultRag@1398306952:ref:refs/heads/main",
              "repo:devaswani18@182419818/VaultRag@1398306952:environment:dev"
            ]
          }
        }
      }
    ]
  })
}

resource "aws_iam_policy" "gha_apply_policy" {
  name        = "${var.project}-gha-apply-policy"
  description = "Scoped permissions policy for VaultRAG deployment via GitHub Actions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Statement 1: S3 Bucket & Object management scoped to project-named buckets (including state bucket)
      {
        Sid    = "S3ScopedManagement"
        Effect = "Allow"
        Action = [
          "s3:*"
        ]
        Resource = [
          "arn:aws:s3:::${var.project}-*",
          "arn:aws:s3:::${var.project}-*/*"
        ]
      },
      # Statement 2: DynamoDB table and index management scoped to project prefix
      {
        Sid    = "DynamoDBScopedManagement"
        Effect = "Allow"
        Action = [
          "dynamodb:*"
        ]
        Resource = [
          "arn:aws:dynamodb:${var.aws_region}:${data.aws_caller_identity.current.account_id}:table/${var.project}-*",
          "arn:aws:dynamodb:${var.aws_region}:${data.aws_caller_identity.current.account_id}:table/${var.project}-*/*"
        ]
      },
      # Statement 3: Lambda function, layer, and event source management scoped to project prefix
      {
        Sid    = "LambdaScopedManagement"
        Effect = "Allow"
        Action = [
          "lambda:*"
        ]
        Resource = [
          "arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:${var.project}-*",
          "arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:layer:${var.project}-*:*"
        ]
      },
      # Statement 4: CloudWatch Logs group and stream management scoped to Lambda project prefix
      {
        Sid    = "LogsScopedManagement"
        Effect = "Allow"
        Action = [
          "logs:*"
        ]
        Resource = [
          "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.project}-*:*",
          "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.project}-*"
        ]
      },
      # Statement 5: SSM Parameter Store read/write scoped strictly to project hierarchy
      {
        Sid    = "SSMScopedManagement"
        Effect = "Allow"
        Action = [
          "ssm:*"
        ]
        Resource = [
          "arn:aws:ssm:${var.aws_region}:${data.aws_caller_identity.current.account_id}:parameter/${var.project}/*"
        ]
      },
      # Statement 6: IAM role and policy creation/attachment strictly scoped to project name prefix
      {
        Sid    = "IAMScopedRoleManagement"
        Effect = "Allow"
        Action = [
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:GetRole",
          "iam:UpdateRole",
          "iam:TagRole",
          "iam:UntagRole",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "iam:PutRolePolicy",
          "iam:GetRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:AttachRolePolicy",
          "iam:DetachRolePolicy",
          "iam:CreatePolicy",
          "iam:DeletePolicy",
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:ListPolicyVersions"
        ]
        Resource = [
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.project}-*",
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/${var.project}-*"
        ]
      },
      # Statement 7: Restrict iam:PassRole exclusively to project-scoped roles (e.g. for Lambda execution)
      {
        Sid    = "IAMScopedPassRole"
        Effect = "Allow"
        Action = [
          "iam:PassRole"
        ]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.project}-*"
      },
      # Statement 8: EventBridge rules and targets scoped to project prefix
      {
        Sid    = "EventBridgeScopedManagement"
        Effect = "Allow"
        Action = [
          "events:*"
        ]
        Resource = "arn:aws:events:${var.aws_region}:${data.aws_caller_identity.current.account_id}:rule/${var.project}-*"
      },
      # Statement 9: CloudFront distribution and cache invalidation management
      {
        Sid    = "CloudFrontManagement"
        Effect = "Allow"
        Action = [
          "cloudfront:CreateDistribution",
          "cloudfront:UpdateDistribution",
          "cloudfront:DeleteDistribution",
          "cloudfront:GetDistribution",
          "cloudfront:GetDistributionConfig",
          "cloudfront:TagResource",
          "cloudfront:UntagResource",
          "cloudfront:CreateInvalidation",
          "cloudfront:GetInvalidation"
        ]
        Resource = "*"
      },
      # Statement 10: Amazon Cognito Identity Provider management
      # Note: AWS Cognito User Pools use generated IDs (e.g., ap-south-1_xxxxxxxxx) rather than
      # user-defined names in their ARNs. AWS IAM does not support resource name-prefix wildcard
      # scoping on Cognito User Pool IDs; hence this permission is scoped to the AWS account userpools.
      {
        Sid    = "CognitoIDPAccountScopedManagement"
        Effect = "Allow"
        Action = [
          "cognito-idp:*"
        ]
        Resource = "arn:aws:cognito-idp:${var.aws_region}:${data.aws_caller_identity.current.account_id}:userpool/*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "gha_apply_attach" {
  role       = aws_iam_role.gha_apply.name
  policy_arn = aws_iam_policy.gha_apply_policy.arn
}
