# ==============================================================================
# AWS Zero-Cost Budget & Alerting
# ==============================================================================
# Ensures the project never exceeds $1/month by issuing immediate email alerts
# at 80% actual cost and 100% forecasted cost.

resource "aws_budgets_budget" "monthly_cost" {
  name              = "${var.project}-monthly-budget"
  budget_type       = "COST"
  limit_amount      = "1"
  limit_unit        = "USD"
  time_unit         = "MONTHLY"
  time_period_start = "2026-01-01_00:00"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.alert_email]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.alert_email]
  }
}
