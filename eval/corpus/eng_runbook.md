# Evalco Engineering Production Incident Runbook

## 1. Severity Classifications
- **P1 (Critical Outage)**: Customer-facing degradation impacting > 5% of traffic. Incident commander must be assigned within 15 minutes.
- **P2 (Major)**: Non-critical feature disruption with viable workaround. Target response time is 45 minutes.
- **P3 (Minor)**: Internal tooling bug. Target response within 24 hours.

## 2. P1 Escalation Protocol
1. Open an incident bridge in Slack channel `#incident-prod`.
2. Page the on-call engineer using PagerDuty primary rotation.
3. Post initial status page update within 20 minutes of incident declaration.
4. Execute rollbacks using command `kubectl rollout undo deployment/api-server`.

## 3. Post-Incident Review
A blameless postmortem document must be drafted within 48 hours and reviewed in the weekly engineering operations meeting.
