# Demo Walkthrough

Use this flow when showing IdentityRiskGraph to a recruiter, hiring manager, IAM engineer, or SOC analyst.

## 1. Start With The Terminal Detector

```powershell
python cloudtrail_detector.py --file data/cloudtrail/sample_cloudtrail_iam_events.json
```

Point out that raw CloudTrail-style JSON becomes readable IAM alerts with severity, actor, target, source IP, MITRE mapping, evidence, and recommended action.

## 2. Open CloudTrail IAM Detections

In the Streamlit dashboard, open **CloudTrail IAM Detections**.

Show:

- event count
- risky IAM event count
- YAML rule count
- filters for severity, event name, actor, and target identity
- expanded finding details

Good findings to open:

- `AdministratorAccess Attached To User`
- `CloudTrail Logging Stopped`
- `AssumeRole Into Sensitive Role`

## 3. Pivot To Risky Identities

Open **Risky Identities** and explain that CloudTrail findings are folded into identity risk when the actor or target matches a simulated identity.

## 4. Investigate Caleb Stone

Open **User Investigation**. The default case is Caleb Stone because it demonstrates:

- contractor context
- sensitive permissions
- CloudTrail IAM findings
- risky access path
- data export behavior
- explainable risk factors

## 5. Show David User In The Graph

Use **Identity Graph** or the user selector to show David User as a nested-group inheritance scenario.

The important talking point: privileged access can be indirect. A user may not have a direct admin role, but nested group paths can create the same effective risk.

## 6. Close With Exports

Open **Export / Reports** and show:

- CSV findings export
- JSON findings export
- Splunk-friendly JSON export
- Markdown user investigation report

This ties the project back to SOC and detection engineering workflows: alerts, triage, evidence, and reporting.

