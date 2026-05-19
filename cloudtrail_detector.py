from __future__ import annotations

import argparse
from dataclasses import asdict

from src.aws_iam_detections import detect_aws_iam_risks
from src.cloudtrail_parser import load_cloudtrail
from src.rule_loader import evaluate_yaml_rules, load_yaml_rules


def main() -> None:
    parser = argparse.ArgumentParser(description="Detect risky AWS IAM CloudTrail control-plane events.")
    parser.add_argument("--file", required=True, help="Path to CloudTrail JSON file. Supports Records[], list, or single-record JSON.")
    parser.add_argument("--engine", choices=["python", "yaml"], default="python", help="Detection engine to use. The Python engine is richer; the YAML engine demonstrates detection-as-code rules.")
    parser.add_argument("--rules", default="rules/cloudtrail_iam_rules.yaml", help="YAML rule file used when --engine yaml is selected.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON findings.")
    args = parser.parse_args()

    events = load_cloudtrail(args.file)
    if args.engine == "yaml":
        findings = evaluate_yaml_rules(events, load_yaml_rules(args.rules))
    else:
        findings = detect_aws_iam_risks(events)

    if args.json:
        import json

        print(json.dumps([asdict(finding) for finding in findings], indent=2))
        return

    print(f"IdentityRiskGraph CloudTrail IAM Detector")
    print(f"File: {args.file}")
    print(f"Engine: {args.engine}")
    print(f"Events parsed: {len(events)}")
    print(f"Alerts: {len(findings)}")
    print("=" * 72)
    if not findings:
        print("No risky IAM control-plane alerts detected.")
        return

    for finding in findings:
        print(f"[{finding.severity.upper()}] {finding.detection_name}")
        print(f"Event: {finding.event_name}")
        print(f"User: {finding.target_identity}")
        print(f"Actor: {finding.actor}")
        print(f"Source IP: {finding.source_ip}")
        if finding.evidence.get("policyArn"):
            print(f"Policy: {finding.evidence['policyArn'].split('/')[-1]}")
        print(f"Reason: {finding.reason}")
        print(f"MITRE: {finding.mitre_technique}")
        print(f"Recommended action: {finding.recommended_action}")
        print("-" * 72)


if __name__ == "__main__":
    main()
