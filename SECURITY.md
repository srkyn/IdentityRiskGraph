# Security Policy

IdentityRiskGraph is a defensive portfolio project that uses simulated identity data, sample CloudTrail-style events, and optional public GitHub repository metadata.

## Reporting

If you notice a safety issue in the public content, open a GitHub issue with:

- the affected file or feature
- a short description of the concern
- sanitized reproduction details, if relevant

Do not include real credentials, tokens, private logs, customer data, tenant IDs, AWS account IDs, internal hostnames, private IP addresses, or screenshots from live environments.

## Scope

In scope:

- accidental sensitive data exposure in committed samples
- misleading detection or risk-scoring wording
- unsafe public API usage patterns
- broken examples that could confuse defensive analysis

Out of scope:

- requests to analyze private logs publicly
- offensive expansion beyond defensive detection context
- environment-specific allowlists or proprietary detections

## Safe Usage

The GitHub API adapter reads public repository metadata and prints local review notes. It does not store responses, write to GitHub, inspect private code, or treat metadata as a security verdict.

All included IAM, device, event, and CloudTrail data is simulated and should not be treated as production evidence.
