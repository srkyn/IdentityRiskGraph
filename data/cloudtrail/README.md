# CloudTrail Sample Data

This folder contains simulated AWS CloudTrail-style IAM control-plane logs. The events are defensive training data only and do not contain real account IDs, credentials, tenants, or API keys.

Files:

- `sample_cloudtrail_iam_events.json`: mixed benign and suspicious IAM events.
- `suspicious_cloudtrail_events.json`: short suspicious sequence for terminal demos.

Included event names:

- `AttachUserPolicy`
- `AttachGroupPolicy`
- `PutUserPolicy`
- `PutGroupPolicy`
- `AddUserToGroup`
- `CreateAccessKey`
- `UpdateAssumeRolePolicy`
- `CreatePolicyVersion`
- `SetDefaultPolicyVersion`
- `CreateLoginProfile`
- `ConsoleLogin`
- `DeleteTrail`
- `StopLogging`
- `AssumeRole`
- `GetCallerIdentity`
- `ListAttachedUserPolicies`
- `ListGroupsForUser`

