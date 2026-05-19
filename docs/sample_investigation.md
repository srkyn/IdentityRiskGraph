# Sample Investigation: Contractor AdministratorAccess

## Alert Summary

A CloudTrail `AttachUserPolicy` event grants `AdministratorAccess` to a contractor-style identity. The same activity chain includes IAM reconnaissance, an unusual source IP, sensitive role usage, and enterprise identity context that raises the user's risk score.

## Timeline

1. `admin.user@example.com` performs IAM discovery activity, including identity and group lookups.
2. The actor attaches `AdministratorAccess` to `john.contractor@example.com`.
3. A contractor identity, `caleb.stone@vendor.example`, is added to a privileged group in the simulated environment.
4. The contractor later assumes a sensitive `ProductionAdmin` role from an unusual IP range.
5. Existing enterprise telemetry shows sensitive data export activity from a vendor-managed context.
6. IdentityRiskGraph raises risk because contractor status, privileged access, sensitive permissions, and suspicious CloudTrail activity overlap.

## Evidence Reviewed

- CloudTrail event name: `AttachUserPolicy`
- Target policy: `AdministratorAccess`
- Actor: `admin.user@example.com`
- Source IP: simulated external range
- Target identity: contractor-style account
- MITRE mapping: Account Manipulation / Additional Cloud Roles
- Related activity: IAM reconnaissance and sensitive role assumption

## Analyst Reasoning

The policy attachment alone is high-signal because it grants broad administrative control directly to an identity. The risk increases because the target identity is contractor-style and related activity suggests privilege discovery and sensitive role usage.

The analyst should not assume compromise from one event. The right workflow is to validate authorization, inspect the actor session, review the target identity's business need, and contain access if the change cannot be justified.

## Recommended Containment Steps

1. Confirm whether a valid change ticket approved the policy attachment.
2. Temporarily detach `AdministratorAccess` if approval is missing.
3. Review the actor's CloudTrail activity before and after the change.
4. Check whether MFA and expected source network were used.
5. Rotate credentials or revoke sessions if the actor or target activity is unexplained.
6. Review group membership and inherited access for the contractor.
7. Notify the data owner if sensitive resources were accessed or exported.

## Outcome In The Dashboard

In the Streamlit app, the analyst can pivot from **CloudTrail IAM Detections** to **Risky Identities**, then open **User Investigation** to review risk factors, effective permissions, recent events, and recommended actions.

