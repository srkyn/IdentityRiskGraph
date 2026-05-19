# Detection Logic

Each finding returns a detection ID, name, severity, user, timestamp, reason, evidence, risk score delta, MITRE mapping, recommended action, and investigation questions.

## Rules

1. **Toxic Permission Combination:** fires when an identity can both administer IAM and export/download sensitive data.
2. **Nested Group Privilege Escalation:** fires when privileged access is inherited through at least two group hops.
3. **Dormant Account Access:** fires when a dormant, terminated, or stale account succeeds after long inactivity.
4. **Privileged Access From Untrusted Device:** fires when a privileged identity uses an unmanaged or noncompliant endpoint.
5. **Impossible Travel:** fires when successful logins imply unrealistic travel velocity.
6. **Role Change Followed By Sensitive Access:** fires when sensitive access occurs within 24 hours of a role or group change.
7. **Service Account Interactive Login:** fires when a service account performs a browser-style login.
8. **Contractor With Privileged Access:** fires when a contractor has elevated privilege or sensitive export capability.
9. **Break-Glass Account Usage:** fires when an emergency account is used outside the simulated emergency workflow.
10. **Permission Boundary Violation Attempt:** fires when an attempted action is outside a boundary-style maximum permission set.
11. **Excessive Inherited Permissions:** fires when many sensitive permissions arrive through inherited groups.
12. **Stale Privileged Assignment:** fires when a privileged role is marked stale or unused.
13. **Data Exfiltration Pattern:** fires on repeated sensitive exports/downloads against restricted resources.
14. **Repeated Access Denied Followed By Success:** fires when denied attempts are followed by success for the same action.
15. **Admin Role Assigned By Unusual Actor:** fires when privileged assignment is performed by an actor outside access-management context.

## MITRE Mapping

The rules are mapped to defensive ATT&CK-style investigation themes such as Valid Accounts, Account Manipulation, Additional Local or Domain Groups, and Data from Cloud Storage Object.

CloudTrail IAM rules use cloud-focused mappings such as Cloud Accounts, Account Manipulation, Additional Cloud Roles, Account Discovery, Permission Groups Discovery, Additional Cloud Credentials, and Disable Cloud Logs. These are used as analyst pivots, not as claims that every sample event is malicious by itself.

## False Positive Reduction

The same event can score differently based on identity context. For example, a payroll export by a finance manager may be medium risk, while the same export by a contractor with recent role changes, an unmanaged device, and nested inherited access becomes critical.
