# GCP Resource Hierarchy

IdentityRiskGraph does not integrate with Google Cloud in v1, but its permission resolver is intentionally compatible with the concept of inherited IAM access.

## Resource Model

Google Cloud resources are organized in a hierarchy:

- **Organization:** top-level container for a company.
- **Folders:** optional grouping layer for departments, environments, or business units.
- **Projects:** primary boundary for workloads, billing, APIs, and IAM policies.
- **Resources:** services and assets inside projects, such as Cloud Storage buckets, BigQuery datasets, service accounts, and compute resources.

## IAM Inheritance

IAM allow policies can be attached at different levels. A role granted at the organization level can flow down to folders, projects, and resources. A role granted at a folder can affect every project below that folder.

That inheritance is powerful, but it can create hidden risk:

- A user may look low-risk at the project level but inherit powerful organization-level access.
- A contractor may inherit access through a folder used by multiple teams.
- A service account may receive broad roles that affect many projects.
- A sensitive project may accidentally inherit permissions intended for a broader business unit.

## Mapping To IdentityRiskGraph

IdentityRiskGraph models inheritance with users, groups, nested groups, roles, and permissions. The same idea applies to GCP:

- User or service account maps to an identity.
- Organization/folder/project/resource policies map to inherited role paths.
- Broad predefined roles map to high-privilege effective permissions.
- Principal boundaries and deny policies map conceptually to maximum-permission and explicit-deny constraints.

Future GCP support could ingest IAM policies from organization, folder, project, and resource levels, then use the existing resolver to explain effective access paths.

