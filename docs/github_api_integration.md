# GitHub API Integration

IdentityRiskGraph includes a small GitHub REST API adapter for public repository context.

The adapter is intentionally narrow. It reads public repository metadata and turns it into short review notes that help an analyst understand project hygiene signals before opening the code.

## What It Reads

- repository owner and name
- description
- default branch
- visibility
- archived/fork state
- open issue count
- star count
- pushed timestamp
- topics
- issue/wiki/discussion settings
- license name

## What It Does Not Do

- does not scrape GitHub pages
- does not write to GitHub
- does not store API responses
- does not require a token for public repositories
- does not inspect private code
- does not treat repository metadata as a security verdict

## Example

```powershell
python -m src.github_repo_context srkyn/IdentityRiskGraph
```

Example output:

```text
# GitHub Repository Context: srkyn/IdentityRiskGraph

Description: Identity-first detection engineering app for CloudTrail IAM events, nested access paths, and explainable SOC risk investigation.
Default branch: main
URL: https://github.com/srkyn/IdentityRiskGraph

| Signal | Status | Note |
|---|---|---|
| visibility | public | Public metadata can be reviewed without credentials. |
| repository state | active | Recent maintenance signals can support trust. |
| issue workflow | enabled | Issues provide a visible review path for fixes and follow-up. |
| topics | 12 topics | Topics improve discoverability and make project intent easier to scan. |
| license | not declared | Add a license if reuse is intended. |
```

## Why It Fits

Identity investigations often start with a small set of observable signals. This adapter applies the same habit to public GitHub projects: collect context, avoid overclaiming, and write down what the signal does or does not prove.
