from __future__ import annotations

import json
import os
import argparse
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


GITHUB_API_ROOT = "https://api.github.com"


@dataclass(frozen=True)
class GitHubRepoContext:
    owner: str
    name: str
    description: str
    default_branch: str
    visibility: str
    archived: bool
    fork: bool
    open_issues_count: int
    stargazers_count: int
    pushed_at: str
    html_url: str
    topics: tuple[str, ...]
    has_issues: bool
    has_wiki: bool
    has_discussions: bool
    license_name: str | None


@dataclass(frozen=True)
class GitHubRepoReviewNote:
    signal: str
    status: str
    note: str


def build_repo_api_url(owner: str, repo: str) -> str:
    owner = owner.strip()
    repo = repo.strip()
    if not owner or not repo:
        raise ValueError("owner and repo are required")
    return f"{GITHUB_API_ROOT}/repos/{owner}/{repo}"


def fetch_repo_context(owner: str, repo: str, token: str | None = None) -> GitHubRepoContext:
    """Fetch public GitHub repository metadata with an optional token.

    This does not store responses, write files, or call any non-GitHub service.
    """

    token = token or os.getenv("GITHUB_TOKEN")
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "IdentityRiskGraph-public-repo-context",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = Request(build_repo_api_url(owner, repo), headers=headers)
    try:
        with urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        raise RuntimeError(f"GitHub API returned HTTP {exc.code} for {owner}/{repo}") from exc
    except URLError as exc:
        raise RuntimeError(f"GitHub API request failed for {owner}/{repo}: {exc.reason}") from exc

    return parse_repo_context(payload)


def parse_repo_context(payload: dict[str, Any]) -> GitHubRepoContext:
    owner = payload.get("owner") or {}
    license_info = payload.get("license") or {}

    topics = payload.get("topics") or []
    if not isinstance(topics, list):
        topics = []

    return GitHubRepoContext(
        owner=str(owner.get("login") or ""),
        name=str(payload.get("name") or ""),
        description=str(payload.get("description") or ""),
        default_branch=str(payload.get("default_branch") or ""),
        visibility=str(payload.get("visibility") or "public"),
        archived=bool(payload.get("archived")),
        fork=bool(payload.get("fork")),
        open_issues_count=int(payload.get("open_issues_count") or 0),
        stargazers_count=int(payload.get("stargazers_count") or 0),
        pushed_at=str(payload.get("pushed_at") or ""),
        html_url=str(payload.get("html_url") or ""),
        topics=tuple(str(topic) for topic in topics),
        has_issues=bool(payload.get("has_issues")),
        has_wiki=bool(payload.get("has_wiki")),
        has_discussions=bool(payload.get("has_discussions")),
        license_name=str(license_info.get("name") or "") if license_info else None,
    )


def review_repo_context(context: GitHubRepoContext) -> list[GitHubRepoReviewNote]:
    notes: list[GitHubRepoReviewNote] = []

    notes.append(
        GitHubRepoReviewNote(
            signal="visibility",
            status=context.visibility,
            note="Public metadata can be reviewed without credentials." if context.visibility == "public" else "Review access boundaries before sharing.",
        )
    )

    notes.append(
        GitHubRepoReviewNote(
            signal="repository state",
            status="archived" if context.archived else "active",
            note="Archived repositories should be treated as historical context." if context.archived else "Recent maintenance signals can support trust.",
        )
    )

    notes.append(
        GitHubRepoReviewNote(
            signal="issue workflow",
            status="enabled" if context.has_issues else "disabled",
            note="Issues provide a visible review path for fixes and follow-up." if context.has_issues else "No public issue workflow is exposed.",
        )
    )

    notes.append(
        GitHubRepoReviewNote(
            signal="topics",
            status=f"{len(context.topics)} topics",
            note="Topics improve discoverability and make project intent easier to scan." if context.topics else "Missing topics can reduce discoverability.",
        )
    )

    notes.append(
        GitHubRepoReviewNote(
            signal="license",
            status=context.license_name or "not declared",
            note="A license clarifies reuse expectations." if context.license_name else "Add a license if reuse is intended.",
        )
    )

    return notes


def format_review_notes(context: GitHubRepoContext, notes: list[GitHubRepoReviewNote]) -> str:
    lines = [
        f"# GitHub Repository Context: {context.owner}/{context.name}",
        "",
        f"Description: {context.description or 'No description provided.'}",
        f"Default branch: {context.default_branch or 'unknown'}",
        f"URL: {context.html_url or 'unknown'}",
        "",
        "| Signal | Status | Note |",
        "|---|---|---|",
    ]
    for note in notes:
        lines.append(f"| {note.signal} | {note.status} | {note.note} |")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch public GitHub repository context for identity/security review notes.")
    parser.add_argument("repo", help="Repository in owner/name format, for example srkyn/IdentityRiskGraph")
    args = parser.parse_args()

    if "/" not in args.repo:
        raise SystemExit("repo must be in owner/name format")
    owner, repo = args.repo.split("/", 1)
    context = fetch_repo_context(owner, repo)
    print(format_review_notes(context, review_repo_context(context)))


if __name__ == "__main__":
    main()
