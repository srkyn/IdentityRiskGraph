from src.github_repo_context import build_repo_api_url, parse_repo_context, review_repo_context


def test_build_repo_api_url_requires_owner_and_repo():
    assert build_repo_api_url("srkyn", "IdentityRiskGraph") == "https://api.github.com/repos/srkyn/IdentityRiskGraph"


def test_parse_repo_context_normalizes_github_api_payload():
    context = parse_repo_context(
        {
            "name": "IdentityRiskGraph",
            "description": "Identity-first detection engineering app.",
            "default_branch": "main",
            "visibility": "public",
            "archived": False,
            "fork": False,
            "open_issues_count": 3,
            "stargazers_count": 4,
            "pushed_at": "2026-05-22T14:00:00Z",
            "html_url": "https://github.com/srkyn/IdentityRiskGraph",
            "topics": ["iam", "soc", "github-api"],
            "has_issues": True,
            "has_wiki": False,
            "has_discussions": True,
            "license": {"name": "MIT License"},
            "owner": {"login": "srkyn"},
        }
    )

    assert context.owner == "srkyn"
    assert context.name == "IdentityRiskGraph"
    assert context.default_branch == "main"
    assert context.topics == ("iam", "soc", "github-api")
    assert context.license_name == "MIT License"
    assert context.has_issues is True


def test_review_repo_context_returns_human_review_notes():
    context = parse_repo_context(
        {
            "name": "sample",
            "visibility": "public",
            "archived": False,
            "has_issues": True,
            "topics": ["security"],
            "license": {"name": "MIT License"},
            "owner": {"login": "srkyn"},
        }
    )

    notes = review_repo_context(context)

    assert [note.signal for note in notes] == [
        "visibility",
        "repository state",
        "issue workflow",
        "topics",
        "license",
    ]
    assert any(note.status == "public" for note in notes)
    assert all(note.note for note in notes)
