from __future__ import annotations

import re
from urllib.parse import urlparse


_RESERVED_GITHUB_OWNERS = {
    "advisories",
    "apps",
    "collections",
    "features",
    "marketplace",
    "organizations",
    "security",
    "settings",
    "sponsors",
    "topics",
}

def canonical_github_repo(url: str | None) -> str | None:
    """Return a lowercase ``owner/repo`` for a GitHub source URL."""
    if not url:
        return None
    value = url.strip()
    if value.startswith("git+"):
        value = value[4:]
    if value.startswith("git@github.com:"):
        path = value.removeprefix("git@github.com:")
    else:
        parsed = urlparse(value)
        if parsed.hostname not in {"github.com", "www.github.com"}:
            return None
        path = parsed.path
    parts = [part for part in path.strip("/").split("/") if part]
    if len(parts) < 2 or parts[0].lower() in _RESERVED_GITHUB_OWNERS:
        return None
    owner = parts[0].lower()
    repo = parts[1].removesuffix(".git").lower()
    if not re.fullmatch(r"[a-z0-9_.-]+", owner) or not re.fullmatch(
        r"[a-z0-9_.-]+", repo
    ):
        return None
    return f"{owner}/{repo}"

def prototype_exclusion_reason(project: dict) -> str | None:
    """Reject obvious non-service shapes while leaving ambiguous cases for review."""
    topics = {str(topic).lower() for topic in project.get("topics", [])}
    service_terms = {
        "database", "platform", "self-hosted", "server", "service", "web",
        "webapp", "web-application",
    }
    if topics & {"cli", "command-line"} and not topics & service_terms:
        return "command-line tool, not a deployable service"
    if topics & {"cni", "ebpf", "kernel", "kubernetes-networking"}:
        return "kernel/cluster infrastructure likely requires unsafe arena privileges"
    if topics & {"library", "sdk"} and not topics & service_terms:
        return "library or SDK, not a deployable service"
    text = " ".join(
        [
            str(project.get("name", "")),
            str(project.get("description", "")),
            " ".join(project.get("topics", [])),
        ]
    ).lower()
    words = set(re.findall(r"[a-z0-9-]+", text))
    deployable_terms = service_terms | {
        "analytics", "application", "authentication", "ci-cd", "cms",
        "collaboration", "dashboard", "file-server", "file-sharing", "git-server",
        "iam", "identity", "management", "monitoring", "observability", "webui",
    }
    if not words & deployable_terms:
        return "no clear deployable network-service signal in repository metadata"
    return None
