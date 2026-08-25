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
    """Return why metadata alone cannot establish a deployable service."""
    text = " ".join(
        [
            str(project.get("name", "")),
            str(project.get("description", "")),
            " ".join(project.get("topics", [])),
        ]
    ).lower()
    words = set(re.findall(r"[a-z0-9-]+", text))
    service_terms = {
        "cms",
        "database",
        "file-server",
        "file-sharing",
        "git-server",
        "self-hosted",
        "selfhosted",
        "server",
        "service",
        "web-application",
        "webapp",
        "webui",
    }
    non_service_terms = {
        "cli",
        "client",
        "command-line",
        "cni",
        "driver",
        "ebpf",
        "framework",
        "kernel",
        "kubernetes-networking",
        "library",
        "sdk",
        "tool",
    }
    has_service_signal = bool(words & service_terms) or (
        {"self", "hosted"} <= words or {"web", "application"} <= words
    )
    has_non_service_signal = bool(words & non_service_terms) or {
        "command",
        "line",
    } <= words
    if has_service_signal and has_non_service_signal:
        return "conflicting_service_metadata"
    if has_non_service_signal:
        return "non_service_shape_indicated"
    if not has_service_signal:
        return "deployable_service_not_established"
    return None
