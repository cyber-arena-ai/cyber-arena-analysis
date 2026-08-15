from __future__ import annotations

import math
import re
from collections import defaultdict
from datetime import datetime, timezone
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

_CATEGORY_TERMS = {
    "developer-platform": {
        "devops", "git", "repository", "scm", "source-control",
    },
    "ci-cd": {
        "automation", "build", "ci", "ci-cd", "continuous-delivery",
        "continuous-integration", "deployment", "pipeline",
    },
    "cms-publishing": {
        "blog", "cms", "content-management", "publishing", "website-builder",
    },
    "collaboration": {
        "chat", "collaboration", "forum", "messaging", "project-management",
        "social-network",
    },
    "observability": {
        "dashboard", "logging", "metrics", "monitoring", "observability",
        "tracing",
    },
    "data-analytics": {
        "analytics", "bi", "business-intelligence", "data-visualization",
        "notebook", "reporting",
    },
    "storage-files": {
        "cloud-storage", "document-management", "file-manager", "file-sharing",
        "object-storage", "storage",
    },
    "security-identity": {
        "authentication", "authorization", "identity", "iam", "password-manager",
        "security", "sso",
    },
    "infrastructure": {
        "container", "database", "infrastructure", "kubernetes", "network",
        "orchestration", "proxy", "server", "virtualization",
    },
}

_APP_POSITIVE_TERMS = {
    "admin", "analytics", "automation", "dashboard", "database", "git",
    "management", "monitoring", "platform", "self-hosted", "server", "service",
}
_APP_NEGATIVE_TERMS = {
    "awesome", "boilerplate", "client", "collection", "examples", "framework",
    "library", "plugin", "sdk", "template", "tutorial",
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


def _normalize_cwes(record: dict) -> list[str]:
    found: set[str] = set()
    containers = [record.get("database_specific", {})]
    for affected in record.get("affected", []):
        containers.extend(
            [
                affected.get("database_specific", {}),
                affected.get("ecosystem_specific", {}),
            ]
        )
    for container in containers:
        for key in ("cwe", "cwes", "cwe_id", "cwe_ids"):
            values = container.get(key, []) if isinstance(container, dict) else []
            if isinstance(values, str):
                values = [values]
            for value in values or []:
                match = re.search(r"CWE[- ]?(\d+)", str(value), re.IGNORECASE)
                if match:
                    found.add(f"CWE-{match.group(1)}")
    return sorted(found, key=lambda item: int(item.split("-", 1)[1]))


def extract_osv_record(record: dict, *, source_ecosystem: str) -> list[dict]:
    """Extract repository-linked advisory evidence from one OSV record.

    A repository declared by an affected GIT range is considered authoritative.
    If none exists, package/fix/advisory references are accepted as lower-confidence
    discovery evidence. Generic web/article links are intentionally ignored because
    they frequently point to researchers or proof-of-concept repositories.
    """
    record_packages: set[str] = set()
    repository_data: dict[str, dict[str, set[str]]] = defaultdict(
        lambda: {"packages": set(), "fixed_commits": set()}
    )
    for affected in record.get("affected", []):
        package = affected.get("package", {})
        ecosystem = package.get("ecosystem")
        name = package.get("name")
        package_key = f"{ecosystem}:{name}" if ecosystem and name else None
        if package_key:
            record_packages.add(package_key)
        for item in affected.get("ranges", []):
            if item.get("type") != "GIT":
                continue
            repo = canonical_github_repo(item.get("repo"))
            if not repo:
                continue
            if package_key:
                repository_data[repo]["packages"].add(package_key)
            for event in item.get("events", []):
                fixed = event.get("fixed")
                if fixed:
                    repository_data[repo]["fixed_commits"].add(str(fixed))

    references = [
        ref.get("url")
        for ref in record.get("references", [])
        if isinstance(ref, dict) and ref.get("url")
    ]
    if repository_data:
        repositories = set(repository_data)
        confidence = "affected_git_range"
        for ref in record.get("references", []):
            if ref.get("type") != "FIX":
                continue
            repo = canonical_github_repo(ref.get("url"))
            commit = _github_commit_from_url(ref.get("url"))
            if repo in repositories and commit:
                repository_data[repo]["fixed_commits"].add(commit)
    else:
        repositories = set()
        for ref in record.get("references", []):
            repo = strong_reference_repository(ref)
            if not repo:
                continue
            repositories.add(repo)
            commit = _github_commit_from_url(ref.get("url"))
            if commit:
                repository_data[repo]["fixed_commits"].add(commit)
        if len(repositories) == 1:
            repository_data[next(iter(repositories))]["packages"].update(
                record_packages
            )
        confidence = "strong_reference"

    aliases = sorted(set(str(value) for value in record.get("aliases", [])))
    evidence = []
    for repository in sorted(repositories):
        evidence.append(
            {
                "repository": repository,
                "repository_confidence": confidence,
                "advisory_id": str(record.get("id", "")),
                "aliases": aliases,
                "summary": str(record.get("summary", "")),
                "published": record.get("published"),
                "modified": record.get("modified"),
                "withdrawn": record.get("withdrawn"),
                "packages": sorted(repository_data[repository]["packages"]),
                "cwes": _normalize_cwes(record),
                "fixed_commits": sorted(
                    repository_data[repository]["fixed_commits"]
                ),
                "references": sorted(set(references)),
                "source_ecosystem": source_ecosystem,
            }
        )
    return evidence


def _github_path_parts(url: str | None) -> list[str]:
    if not url:
        return []
    parsed = urlparse(url.strip())
    if parsed.hostname not in {"github.com", "www.github.com"}:
        return []
    return [part for part in parsed.path.strip("/").split("/") if part]


def _github_commit_from_url(url: str | None) -> str | None:
    parts = _github_path_parts(url)
    if len(parts) >= 4 and parts[2] == "commit" and re.fullmatch(
        r"[0-9a-fA-F]{40}", parts[3]
    ):
        return parts[3].lower()
    return None


def strong_reference_repository(reference: dict) -> str | None:
    """Return a conservative source repository from a typed OSV reference."""
    reference_type = reference.get("type")
    url = reference.get("url")
    repository = canonical_github_repo(url)
    parts = _github_path_parts(url)
    if not repository or len(parts) < 2:
        return None
    if reference_type == "PACKAGE":
        return repository
    if reference_type == "FIX" and len(parts) >= 4 and parts[2] in {
        "commit",
        "pull",
    }:
        return repository
    if (
        reference_type == "ADVISORY"
        and len(parts) >= 5
        and parts[2:4] == ["security", "advisories"]
    ):
        return repository
    return None


def infer_category(project: dict) -> str:
    text = " ".join(
        [
            str(project.get("name", "")),
            str(project.get("description", "")),
            " ".join(project.get("topics", [])),
        ]
    ).lower()
    words = set(re.findall(r"[a-z0-9-]+", text))
    scored = [
        (len(words & terms), category)
        for category, terms in _CATEGORY_TERMS.items()
    ]
    score, category = max(scored)
    return category if score else "other-service"


def _application_fit(project: dict) -> int:
    text = " ".join(
        [
            str(project.get("name", "")),
            str(project.get("description", "")),
            " ".join(project.get("topics", [])),
        ]
    ).lower()
    words = set(re.findall(r"[a-z0-9-]+", text))
    score = 5 + 2 * len(words & _APP_POSITIVE_TERMS)
    score -= 3 * len(words & _APP_NEGATIVE_TERMS)
    if "self-hosted" in words:
        score += 4
    return max(0, min(15, score))


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


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _dedupe_advisories(items: list[dict]) -> list[dict]:
    parent = list(range(len(items)))
    owner: dict[str, int] = {}

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        left, right = find(left), find(right)
        if left != right:
            parent[right] = left

    for index, item in enumerate(items):
        identifiers = {
            str(value)
            for value in [item.get("advisory_id"), *item.get("aliases", [])]
            if value
        }
        for identifier in identifiers:
            if identifier in owner:
                union(index, owner[identifier])
            else:
                owner[identifier] = index

    grouped: dict[int, list[dict]] = defaultdict(list)
    for index, item in enumerate(items):
        grouped[find(index)].append(item)

    merged = []
    for members in grouped.values():
        identifiers = {
            str(value)
            for item in members
            for value in [item.get("advisory_id"), *item.get("aliases", [])]
            if value
        }
        cves = sorted(value for value in identifiers if value.startswith("CVE-"))
        ghsas = sorted(value for value in identifiers if value.startswith("GHSA-"))
        component_id = (cves or ghsas or sorted(identifiers) or [""])[0]
        preferred = min(
            members,
            key=lambda item: (
                item.get("repository_confidence") != "affected_git_range",
                not item.get("summary"),
                item.get("advisory_id", ""),
            ),
        )
        published = sorted(
            str(item["published"])
            for item in members
            if item.get("published")
        )
        modified = sorted(
            str(item["modified"])
            for item in members
            if item.get("modified")
        )
        merged.append(
            {
                **preferred,
                "advisory_id": component_id,
                "aliases": sorted(identifiers - {component_id}),
                "published": published[0] if published else None,
                "modified": modified[-1] if modified else None,
                "withdrawn": next(
                    (
                        item.get("withdrawn")
                        for item in members
                        if item.get("withdrawn")
                    ),
                    None,
                ),
                "packages": sorted(
                    {
                        value
                        for item in members
                        for value in item.get("packages", [])
                    }
                ),
                "cwes": sorted(
                    {
                        value
                        for item in members
                        for value in item.get("cwes", [])
                    }
                ),
                "fixed_commits": sorted(
                    {
                        value
                        for item in members
                        for value in item.get("fixed_commits", [])
                    }
                ),
                "references": sorted(
                    {
                        value
                        for item in members
                        for value in item.get("references", [])
                    }
                ),
                "source_ecosystems": sorted(
                    {
                        value
                        for item in members
                        for value in [
                            *item.get("source_ecosystems", []),
                            item.get("source_ecosystem"),
                        ]
                        if value
                    }
                ),
            }
        )
    return sorted(merged, key=lambda item: item.get("advisory_id", ""))


def popularity_score(project: dict, *, as_of: str) -> tuple[int, dict]:
    """Score GitHub popularity proxies independently from security evidence."""
    stars = max(0, int(project.get("stars", 0) or 0))
    forks = max(0, int(project.get("forks", 0) or 0))
    star_reach = min(55, round(11 * math.log10(stars + 1)))
    community_breadth = min(25, round(5 * math.log10(forks + 1)))

    now = _parse_time(as_of) or datetime.now(timezone.utc)
    pushed = _parse_time(project.get("pushed_at"))
    age_days = (now - pushed).days if pushed else 10_000
    activity = 10 if age_days <= 90 else 7 if age_days <= 365 else 3 if age_days <= 730 else 0

    created = _parse_time(project.get("created_at"))
    project_age_days = max(0, (now - created).days) if created else 0
    longevity = (
        10
        if project_age_days >= 1_825
        else 7
        if project_age_days >= 730
        else 4
        if project_age_days >= 365
        else 2
        if created
        else 0
    )
    return star_reach + community_breadth + activity + longevity, {
        "star_reach": star_reach,
        "community_breadth": community_breadth,
        "maintenance_activity": activity,
        "longevity": longevity,
    }


def _research_score(
    project: dict, advisories: list[dict], *, as_of: str
) -> tuple[int, dict]:
    stars = max(0, int(project.get("stars", 0) or 0))
    popularity = min(25, round(5 * math.log10(stars + 1)))

    now = _parse_time(as_of) or datetime.now(timezone.utc)
    pushed = _parse_time(project.get("pushed_at"))
    age_days = (now - pushed).days if pushed else 10_000
    activity = 10 if age_days <= 180 else 8 if age_days <= 365 else 5 if age_days <= 730 else 1

    app_fit = _application_fit(project)
    advisory_count = len(advisories)
    advisory_history = min(25, advisory_count * 3)
    cwes = {cwe for advisory in advisories for cwe in advisory.get("cwes", [])}
    history_diversity = min(15, len(cwes) * 2)
    license_score = 5 if project.get("license") else 0
    total = min(
        100,
        popularity
        + activity
        + app_fit
        + advisory_history
        + history_diversity
        + license_score,
    )
    return total, {
        "popularity": popularity,
        "activity": activity,
        "application_fit": app_fit,
        "advisory_history": advisory_history,
        "history_diversity": history_diversity,
        "license": license_score,
    }


def merge_and_rank(projects: list[dict], advisories: list[dict], *, as_of: str) -> list[dict]:
    """Join project and advisory snapshots, then compute transparent proxy scores."""
    projects_by_repo = {
        project["repository"].lower(): dict(project)
        for project in projects
        if project.get("repository")
    }
    advisory_by_repo: dict[str, list[dict]] = defaultdict(list)
    for advisory in advisories:
        repository = advisory.get("repository", "").lower()
        if repository:
            advisory_by_repo[repository].append(advisory)

    repositories = set(projects_by_repo) | set(advisory_by_repo)
    ranked = []
    for repository in repositories:
        project = projects_by_repo.get(
            repository,
            {
                "repository": repository,
                "name": repository.split("/", 1)[-1],
                "url": f"https://github.com/{repository}",
                "description": "",
                "stars": 0,
                "forks": 0,
                "language": "Unknown",
                "license": None,
                "topics": [],
                "archived": False,
                "pushed_at": None,
                "discovery_queries": [],
                "discovery_categories": [],
            },
        )
        evidence = _dedupe_advisories(advisory_by_repo.get(repository, []))
        popularity, popularity_components = popularity_score(project, as_of=as_of)
        research_score, research_components = _research_score(
            project, evidence, as_of=as_of
        )
        cwes = sorted(
            {cwe for advisory in evidence for cwe in advisory.get("cwes", [])}
        )
        lane = "both" if repository in projects_by_repo and evidence else (
            "project" if repository in projects_by_repo else "advisory"
        )
        ranked.append(
            {
                **project,
                "repository": repository,
                "primary_category": infer_category(project),
                "discovery_lane": lane,
                "advisory_count": len(evidence),
                "advisory_ids": [item["advisory_id"] for item in evidence],
                "advisory_summaries": [item.get("summary", "") for item in evidence],
                "cwes": cwes,
                "fixed_commit_count": len(
                    {commit for item in evidence for commit in item.get("fixed_commits", [])}
                ),
                "popularity_score": popularity,
                "popularity_score_components": popularity_components,
                "research_score": research_score,
                "research_score_components": research_components,
                "needs_manual_complexity_review": True,
                "prototype_exclusion_reason": prototype_exclusion_reason(project),
            }
        )
    ranked.sort(
        key=lambda item: (
            -item["popularity_score"],
            -item["stars"],
            item["repository"],
        )
    )
    return ranked
