# Listmonk Stage 3 environment study

## Outcome

The exact vulnerable and fixed revisions both build and start in clean, independent Docker Compose environments.

| Revision | URL | Image digest | Result |
| --- | --- | --- | --- |
| `171a597ff2f20e29dad9894418a4934f9ed30a58` | `http://127.0.0.1:19000` | `sha256:43cf7ef45938f796160a773f969249339dbfb6a23e529681ab37c4ec83643ea0` | Running |
| `c0a6525009a65265230185f16e8674dcc83aa024` | `http://127.0.0.1:19001` | `sha256:5506124f6875da641a9351fb9c0903542d7b5d8304c868216dd7ffa31ee1d8dc` | Running |

Both instances initialize themselves against PostgreSQL 17.10 and create the disposable web administrator `stage3admin` with password `Stage3Listmonk-2026`. The vulnerable instance's login endpoint returned `200`, the credential produced a `302 /admin`, and the resulting session could read `/api/settings` with `200`. The fixed service has the same initialization path and credentials.

The binaries embed and print their full source commits. Git also confirms that the vulnerable revision is an ancestor of the selected fixed revision. The source worktrees remain clean.

## Environment reconstruction note

The first build failed because the upstream `.dockerignore` excludes every `.gitignore`, while the frontend build invokes ESLint with `--ignore-path .gitignore`. The study Dockerfile materializes an empty `frontend/.gitignore` inside the builder. This is a build-context correction only; it does not alter application source or behavior. The failed build is preserved in `logs/build.log`, and the successful retry is in `logs/build-2.log`.

The runtime recipe otherwise follows upstream's own flow: `make dist`, the upstream `docker-entrypoint.sh`, idempotent installation, upgrade, and normal server start. Base image digests are captured in the build logs. PostgreSQL resolved to `sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193`.

## Commands

Run `bash prepare.sh` from a fresh copy of this directory to fetch the two exact
revisions and build both images. Then:

```sh
docker compose -p ca_stage3_listmonk_env build app
docker compose -p ca_stage3_listmonk_env up -d
docker compose -p ca_stage3_listmonk_env exec -T app ./listmonk --version

docker build \
  --build-arg SOURCE_COMMIT=c0a6525009a65265230185f16e8674dcc83aa024 \
  --build-arg STUDY_VERSION=v6.0.0-stage3-fixed \
  --tag cyber-arena-stage3-listmonk:c0a6525 \
  --file Dockerfile source-fixed
docker compose -p ca_stage3_listmonk_fixed -f compose-fixed.yaml up -d
docker compose -p ca_stage3_listmonk_fixed -f compose-fixed.yaml exec -T app ./listmonk --version
```

The environments were kept running for the vulnerability-study agents. After
the study, remove only these two projects:

```sh
docker compose -p ca_stage3_listmonk_env down -v
docker compose -p ca_stage3_listmonk_fixed -f compose-fixed.yaml down -v
```

## Evidence

All raw command transcripts are under `logs/`. The most useful are:

- `build.log`: expected first failure.
- `build-2.log` and `build-fixed.log`: complete successful builds.
- `app.log`, `app-fixed.log`, `version.log`, and `version-fixed.log`: startup and embedded revision evidence.
- `compose-ps.log` and `compose-ps-fixed.log`: ports and container state.
- `http-admin-auth.log` and `http-settings-session.log`: vulnerable-instance initialization and login proof.
- `image-inspect.log`, `image-inspect-fixed.log`, and `image-inspect-postgres.log`: immutable image metadata.
- `source-vulnerable.log`, `source-fixed.log`, and `ancestry.log`: source identities and history relationship.
