#!/usr/bin/env bash
set -euo pipefail

if [[ -e source || -e source-fixed ]]; then
  echo "source or source-fixed already exists; use a fresh study directory" >&2
  exit 1
fi

git clone --filter=blob:none https://github.com/knadh/listmonk.git source
git -C source checkout --detach 171a597ff2f20e29dad9894418a4934f9ed30a58

git clone --filter=blob:none https://github.com/knadh/listmonk.git source-fixed
git -C source-fixed checkout --detach c0a6525009a65265230185f16e8674dcc83aa024

docker compose -p ca_stage3_listmonk_env build app
docker build \
  --build-arg SOURCE_COMMIT=c0a6525009a65265230185f16e8674dcc83aa024 \
  --build-arg STUDY_VERSION=v6.0.0-stage3-fixed \
  --tag cyber-arena-stage3-listmonk:c0a6525 \
  --file Dockerfile source-fixed
