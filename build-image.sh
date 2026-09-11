#!/usr/bin/env bash
# Construye exclusivamente una imagen local. La publicación pertenece al workflow de release.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

VERSION="$(tr -d ' \r\n' < VERSION)"
IMAGE="${VG_IMAGE:-vault-guardian:$VERSION}"
SOURCE_URL="${VG_SOURCE_URL:-https://github.com/Ezr43l/vault-guardian-s}"
LICENSE_SPDX="${VG_LICENSE_SPDX:-Apache-2.0}"
VCS_REF="${VG_VCS_REF:-$(git rev-parse HEAD 2>/dev/null || printf unknown)}"
BUILD_DATE="${SOURCE_DATE_EPOCH:-}"

args=(
  --pull
  --file docker/guardian/Dockerfile
  --tag "$IMAGE"
  --build-arg "VERSION=$VERSION"
  --build-arg "SOURCE_URL=$SOURCE_URL"
  --build-arg "VCS_REF=$VCS_REF"
  --build-arg "LICENSE=$LICENSE_SPDX"
)
if [[ -n "$BUILD_DATE" ]]; then
  args+=(--build-arg "BUILD_DATE=$BUILD_DATE")
fi
if [[ -n "${VG_PLATFORM:-}" ]]; then
  args+=(--platform "$VG_PLATFORM")
fi

docker build "${args[@]}" .
echo "Imagen local construida: $IMAGE"
