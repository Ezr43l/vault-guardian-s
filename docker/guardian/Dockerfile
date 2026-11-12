# syntax=docker/dockerfile:1.7

ARG PYTHON_IMAGE=python:3.12.16-alpine3.24@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89

FROM ${PYTHON_IMAGE} AS security-builder
COPY docker/security /security
RUN sh /security/build-runtime.sh

FROM ${PYTHON_IMAGE} AS security-python
RUN apk upgrade --no-cache && apk add --no-cache libexpat=2.10.0-r0 libgcc=15.2.0-r5
COPY --from=security-builder /out-runtime/ /
COPY --from=security-builder /wheels /tmp/security-wheels
COPY docker/security/install-python.py /tmp/install-python.py
RUN python3 -c 'import sys,pyexpat;assert sys.version_info[:3] == (3,12,16);assert pyexpat.version_info >= (2,10,0)'

FROM security-python AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

RUN apk upgrade --no-cache \
    && apk add --no-cache ca-certificates tzdata
COPY docker/guardian/requirements.txt /tmp/requirements.txt
RUN python3 -m pip install --no-cache-dir --upgrade pip==26.2.2 \
    && python3 /tmp/install-python.py /tmp/requirements.txt \
    && python3 -m pip uninstall --yes pip

FROM base AS test
ARG RUN_BUILD_TESTS=0
WORKDIR /workspace
COPY VERSION LICENSE README.md CHANGELOG.md build-image.sh ./
COPY config ./config
COPY unraid ./unraid
COPY docker/guardian ./docker/guardian
RUN if [ "$RUN_BUILD_TESTS" = "1" ]; then \
      PYTHONPATH=/workspace/docker/guardian/app python -m unittest discover -s /workspace/docker/guardian/tests -v; \
    fi

FROM base AS runtime
WORKDIR /app

COPY --from=test /workspace/VERSION /app/VERSION
COPY --from=test /workspace/LICENSE /app/LICENSE
COPY --from=test /workspace/docker/guardian/app /app
COPY --from=test /workspace/docker/guardian/web /web
COPY --from=test /workspace/docker/guardian/entrypoint.sh /entrypoint.sh

RUN chmod 0755 /entrypoint.sh \
    && mkdir -p /config /instances /state

ARG BUILD_DATE=""
ARG VCS_REF="unknown"
ARG VERSION="development"
ARG SOURCE_URL="https://github.com/Ezr43l/vault-guardian-s"
ARG LICENSE="Apache-2.0"

LABEL org.opencontainers.image.title="Vault Guardian" \
      org.opencontainers.image.description="Portal HA, aprovisionamiento y réplica segura para Vaultwarden" \
      org.opencontainers.image.source="$SOURCE_URL" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$VCS_REF" \
      org.opencontainers.image.created="$BUILD_DATE" \
      org.opencontainers.image.licenses="$LICENSE"

ENV VG_VERSION="$VERSION"

EXPOSE 6062
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:6062/api/health', timeout=3).read()"]

USER 0:0
ENTRYPOINT ["/entrypoint.sh"]
