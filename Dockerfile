# Build stage: install kubeready and PyYAML into a virtualenv.
FROM python:3.12-slim AS build
COPY --from=ghcr.io/astral-sh/uv:0.8 /uv /usr/local/bin/uv
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN uv venv /opt/venv && VIRTUAL_ENV=/opt/venv uv pip install --no-cache .

# Runtime stage: just the venv, running as a non-root user.
FROM python:3.12-slim
COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN useradd --create-home --uid 10001 kubeready
USER 10001
WORKDIR /work
# A one-shot CLI, not a service, so there is no HEALTHCHECK. Mount manifests at /work.
ENTRYPOINT ["kubeready"]
CMD ["."]
