# Reproducible replacement for the hand-built "ag-test"/"agplugin-test" containers
# (docker exec + apt-get by hand, never committed, thrown away between sessions).
# Build: docker build -t agentguards-claude-e2e tests/e2e (from the repo root)
# Run:   see run.sh — needs --dns 8.8.8.8 at `docker run` time (see README.md).

FROM node:22-slim

# git: node:22-slim ships without it. Missing git makes
# `/plugin marketplace add alelaguard/agentguards-plugins` fail with
# ERR_STREAM_PREMATURE_CLOSE and an SSH-shaped error — the git binary never
# existed, so the spawn dies before SSH is ever reached. python3 + venv: pyte
# (the transcript renderer) needs a venv, PEP 668 blocks a system install.
RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends \
        git \
        ca-certificates \
        python3 \
        python3-venv \
    && rm -rf /var/lib/apt/lists/* \
    # The plugin repo is public; rewrite the SSH remote `git clone` shells out
    # to into HTTPS so no key or known_hosts entry is needed. Claude Code
    # passes BatchMode=yes, so ssh can never fall back to prompting either.
    && git config --system url."https://github.com/".insteadOf "git@github.com:"

RUN npm install -g @anthropic-ai/claude-code

RUN python3 -m venv /opt/e2e-venv \
    && /opt/e2e-venv/bin/pip install --no-cache-dir --quiet pyte pytest

ENV PATH="/opt/e2e-venv/bin:${PATH}"

WORKDIR /demo

# AGENTGUARDS_API_KEY / ANTHROPIC_API_KEY are NOT baked in — passed at
# `docker run` time only (see CLAUDE.md: never commit or embed a live key).

CMD ["sleep", "infinity"]
