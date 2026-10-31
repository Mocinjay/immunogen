# immunogen Docker image — scan an AI-built repo with no Node toolchain
# install required.
#
# Build (from repo root, no network needed at runtime):
#   docker build -t immunogen:latest .
#
# Run against a mounted directory (deterministic, offline scan, exit code
# reflects the verdict — 1 when blocked, 0 when pass):
#   docker run --rm -v "$(pwd):/app" immunogen:latest /app
#
# Or clone and scan a public repository (needs network):
#   docker run --rm immunogen:latest https://github.com/owner/repo
#
# The deterministic scan needs no network at runtime — the only network
# access is OSV.dev's live dependency-vulnerability lookup, which itself
# has an offline fallback (see src/index.ts's DEP-OFFLINE sentinel), so the
# scan is fully usable with the container's network disabled entirely
# (`docker run --network none ...`).
#
# No API key is baked into this image and none is read from a provider env
# var by default — every `docker run` without an explicit LLM flag stays on
# the offline, deterministic path (T-08-12).

# ---- Build stage ---------------------------------------------------------
# Pinned to node:22-alpine (Alpine is safe here: pure JS/TS stack, no
# native/WASM bindings — .planning/research/PITFALLS.md Pitfall 9).
FROM node:22-alpine AS builder

WORKDIR /build

# Copy manifests first so dependency install is cached independent of
# source changes.
COPY package.json pnpm-lock.yaml ./
RUN corepack enable && pnpm install --frozen-lockfile

COPY . .
RUN pnpm run build

# Strip devDependencies from node_modules before copying into the final
# image — keeps the runtime image lean without re-resolving the lockfile.
RUN pnpm prune --prod

# ---- Runtime stage --------------------------------------------------------
FROM node:22-alpine AS runtime

# git is required to scan a repository URL (the git input mode shells out to
# it via simple-git); the base image does not ship it.
RUN apk add --no-cache git

# Non-root user: the built-in `node` user/group ships with the official
# node:*-alpine image (uid/gid 1000) — no need to addgroup/adduser (T-08-09).
WORKDIR /opt/immunogen

COPY --from=builder --chown=node:node /build/dist ./dist
COPY --from=builder --chown=node:node /build/node_modules ./node_modules
COPY --from=builder --chown=node:node /build/package.json ./package.json

USER node
WORKDIR /app

ENTRYPOINT ["node", "/opt/immunogen/dist/immunogen.js"]
