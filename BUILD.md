# Building & releasing

This doc covers building the panel image from source, tagging it, and the release flow used by this repo. End users don't need to read this — the [README](./README.md) covers running the published image.

## Contents

- [Build from source (development)](#build-from-source-development)
- [Build a tagged image manually](#build-a-tagged-image-manually)
- [Push to a registry](#push-to-a-registry)
- [Versioning](#versioning)
- [Release flow](#release-flow)

---

## Build from source (development)

To build the image locally instead of pulling the published one — for development, customisation, or to run without depending on the registry — switch `compose.yaml` to build mode:

```yaml
panel:
  # image: ghcr.io/tinyhomelab-io/headscale-panel:latest   # comment this out
  build: ./panel                                            # uncomment this
  …
```

Then build and run:

```bash
docker compose build panel
docker compose up -d
```

The Dockerfile (`panel/Dockerfile`) copies `panel/app/` into the image, so the artefact is fully self-contained — identical in shape to the published image, just built locally. To rebuild after code changes:

```bash
docker compose build panel && docker compose up -d panel
```

## Build a tagged image manually

To produce a calendar-versioned, distributable image without touching `compose.yaml`:

```bash
VERSION=$(date +%Y.%m.%d)
docker build -t headscale-panel:$VERSION -t headscale-panel:latest panel/
```

The build context is `panel/` so the entire `panel/` directory ships. The Dockerfile (`panel/Dockerfile`) is referenced by default.

## Push to a registry

GitHub Container Registry (`ghcr.io`) is what this repo publishes to.

**Push access is restricted** — by default only people with `write` role on the GitHub package (managed via the repo's package settings) can push. Anyone is free to fork the repo, build their own image locally, or push to their own org's registry; nobody else can push to `ghcr.io/tinyhomelab-io/headscale-panel`.

To push manually (with appropriate permissions):

```bash
VERSION=$(date +%Y.%m.%d)
ORG=tinyhomelab-io     # change to your org if you're publishing your own fork

docker tag headscale-panel:$VERSION ghcr.io/$ORG/headscale-panel:$VERSION
docker tag headscale-panel:$VERSION ghcr.io/$ORG/headscale-panel:latest

echo "$GITHUB_TOKEN" | docker login ghcr.io -u <username> --password-stdin
docker push ghcr.io/$ORG/headscale-panel:$VERSION
docker push ghcr.io/$ORG/headscale-panel:latest
```

The token needs `write:packages` scope. For automated publishing via GitHub Actions, the workflow's built-in `GITHUB_TOKEN` is used with:

```yaml
permissions:
  contents: read
  packages: write
```

…which grants push access only when the workflow runs from this repo, not from forks.

---

## Versioning

The project uses **calendar versioning** (CalVer) in the form `YYYY.MM.DD`.

- **Image tags**: `:2026.05.02` (specific build) and `:latest` (most recent)
- **Git tags / GitHub Releases**: `v2026.05.02` — releases on GitHub correspond 1:1 with image tags pushed to `ghcr.io`
- **Multiple releases on the same day**: append `.1`, `.2`, … (e.g. `v2026.05.02.1`)

CalVer is used because the panel doesn't expose a versioned API contract — there's nothing to break compatibility on between versions. Calendar dates make it obvious how recent a deployed version is and remove the bookkeeping of semantic-version bumps.

---

## Release flow

Maintainer release process:

```bash
# 1. Confirm the working tree is clean and on main.
git status
git checkout main && git pull

# 2. Tag with the calendar version.
VERSION=$(date +%Y.%m.%d)
git tag -a v$VERSION -m "Release $VERSION"
git push origin v$VERSION
```

When the tag is pushed, the publish workflow (`.github/workflows/release.yml`, when added) will:

1. Build the panel image from `panel/`.
2. Tag it `:$VERSION` and `:latest`.
3. Push both tags to `ghcr.io/tinyhomelab-io/headscale-panel`.
4. Create a GitHub Release for the tag with auto-generated notes.

For deployers, "use the latest GitHub Release" and "pull `:latest` from `ghcr.io`" mean the same thing. Pin a specific `:YYYY.MM.DD` tag in production so a release outage or unexpected change doesn't blindside you.
