#!/usr/bin/env python3
"""Generate deterministic GitHub release notes from the versioned changelog section."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

REPOSITORY = "https://github.com/nikuscs/wormhole"


def changelog_section(changelog: str, version: str) -> str:
    heading = re.compile(rf"^## \[{re.escape(version)}\](?:\s+-\s+.*)?$", re.MULTILINE)
    match = heading.search(changelog)
    if match is None:
        raise ValueError(f"CHANGELOG.md has no section for {version}")
    start = match.end()
    next_heading = re.search(r"^## \[", changelog[start:], re.MULTILINE)
    end = start + next_heading.start() if next_heading else len(changelog)
    section = changelog[start:end].strip()
    section = re.split(r"^\[Unreleased\]:", section, maxsplit=1, flags=re.MULTILINE)[0].strip()
    if not section:
        raise ValueError(f"CHANGELOG.md section for {version} is empty")
    return section


def render(version: str, highlights: str) -> str:
    tag = f"v{version}"
    release = f"{REPOSITORY}/releases/download/{tag}"
    return f"""Secure tunnels for agents, automation, and worktrees—through your own relay, Tailscale, Cloudflare, or multiple providers at once.

## Install

### Homebrew

```sh
brew install nikuscs/tap/wormhole
```

### Installer

```sh
curl --proto '=https' --tlsv1.2 -LsSf \\
  {release}/wormhole-cli-installer.sh | sh
```

### Wormhole relay

```sh
curl --proto '=https' --tlsv1.2 -LsSf \\
  {release}/wormholed-installer.sh | sh
```

For guided server setup:

```sh
curl --proto '=https' --tlsv1.2 -LO \\
  {release}/wormholed-bootstrap.sh
sh wormholed-bootstrap.sh
```

## Highlights

{highlights}

## Downloads

Prebuilt `wormhole` and `wormholed` binaries are available for:

- macOS — Apple Silicon and Intel
- Linux — ARM64 and x86_64
- Cloudflare Workers — platform-independent deployment bundle

macOS binaries are signed with Developer ID and notarized by Apple. Every artifact includes a SHA-256 checksum.

## Verify a download

```sh
curl -LO {release}/wormhole-cli-aarch64-apple-darwin.zip
curl -LO {release}/wormhole-cli-aarch64-apple-darwin.zip.sha256
shasum -a 256 -c wormhole-cli-aarch64-apple-darwin.zip.sha256
```

## Documentation

See the [README]({REPOSITORY}#readme) for quick-start, relay enrollment, provider configuration, and automation examples.

**Full changelog:** {REPOSITORY}/commits/{tag}
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--changelog", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    highlights = changelog_section(args.changelog.read_text(), args.version)
    args.output.write_text(render(args.version, highlights))


if __name__ == "__main__":
    main()
