#!/usr/bin/env python3
"""Generate the Homebrew tap formula for one Wormhole release."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

TARGETS = {
    "mac_arm": "aarch64-apple-darwin",
    "mac_intel": "x86_64-apple-darwin",
    "linux_arm": "aarch64-unknown-linux-gnu",
    "linux_intel": "x86_64-unknown-linux-gnu",
}


def checksum(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as artifact:
        for block in iter(lambda: artifact.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def render(version: str, artifacts: Path) -> str:
    hashes = {
        name: checksum(artifacts / f"wormhole-cli-{target}.zip")
        for name, target in TARGETS.items()
    }
    release = f"https://github.com/nikuscs/wormhole/releases/download/v{version}"
    return f'''class Wormhole < Formula
  desc "Secure tunnels for agents, automation, and worktrees"
  homepage "https://github.com/nikuscs/wormhole"
  license "MIT"

  if OS.mac?
    if Hardware::CPU.arm?
      url "{release}/wormhole-cli-aarch64-apple-darwin.zip"
      sha256 "{hashes["mac_arm"]}"
    else
      url "{release}/wormhole-cli-x86_64-apple-darwin.zip"
      sha256 "{hashes["mac_intel"]}"
    end
  elsif Hardware::CPU.arm?
    url "{release}/wormhole-cli-aarch64-unknown-linux-gnu.zip"
    sha256 "{hashes["linux_arm"]}"
  else
    url "{release}/wormhole-cli-x86_64-unknown-linux-gnu.zip"
    sha256 "{hashes["linux_intel"]}"
  end

  def install
    bin.install "wormhole"
  end

  test do
    assert_match "Usage:", shell_output("#{{bin}}/wormhole --help")
  end
end
'''


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(render(args.version, args.artifacts))


if __name__ == "__main__":
    main()
