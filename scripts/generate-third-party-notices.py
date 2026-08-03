#!/usr/bin/env python3
"""Generate deterministic notices for third-party code shipped by Wormhole."""

import argparse
import hashlib
import json
import re
import subprocess
from collections import defaultdict
from pathlib import Path

TARGETS = (
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-gnu",
    "wasm32-unknown-unknown",
)
ROOT_PACKAGES = {"wormhole-cli", "wormholed", "wormholed-cloudflare"}
LEGAL_NAME = re.compile(r"^(license|copying|notice|unlicense)([._-].*)?$", re.IGNORECASE)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def cargo_metadata(root: Path, target: str) -> dict:
    result = subprocess.run(
        [
            "cargo",
            "metadata",
            "--locked",
            "--format-version=1",
            "--filter-platform",
            target,
        ],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def production_packages(metadata: dict) -> dict[str, dict]:
    packages = {package["id"]: package for package in metadata["packages"]}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    pending = [
        package["id"]
        for package in metadata["packages"]
        if package["source"] is None and package["name"] in ROOT_PACKAGES
    ]
    visited: set[str] = set()
    while pending:
        package_id = pending.pop()
        if package_id in visited:
            continue
        visited.add(package_id)
        for dependency in nodes[package_id]["deps"]:
            if any(kind["kind"] != "dev" for kind in dependency["dep_kinds"]):
                pending.append(dependency["pkg"])
    return {
        package_id: packages[package_id]
        for package_id in visited
        if packages[package_id]["source"] is not None
    }


def legal_paths(package: dict) -> list[Path]:
    root = Path(package["manifest_path"]).parent
    candidates = [
        path
        for path in root.iterdir()
        if path.is_file() and LEGAL_NAME.match(path.name)
    ]
    licenses = root / "LICENSES"
    if licenses.is_dir():
        candidates.extend(path for path in licenses.rglob("*") if path.is_file())
    license_file = package.get("license_file")
    if license_file:
        path = (root / license_file).resolve()
        if path.is_file():
            candidates.append(path)
    return sorted(set(candidates), key=lambda path: path.relative_to(root).as_posix().lower())


def normalized_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n").strip()


def component_label(package: dict) -> str:
    return f'{package["name"]} {package["version"]}'


def render(packages: dict[str, dict]) -> str:
    documents: dict[str, str] = {}
    document_users: dict[str, set[str]] = defaultdict(set)
    document_names: dict[str, set[str]] = defaultdict(set)
    component_documents: dict[str, list[str]] = {}

    ordered = sorted(
        packages.values(),
        key=lambda package: (package["name"].lower(), package["version"], package["source"]),
    )
    for package in ordered:
        label = component_label(package)
        digests = []
        for path in legal_paths(package):
            text = normalized_text(path)
            if not text:
                continue
            digest = hashlib.sha256(text.encode()).hexdigest()
            documents[digest] = text
            document_users[digest].add(label)
            document_names[digest].add(path.name)
            digests.append(digest)
        component_documents[package["id"]] = sorted(set(digests))

    lines = [
        "Wormhole Third-Party Notices",
        "============================",
        "",
        "This file covers third-party software incorporated into Wormhole's native binaries and",
        "Cloudflare Worker bundle. It is generated from the locked production dependency graph for",
        "the supported macOS, Linux, and WebAssembly targets.",
        "",
        "External tools and services",
        "---------------------------",
        "Wormhole can invoke separately installed Cloudflare cloudflared and Tailscale clients.",
        "Those programs are not distributed with Wormhole and remain subject to their own licenses",
        "and service terms. Wormhole is not affiliated with or endorsed by Cloudflare or Tailscale.",
        "",
        "Artwork",
        "-------",
        "The worm icon is derived from Twitter Twemoji, Copyright 2020 Twitter, Inc. and other",
        "contributors, licensed under CC BY 4.0:",
        "https://creativecommons.org/licenses/by/4.0/",
        "",
        "Components",
        "----------",
    ]
    for package in ordered:
        label = component_label(package)
        license_name = package.get("license") or "license-file"
        digests = component_documents[package["id"]]
        references = ", ".join(digest[:16] for digest in digests) or "SPDX metadata only"
        lines.append(f"- {label} | {license_name} | documents: {references}")
        repository = package.get("repository") or package.get("homepage")
        if repository:
            lines.append(f"  {repository}")

    lines.extend(["", "License and notice documents", "----------------------------"])
    for digest in sorted(documents):
        users = ", ".join(
            sorted(document_users[digest], key=lambda value: (value.lower(), value))
        )
        names = ", ".join(
            sorted(document_names[digest], key=lambda value: (value.lower(), value))
        )
        lines.extend(
            [
                "",
                f"Document {digest[:16]} ({names})",
                f"Used by: {users}",
                "~" * 72,
                documents[digest],
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    args = parse_args()
    root = args.root.resolve()
    packages: dict[str, dict] = {}
    for target in TARGETS:
        packages.update(production_packages(cargo_metadata(root, target)))
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render(packages), encoding="utf-8")


if __name__ == "__main__":
    main()
