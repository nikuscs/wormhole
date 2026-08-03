#!/usr/bin/env python3
"""Package the prebuilt Cloudflare Worker as a reproducible release bundle."""

import argparse
import gzip
import hashlib
import io
import json
import re
import shutil
import tarfile
from pathlib import Path


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument(
        "--crate-dir",
        type=Path,
        default=root / "crates/wormholed-cloudflare",
    )
    parser.add_argument("--license-file", type=Path, default=root / "LICENSE")
    parser.add_argument(
        "--notices-file", type=Path, default=root / "THIRD_PARTY_NOTICES"
    )
    return parser.parse_args()


def read_config(path: Path) -> dict:
    text = re.sub(r"(?m)^\s*//.*\n", "", path.read_text())
    config = json.loads(text)
    config.pop("$schema", None)
    config.pop("build", None)
    return config


def add_file(archive: tarfile.TarFile, path: Path, name: str) -> None:
    data = path.read_bytes()
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = 0o644
    info.mtime = 0
    archive.addfile(info, io.BytesIO(data))


def main() -> None:
    args = parse_args()
    crate = args.crate_dir.resolve()
    output = args.output_dir.resolve()
    staging = output / "wormholed-cloudflare-worker"
    shutil.rmtree(staging, ignore_errors=True)
    (staging / "build/worker").mkdir(parents=True)

    config = read_config(crate / "wrangler.jsonc")
    (staging / "wrangler.jsonc").write_text(json.dumps(config, indent=2) + "\n")
    lock = json.loads((crate / "package-lock.json").read_text())
    wrangler_version = lock["packages"]["node_modules/wrangler"]["version"]
    manifest = {
        "schema": 1,
        "wormhole_version": args.version,
        "wrangler_version": wrangler_version,
    }
    (staging / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    for relative in ["index.js", "index_bg.wasm", "package.json"]:
        shutil.copy2(crate / "build" / relative, staging / "build" / relative)
    shutil.copy2(crate / "build/worker/shim.mjs", staging / "build/worker/shim.mjs")
    shutil.copy2(args.license_file, staging / "LICENSE")
    shutil.copy2(args.notices_file, staging / "THIRD_PARTY_NOTICES")

    output.mkdir(parents=True, exist_ok=True)
    asset = output / "wormholed-cloudflare-worker.tar.gz"
    with asset.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for path in sorted(staging.rglob("*")):
                    if path.is_file():
                        add_file(archive, path, path.relative_to(staging).as_posix())
    digest = hashlib.sha256(asset.read_bytes()).hexdigest()
    (output / f"{asset.name}.sha256").write_text(f"{digest}  {asset.name}\n")


if __name__ == "__main__":
    main()
