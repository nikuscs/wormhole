#!/usr/bin/env python3
"""Add Wormhole's license and notices to a ZIP or tar.gz release archive."""

import argparse
import copy
import gzip
import io
import os
import tarfile
import tempfile
import zipfile
from pathlib import Path

LEGAL_NAMES = ("LICENSE", "THIRD_PARTY_NOTICES")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("--license-file", required=True, type=Path)
    parser.add_argument("--notices-file", required=True, type=Path)
    return parser.parse_args()


def legal_files(args: argparse.Namespace) -> dict[str, bytes]:
    return {
        "LICENSE": args.license_file.read_bytes(),
        "THIRD_PARTY_NOTICES": args.notices_file.read_bytes(),
    }


def replace_zip(archive: Path, files: dict[str, bytes], temporary: Path) -> None:
    with zipfile.ZipFile(archive) as source, zipfile.ZipFile(
        temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as destination:
        for info in source.infolist():
            if info.filename in LEGAL_NAMES:
                continue
            destination.writestr(info, source.read(info.filename))
        for name, data in files.items():
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            destination.writestr(info, data)


def tar_prefix(members: list[tarfile.TarInfo]) -> str:
    roots = {member.name.strip("/").split("/", 1)[0] for member in members if member.name.strip("/")}
    return f"{next(iter(roots))}/" if len(roots) == 1 else ""


def replace_tar(archive: Path, files: dict[str, bytes], temporary: Path) -> None:
    entries: list[tuple[tarfile.TarInfo, bytes | None]] = []
    with tarfile.open(archive, "r:gz") as source:
        members = source.getmembers()
        prefix = tar_prefix(members)
        legal_paths = {f"{prefix}{name}" for name in LEGAL_NAMES}
        for member in members:
            if member.name in legal_paths:
                continue
            extracted = source.extractfile(member) if member.isfile() else None
            entries.append((copy.copy(member), extracted.read() if extracted else None))

    with temporary.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as destination:
                for member, data in entries:
                    destination.addfile(member, io.BytesIO(data) if data is not None else None)
                for name, data in files.items():
                    info = tarfile.TarInfo(f"{prefix}{name}")
                    info.size = len(data)
                    info.mode = 0o644
                    info.mtime = 0
                    destination.addfile(info, io.BytesIO(data))


def main() -> None:
    args = parse_args()
    archive = args.archive.resolve()
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{archive.name}.", dir=archive.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        if archive.name.endswith(".zip"):
            replace_zip(archive, legal_files(args), temporary)
        elif archive.name.endswith(".tar.gz"):
            replace_tar(archive, legal_files(args), temporary)
        else:
            raise SystemExit(f"unsupported archive format: {archive.name}")
        temporary.replace(archive)
    finally:
        temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
