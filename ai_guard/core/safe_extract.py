"""Archive extraction with Tar Slip / Zip Slip protection."""

from __future__ import annotations

import os
import stat
import sys
import tarfile
import zipfile


class ExtractPathError(ValueError):
    """Rejected path inside an archive (traversal, absolute path, or unsafe link)."""


def _parts_from_archive_name(name: str) -> list[str]:
    """Split a normalized archive entry name into safe path components."""
    normalized = name.replace("\\", "/").strip()
    if not normalized or normalized == ".":
        raise ExtractPathError("empty archive path")
    if normalized.startswith("/"):
        raise ExtractPathError("absolute path in archive")
    if len(normalized) >= 2 and normalized[1] == ":":
        raise ExtractPathError("absolute path in archive")

    parts: list[str] = []
    for p in normalized.split("/"):
        if p == "" or p == ".":
            continue
        if p == "..":
            raise ExtractPathError("path traversal in archive")
        parts.append(p)
    if not parts:
        raise ExtractPathError("empty archive path")
    return parts


def _joined_under_root(root_real: str, parts: list[str]) -> str:
    candidate = os.path.normpath(os.path.join(root_real, *parts))
    try:
        common = os.path.commonpath([root_real, candidate])
    except ValueError:
        raise ExtractPathError("path escapes extraction directory") from None
    if common != root_real:
        raise ExtractPathError("path escapes extraction directory")
    return candidate


def _reject_special_tar_member(member: tarfile.TarInfo) -> None:
    if member.issym() or member.islnk() or member.ischr() or member.isblk() or member.isfifo():
        raise ExtractPathError(f"unsupported tar member type: {member.name!r}")


def _extract_tar_pre_312(tar: tarfile.TarFile, dest_dir: str) -> None:
    root_real = os.path.realpath(dest_dir)
    os.makedirs(dest_dir, exist_ok=True)

    for member in tar.getmembers():
        _reject_special_tar_member(member)
        name = member.name
        if member.isdir() and not name.endswith("/"):
            name = name + "/"
        rel = name.rstrip("/") if name.endswith("/") else name
        if not rel:
            continue
        parts = _parts_from_archive_name(rel)
        target_path = _joined_under_root(root_real, parts)

        if member.isdir():
            os.makedirs(target_path, exist_ok=True)
            continue
        if member.isfile() or member.type == tarfile.REGTYPE:
            parent = os.path.dirname(target_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with tar.extractfile(member) as src:
                if src is None:
                    raise ExtractPathError(f"cannot read tar member: {member.name!r}")
                with open(target_path, "wb") as out:
                    out.write(src.read())
            mode = member.mode
            if mode is not None:
                try:
                    os.chmod(target_path, stat.S_IMODE(mode))
                except OSError:
                    pass
            continue

        raise ExtractPathError(f"unsupported tar member: {member.name!r}")


def extract_tar_archive(archive_path: str, dest_dir: str) -> None:
    """Extract a tar archive (.tar, .tar.gz, .tgz, etc.) under dest_dir."""
    os.makedirs(dest_dir, exist_ok=True)
    root_real = os.path.realpath(dest_dir)

    with tarfile.open(archive_path, mode="r:*") as tar:
        if sys.version_info >= (3, 12):
            for member in tar.getmembers():
                rel = member.name.rstrip("/") if member.isdir() else member.name
                if not rel:
                    continue
                parts = _parts_from_archive_name(rel)
                _joined_under_root(root_real, parts)
            tar.extractall(dest_dir, filter="data")
        else:
            _extract_tar_pre_312(tar, dest_dir)


def extract_zip_archive(zip_path: str, dest_dir: str) -> None:
    """Extract a zip archive (.whl, .zip) under dest_dir."""
    os.makedirs(dest_dir, exist_ok=True)
    root_real = os.path.realpath(dest_dir)

    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            fn = info.filename
            is_dir = fn.endswith("/")
            rel = fn.rstrip("/") if is_dir else fn
            if not rel:
                continue
            parts = _parts_from_archive_name(rel)
            target_path = _joined_under_root(root_real, parts)

            if is_dir:
                os.makedirs(target_path, exist_ok=True)
            else:
                parent = os.path.dirname(target_path)
                if parent:
                    os.makedirs(parent, exist_ok=True)
                with zf.open(info, "r") as src, open(target_path, "wb") as out:
                    out.write(src.read())
