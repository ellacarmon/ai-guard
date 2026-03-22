import json
import os
import subprocess
import tempfile
import urllib.error
import urllib.request
from urllib.parse import quote

import click

from .ingestion import Target, TargetType
from .safe_extract import extract_tar_archive, extract_zip_archive


def _distribution_version() -> str:
    try:
        from importlib.metadata import version

        return version("ai-guard")
    except Exception:
        return "0.1.0"


def _http_user_agent() -> str:
    return f"ai-guard/{_distribution_version()} (+https://github.com/ellacarmon/ai-guard)"


def _http_get_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": _http_user_agent()})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read().decode())


def _http_download(url: str, dest_path: str) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": _http_user_agent()})
    with urllib.request.urlopen(req, timeout=300) as resp:
        data = resp.read()
    with open(dest_path, "wb") as f:
        f.write(data)


class Fetcher:
    def __init__(self, target: Target, verbose: bool = False):
        self.target = target
        self.verbose = verbose
        self._temp_dir = None

    def fetch(self) -> str:
        """Returns the absolute path to the staged contents."""
        if self.target.type == TargetType.LOCAL_PATH:
            return os.path.abspath(self.target.raw)

        if self.target.type == TargetType.GITHUB_REPO:
            self._temp_dir = tempfile.TemporaryDirectory(prefix="ai_guard_")
            staging_path = self._temp_dir.name
            if self.verbose:
                click.echo(f"VERBOSE: Cloning {self.target.raw} into {staging_path}", err=True)

            cmd = ["git", "clone", "--depth", "1", "--quiet", self.target.raw, staging_path]
            try:
                subprocess.run(cmd, check=True, capture_output=not self.verbose)
                return staging_path
            except subprocess.CalledProcessError as e:
                click.echo(
                    click.style(
                        f"Error cloning repository: {e.stderr if e.stderr else e}",
                        fg="red",
                    ),
                    err=True,
                )
                raise

        if self.target.type == TargetType.NPM_PACKAGE:
            return self._fetch_npm_registry()

        if self.target.type == TargetType.PYPI_PACKAGE:
            return self._fetch_pypi_registry()

        raise ValueError(f"Unsupported target type: {self.target.type}")

    def _fetch_npm_registry(self) -> str:
        name = self.target.registry_spec
        if not name:
            raise ValueError("npm package name missing")

        self._temp_dir = tempfile.TemporaryDirectory(prefix="ai_guard_")
        staging_path = self._temp_dir.name
        encoded = quote(name, safe="")
        meta_url = f"https://registry.npmjs.org/{encoded}"

        if self.verbose:
            click.echo(f"VERBOSE: Fetching npm metadata {meta_url}", err=True)

        try:
            meta = _http_get_json(meta_url)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                click.echo(
                    click.style(f"npm package not found: {name!r}", fg="red"),
                    err=True,
                )
            raise

        latest = (meta.get("dist-tags") or {}).get("latest")
        if not latest:
            raise ValueError(f"npm package {name!r} has no dist-tags.latest")

        ver_obj = (meta.get("versions") or {}).get(latest)
        if not ver_obj:
            raise ValueError(f"npm package {name!r}: missing version {latest!r}")

        tarball_url = (ver_obj.get("dist") or {}).get("tarball")
        if not tarball_url:
            raise ValueError(f"npm package {name!r}: no tarball URL for {latest!r}")

        artifact = os.path.join(staging_path, "package.tgz")
        if self.verbose:
            click.echo(f"VERBOSE: Downloading npm tarball for {name}@{latest}", err=True)
        _http_download(tarball_url, artifact)
        extract_tar_archive(artifact, staging_path)
        try:
            os.remove(artifact)
        except OSError:
            pass
        return staging_path

    def _fetch_pypi_registry(self) -> str:
        name = self.target.registry_spec
        if not name:
            raise ValueError("PyPI package name missing")

        self._temp_dir = tempfile.TemporaryDirectory(prefix="ai_guard_")
        staging_path = self._temp_dir.name
        encoded = quote(name, safe="")
        meta_url = f"https://pypi.org/pypi/{encoded}/json"

        if self.verbose:
            click.echo(f"VERBOSE: Fetching PyPI metadata {meta_url}", err=True)

        try:
            meta = _http_get_json(meta_url)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                click.echo(
                    click.style(f"PyPI project not found: {name!r}", fg="red"),
                    err=True,
                )
            raise

        urls = meta.get("urls") or []
        sdist_tgz = [
            u
            for u in urls
            if u.get("packagetype") == "sdist"
            and (u.get("filename") or "").endswith(".tar.gz")
        ]
        wheels = [
            u
            for u in urls
            if u.get("packagetype") == "bdist_wheel" and (u.get("filename") or "").endswith(".whl")
        ]

        if sdist_tgz:
            chosen = sdist_tgz[0]
            suffix = ".tar.gz"
        elif wheels:
            chosen = wheels[0]
            suffix = ".whl"
        else:
            raise ValueError(
                f"PyPI project {name!r}: no .tar.gz sdist or .whl wheel in release urls"
            )

        file_url = chosen.get("url")
        if not file_url:
            raise ValueError(f"PyPI project {name!r}: artifact has no url")

        artifact = os.path.join(staging_path, f"artifact{suffix}")
        if self.verbose:
            click.echo(
                f"VERBOSE: Downloading {chosen.get('filename', 'artifact')} from PyPI",
                err=True,
            )
        _http_download(file_url, artifact)

        if suffix == ".tar.gz":
            extract_tar_archive(artifact, staging_path)
        else:
            extract_zip_archive(artifact, staging_path)
        try:
            os.remove(artifact)
        except OSError:
            pass
        return staging_path

    def cleanup(self):
        if self._temp_dir is not None:
            self._temp_dir.cleanup()
