import os
import re
from enum import Enum
from urllib.parse import urlparse


class TargetType(Enum):
    GITHUB_REPO = "github_repo"
    LOCAL_PATH = "local_path"
    NPM_PACKAGE = "npm_package"
    PYPI_PACKAGE = "pypi_package"
    UNKNOWN = "unknown"


class Target:
    def __init__(self, raw: str):
        self.raw = raw
        self.registry_spec: str | None = None
        self.requested_version: str | None = None
        self.type, self.registry_spec, self.requested_version = self._classify(raw)

    def _classify(self, raw: str) -> tuple[TargetType, str | None, str | None]:
        # Registry prefixes first — do not treat npm:/pypi: as local paths.
        if raw.startswith("npm:"):
            spec = raw[4:].strip()
            if spec:
                package_name, version = self._parse_npm_spec(spec)
                if package_name:
                    return TargetType.NPM_PACKAGE, package_name, version
            return TargetType.UNKNOWN, None, None

        if raw.startswith("pypi:"):
            spec = raw[5:].strip()
            if not spec:
                return TargetType.UNKNOWN, None, None
            package_name, version = self._parse_pypi_spec(spec)
            if package_name:
                return TargetType.PYPI_PACKAGE, package_name, version
            return TargetType.UNKNOWN, None, None

        if raw.startswith("http://") or raw.startswith("https://"):
            parsed = urlparse(raw)
            if parsed.netloc == "github.com":
                return TargetType.GITHUB_REPO, None, None

        if os.path.exists(raw):
            return TargetType.LOCAL_PATH, None, None

        return TargetType.UNKNOWN, None, None

    @staticmethod
    def _parse_npm_spec(spec: str) -> tuple[str | None, str | None]:
        spec = spec.strip()
        if not spec:
            return None, None

        if spec.startswith("@"):
            if "@" in spec[1:]:
                package_name, version = spec.rsplit("@", maxsplit=1)
                if package_name and version:
                    return package_name, version.strip() or None
            return spec, None

        if "@" in spec:
            package_name, version = spec.rsplit("@", maxsplit=1)
            if package_name and version:
                return package_name.strip(), version.strip() or None
        return spec, None

    @staticmethod
    def _parse_pypi_spec(spec: str) -> tuple[str | None, str | None]:
        parts = spec.split("==", maxsplit=1)
        package_name = re.split(r"\[", parts[0].strip(), maxsplit=1)[0].strip()
        if not package_name:
            return None, None
        version = parts[1].strip() if len(parts) == 2 else None
        return package_name, version or None
