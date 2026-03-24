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
        self.type, self.registry_spec = self._classify(raw)

    def _classify(self, raw: str) -> tuple[TargetType, str | None]:
        # Registry prefixes first — do not treat npm:/pypi: as local paths.
        if raw.startswith("npm:"):
            spec = raw[4:].strip()
            if spec:
                return TargetType.NPM_PACKAGE, spec
            return TargetType.UNKNOWN, None

        if raw.startswith("pypi:"):
            spec = raw[5:].strip()
            if not spec:
                return TargetType.UNKNOWN, None
            # Strip PEP 508 extras: package[extra] -> package
            spec = re.split(r"\[", spec, maxsplit=1)[0].strip()
            if spec:
                return TargetType.PYPI_PACKAGE, spec
            return TargetType.UNKNOWN, None

        if raw.startswith("http://") or raw.startswith("https://"):
            parsed = urlparse(raw)
            if parsed.netloc == "github.com":
                return TargetType.GITHUB_REPO, None

        if os.path.exists(raw):
            return TargetType.LOCAL_PATH, None

        return TargetType.UNKNOWN, None
