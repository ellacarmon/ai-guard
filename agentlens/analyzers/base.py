from typing import List, Optional
from ..models.schema import Finding
from ..core import ProgressCallback


class BaseAnalyzer:
    def analyze(
        self,
        target_dir: str,
        progress_callback: Optional[ProgressCallback] = None,
    ) -> List[Finding]:
        """Runs the static analysis over the target directory and returns findings."""
        raise NotImplementedError
