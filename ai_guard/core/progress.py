"""Progress reporting for the ai-guard scan pipeline."""

import sys
import time
import click
from typing import Callable, Optional

# Callback signature: (file_path: str, finding_count: int) -> None
ProgressCallback = Callable[[str, int], None]


class ProgressReporter:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self._is_tty: bool = sys.stderr.isatty()
        self._phase_start_time: Optional[float] = None
        self._current_phase: Optional[str] = None
        self._scan_start_time: float = time.monotonic()

    def _emit(self, message: str, nl: bool = True) -> None:
        """Write to stderr, silently ignoring OSError so the scan continues."""
        try:
            click.echo(message, err=True, nl=nl)
        except OSError:
            pass

    def phase_start(self, phase: str, message: str) -> None:
        """Emit '[phase] message' and record start time."""
        self._current_phase = phase
        self._phase_start_time = time.monotonic()
        self._emit(f"[{phase}] {message}")

    def phase_end(self, phase: str) -> None:
        """Emit '[phase] done (Xs)' with elapsed time since phase_start."""
        if self._phase_start_time is not None:
            elapsed = time.monotonic() - self._phase_start_time
        else:
            elapsed = 0.0
        self._emit(f"[{phase}] done ({elapsed:.1f}s)")

    def file_progress(
        self,
        phase: str,
        processed: int,
        total: int,
        file_path: Optional[str] = None,
        finding_count: Optional[int] = None,
    ) -> None:
        """
        Emit/overwrite the progress indicator.
        - TTY: use carriage return to overwrite in place.
        - Non-TTY: emit a new line per file.
        - verbose=True: also emit file_path and finding_count on separate lines.
        """
        line = f"[{phase}] {processed}/{total} files"
        if self._is_tty:
            self._emit(f"\r{line}", nl=False)
        else:
            self._emit(line)

        if self.verbose:
            if file_path is not None:
                self._emit(f"  \u2192 {file_path}")
            if finding_count is not None:
                self._emit(f"    {finding_count} findings")

    def progress_done(self, phase: str) -> None:
        """Emit a final newline after the last file in a phase."""
        self._emit("")

    def summary(self, total_files: int, total_findings: int) -> None:
        """Emit 'Scan complete: N files, M findings, Xs'."""
        elapsed = time.monotonic() - self._scan_start_time
        self._emit(
            f"Scan complete: {total_files} files, {total_findings} findings, {elapsed:.1f}s"
        )

    def error_summary(self, phase: str) -> None:
        """Emit error summary line with phase name and elapsed time."""
        elapsed = time.monotonic() - self._scan_start_time
        self._emit(f"Scan failed in [{phase}] after {elapsed:.1f}s")

    def debug(self, message: str) -> None:
        """Emit a debug line to stderr when verbose mode is enabled."""
        if self.verbose:
            self._emit(f"[debug] {message}")
