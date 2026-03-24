"""Local prompt-injection classifier to rank which findings go to the semantic LLM."""

from __future__ import annotations

import os
from typing import List, Optional, Sequence, Union

# Default: small DeBERTa (~44M), LABEL_0=safe / LABEL_1=attack per model card.
DEFAULT_INJECTION_MODEL = "neuralchemy/prompt-injection-deberta"


class InjectionPrefilterImportError(ImportError):
    """Raised when transformers/torch are not installed."""


class PromptInjectionPrefilter:
    """Scores text snippets with a Hugging Face sequence-classification model (attack probability)."""

    def __init__(
        self,
        model_id: str = DEFAULT_INJECTION_MODEL,
        *,
        device: Optional[Union[int, str]] = None,
    ):
        self.model_id = model_id
        self._device = device
        self._pipe = None

    def _lazy_pipe(self):
        if self._pipe is not None:
            return self._pipe
        try:
            import torch
            from transformers import pipeline
        except ImportError as e:
            raise InjectionPrefilterImportError(
                "Prompt-injection prefilter requires optional dependencies. "
                'Install with: pip install "agentlens[injection-prefilter]"'
            ) from e

        if self._device is not None:
            dev: Union[int, str] = self._device
        else:
            env = os.environ.get("AI_GUARD_INJECTION_DEVICE", "").strip().lower()
            if env in ("cpu", "-1", ""):
                dev = -1
            elif env == "cuda" or env == "gpu":
                dev = 0 if torch.cuda.is_available() else -1
            else:
                try:
                    dev = int(env)
                except ValueError:
                    dev = -1

        self._pipe = pipeline(
            "text-classification",
            model=self.model_id,
            tokenizer=self.model_id,
            device=dev,
            truncation=True,
            max_length=256,
        )
        return self._pipe

    def warmup(self) -> None:
        """Eagerly load tokenizer and weights so missing deps fail before the scan continues."""
        self._lazy_pipe()

    @staticmethod
    def _attack_probability(row: object) -> float:
        """Extract P(attack) from one pipeline row (top_k=2 list of dicts)."""
        if not isinstance(row, list) or not row:
            return 0.0
        by_label = {str(d["label"]).upper(): float(d["score"]) for d in row}
        if "LABEL_1" in by_label:
            return by_label["LABEL_1"]
        if "LABEL_0" in by_label and len(by_label) == 2:
            return 1.0 - by_label["LABEL_0"]
        # Named labels: prefer anything that looks like attack / injection
        for lab, sc in by_label.items():
            low = lab.lower()
            if any(k in low for k in ("inject", "attack", "jailbreak", "unsafe", "malicious")):
                return sc
        return float(row[0]["score"]) if row else 0.0

    def score_texts(self, texts: Sequence[str]) -> List[float]:
        """Return attack/injection probability in [0, 1] for each string (batched)."""
        pipe = self._lazy_pipe()
        cleaned = [(t or "").strip() or " " for t in texts]
        if not cleaned:
            return []
        try:
            raw = pipe(list(cleaned), top_k=2)
        except TypeError:
            raw = pipe(list(cleaned))

        def row_for_one(
            batch: List[object],
        ) -> object:
            """Normalize pipeline output for a single input to a list of label dicts."""
            if not batch:
                return []
            if isinstance(batch[0], dict):
                return batch
            return batch[0]

        if len(cleaned) == 1:
            return [self._attack_probability(row_for_one(raw))]  # type: ignore[arg-type]

        out: List[float] = []
        if isinstance(raw, list) and len(raw) == len(cleaned):
            for r in raw:
                out.append(self._attack_probability(r if isinstance(r, list) else [r]))
            return out
        return [self._attack_probability(row_for_one(raw))] * len(cleaned)  # type: ignore[arg-type]
