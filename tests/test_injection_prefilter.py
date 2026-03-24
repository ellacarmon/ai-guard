import sys
import types

import pytest

from agentlens.analyzers.injection_prefilter import (
    InjectionPrefilterSecurityError,
    PromptInjectionPrefilter,
)


def test_prefilter_loads_model_with_safetensors_and_remote_code_disabled(monkeypatch):
    calls = {}

    class _FakeTokenizer:
        @staticmethod
        def from_pretrained(model_id, **kwargs):
            calls["tokenizer"] = (model_id, kwargs)
            return "tokenizer"

    class _FakeModel:
        @staticmethod
        def from_pretrained(model_id, **kwargs):
            calls["model"] = (model_id, kwargs)
            return "model"

    def _fake_pipeline(task, **kwargs):
        calls["pipeline"] = (task, kwargs)
        return object()

    fake_torch = types.SimpleNamespace(
        cuda=types.SimpleNamespace(is_available=lambda: False)
    )
    fake_transformers = types.SimpleNamespace(
        AutoTokenizer=_FakeTokenizer,
        AutoModelForSequenceClassification=_FakeModel,
        pipeline=_fake_pipeline,
    )

    monkeypatch.setitem(sys.modules, "torch", fake_torch)
    monkeypatch.setitem(sys.modules, "transformers", fake_transformers)

    prefilter = PromptInjectionPrefilter(model_id="secure/model")
    prefilter.warmup()

    assert calls["tokenizer"] == ("secure/model", {"trust_remote_code": False})
    assert calls["model"] == (
        "secure/model",
        {"use_safetensors": True, "trust_remote_code": False},
    )
    assert calls["pipeline"][0] == "text-classification"
    assert calls["pipeline"][1]["trust_remote_code"] is False


def test_prefilter_rejects_models_without_safetensors(monkeypatch):
    class _FakeTokenizer:
        @staticmethod
        def from_pretrained(model_id, **kwargs):
            return "tokenizer"

    class _FakeModel:
        @staticmethod
        def from_pretrained(model_id, **kwargs):
            raise OSError("no file named model.safetensors found")

    def _fake_pipeline(task, **kwargs):
        return object()

    fake_torch = types.SimpleNamespace(
        cuda=types.SimpleNamespace(is_available=lambda: False)
    )
    fake_transformers = types.SimpleNamespace(
        AutoTokenizer=_FakeTokenizer,
        AutoModelForSequenceClassification=_FakeModel,
        pipeline=_fake_pipeline,
    )

    monkeypatch.setitem(sys.modules, "torch", fake_torch)
    monkeypatch.setitem(sys.modules, "transformers", fake_transformers)

    prefilter = PromptInjectionPrefilter(model_id="unsafe/model")

    with pytest.raises(InjectionPrefilterSecurityError) as exc:
        prefilter.warmup()

    assert "must provide SafeTensors weights" in str(exc.value)
