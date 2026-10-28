"""Vision route: the model cannot see images, and the OCR fallback was silent.

Measured 2026-10-28 on DASBOOK 7.3.3 波形图 (CTF2 practice): four consecutive
runs rendered waveform and spectrogram PNGs and then tried to "read the image"
in text -- numpy pixel dumps, ASCII art, histogram thresholds. None called the
``ocr`` tool, which is the only path from an image to words, and the two
reasons it looked dead are pinned here:

* ``_ocr_via_vision_llm`` sent ``max_tokens: 500`` to a reasoning model. The
  budget went to ``reasoning_content`` and ``content`` came back empty with
  HTTP 200 -- a silent failure indistinguishable from "no text in the image".
  Measured on api.deepseek.com/v1 + deepseek-v4-flash-vision-exp: 500 -> "",
  2000 -> "NO_TEXT", and on a synthetic ``flag{...}`` PNG 1500 -> "", 4000 ->
  the flag. Hence: empty content is always retried with a bigger budget.
* the tool exposed no ``prompt``, so callers could only ask "extract text" --
  useless for letters *drawn* in a waveform.

These tests use a fake ``_vision_chat`` so they neither spend quota nor need a
network.
"""

from __future__ import annotations

import vulnclaw.agent.tools.ocr as ocr
from vulnclaw.agent.solver import _vision_route_instruction


def _write_png(tmp_path):
    from PIL import Image

    path = tmp_path / "img.png"
    Image.new("RGB", (8, 8), "white").save(path)
    return str(path)


def _patch_config(monkeypatch, *, base_url="https://api.example.com/v1", api_key="k"):
    class _LLM:
        pass

    llm = _LLM()
    llm.api_key = api_key
    llm.base_url = base_url
    llm.vision_model = "vision-test"

    class _Cfg:
        pass

    cfg = _Cfg()
    cfg.llm = llm

    import vulnclaw.config.settings as settings

    monkeypatch.setattr(settings, "load_config", lambda: cfg, raising=False)


def test_empty_content_is_retried_with_a_larger_budget(monkeypatch, tmp_path):
    _patch_config(monkeypatch)
    budgets: list[int] = []

    def fake_chat(base_url, api_key, model, prompt, image_url, max_tokens):
        budgets.append(max_tokens)
        # First attempt: reasoning ate the whole budget (content empty).
        if len(budgets) == 1:
            return "", {"status": 200, "finish_reason": "length", "reasoning_chars": 900}
        return "flag{read_from_pixels}", {"status": 200}

    monkeypatch.setattr(ocr, "_vision_chat", fake_chat)
    out = ocr._ocr_via_vision_llm(_write_png(tmp_path))

    assert out == "flag{read_from_pixels}"
    assert len(budgets) == 2
    assert budgets[1] > budgets[0]


def test_a_real_answer_is_not_retried(monkeypatch, tmp_path):
    _patch_config(monkeypatch)
    calls: list[int] = []

    def fake_chat(*args):
        calls.append(args[-1])
        return "NO_TEXT", {"status": 200}

    monkeypatch.setattr(ocr, "_vision_chat", fake_chat)
    assert ocr._ocr_via_vision_llm(_write_png(tmp_path)) == "NO_TEXT"
    assert len(calls) == 1


def test_both_attempts_empty_returns_empty(monkeypatch, tmp_path):
    _patch_config(monkeypatch)

    monkeypatch.setattr(ocr, "_vision_chat", lambda *a: ("", {"status": 200}))
    assert ocr._ocr_via_vision_llm(_write_png(tmp_path)) == ""


def test_execute_ocr_passes_prompt_and_method_llm(monkeypatch, tmp_path):
    seen: dict = {}

    def fake_vision(image_path, prompt=None):
        seen["path"] = image_path
        seen["prompt"] = prompt
        return "NO_TEXT, a solid block"

    monkeypatch.setattr(ocr, "_ocr_via_vision_llm", fake_vision)
    path = _write_png(tmp_path)
    out = ocr.execute_ocr(
        object(),
        {
            "image_path": path,
            "method": "llm",
            "prompt": "Is any letter shaped in this waveform?",
        },
    )
    assert seen["path"] == path
    assert seen["prompt"] == "Is any letter shaped in this waveform?"
    assert "NO_TEXT" in out


def test_vision_route_block_names_the_tool_and_the_caveat():
    text = _vision_route_instruction("[7.3.3 波形图]04 波形 音频")
    assert "Looking at images" in text
    assert "method=llm" in text
    assert "no direct vision" in text
    # Reading pixels is explicitly not a substitute for looking.
    assert "ASCII art" in text


def test_vision_route_block_covers_image_goals_but_not_code_goals():
    assert _vision_route_instruction("图片隐写 challenge") != ""
    assert _vision_route_instruction("scan 192.168.1.10 for open ports") == ""
    assert _vision_route_instruction("") == ""
