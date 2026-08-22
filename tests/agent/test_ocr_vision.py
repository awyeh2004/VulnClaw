"""Tests for the OCR vision-LLM fallback (local OCR -> vision model).

These tests do NOT hit the real network or require real credentials. The
config used by the fallback is monkeypatched, and the HTTP call is stubbed,
so the suite is hermetic and green on any machine.
"""

import pytest

from vulnclaw.agent.builtin_tools import execute_ocr


class MockAgent:
    pass


TEST_IMG = r"E:\vulnclaw\test\test_ocr.png"


class _LLM:
    api_key = "sk-test-vision"
    base_url = "https://api.deepseek.com/v1"
    vision_model = "deepseek-v4-flash-vision-exp"


class _Config:
    llm = _LLM()


@pytest.fixture
def fake_deepseek_config(monkeypatch):
    import vulnclaw.config.settings as settings

    monkeypatch.setattr(settings, "load_config", lambda: _Config())


@pytest.fixture
def stub_vision_http(monkeypatch):
    """Stub httpx.post so the fallback returns a canned answer."""
    import vulnclaw.agent.builtin_tools as bt

    class _Resp:
        status_code = 200

        def json(self):
            return {"choices": [{"message": {"content": "DASCTF{vision_ok}"}}]}

    def fake_post(url, **kwargs):
        return _Resp()

    monkeypatch.setattr(bt.httpx, "post", fake_post)


def test_ocr_llm_only_mode(fake_deepseek_config, stub_vision_http):
    r = execute_ocr(MockAgent(), {"image_path": TEST_IMG, "method": "llm"})
    assert r.startswith("[+] vision-llm:")


def test_ocr_vision_fallback_fires_when_local_fails(fake_deepseek_config, stub_vision_http):
    # Point at a file easyocr cannot read (a corrupt/empty png) so local OCR
    # produces nothing and the vision fallback kicks in.
    import os

    empty = os.path.join(os.path.dirname(TEST_IMG), "empty_test.png")
    with open(empty, "wb") as f:
        f.write(b"not a real image")

    r = execute_ocr(MockAgent(), {"image_path": empty, "method": "auto", "use_llm": True})
    assert "vision-llm" in r
    os.unlink(empty)


def test_ocr_auto_prefers_local_when_it_works(fake_deepseek_config):
    # Real easyocr on the simple image; even without stubbing HTTP, easyocr
    # wins so no network is touched.
    r = execute_ocr(MockAgent(), {"image_path": TEST_IMG, "method": "auto"})
    assert r.startswith("[+] easyocr:")


def test_ocr_missing_image():
    r = execute_ocr(MockAgent(), {"image_path": r"E:\nope.png"})
    assert "not found" in r


def test_ocr_vision_no_credentials_safe(monkeypatch):
    import vulnclaw.agent.builtin_tools as bt
    import vulnclaw.config.settings as settings

    class _NoCreds:
        llm = type("LLM", (), {"api_key": "", "base_url": "", "vision_model": ""})()

    monkeypatch.setattr(settings, "load_config", lambda: _NoCreds())
    r = bt._ocr_via_vision_llm(TEST_IMG)
    assert r == ""
