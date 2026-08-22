"""Tests for the pdf forensics analysis tool.

Real-PDF tests run only when a PDF fixture is found under the configured
challenge work dir (``VULNCLAW_ATTACH_DIR`` / ``VULNCLAW_WORK_DIR``); otherwise
they skip so the suite stays green anywhere.
"""

import os

import pytest

from vulnclaw.agent.builtin_tools import execute_pdf_analyze, extract_pdf_text


class MockAgent:
    pass


def _work_dir() -> str:
    for key in ("VULNCLAW_ATTACH_DIR", "VULNCLAW_WORK_DIR"):
        val = os.environ.get(key, "").strip()
        if val:
            return val
    return os.path.expandvars(r"%USERPROFILE%\vulnclaw\work")


def _find_test_pdf() -> str:
    """Locate any PDF under the work dir to use as a fixture, else ''."""
    base = _work_dir()
    for root, _dirs, files in os.walk(base):
        for name in files:
            if name.lower().endswith(".pdf"):
                return os.path.join(root, name)
    return ""


TEST_PDF = _find_test_pdf()
_has_pdf = pytest.mark.skipif(not TEST_PDF, reason="no PDF fixture found in work dir")


def test_pdf_analyze_missing_path():
    r = execute_pdf_analyze(MockAgent(), {"pdf_path": r"E:\nope.pdf"})
    assert "not found" in r


@_has_pdf
def test_pdf_analyze_opens_real_pdf():
    r = execute_pdf_analyze(MockAgent(), {"pdf_path": TEST_PDF, "page_limit": 3})
    assert "[pdf]" in r
    assert "pages" in r


def test_pdf_analyze_requires_path():
    r = execute_pdf_analyze(MockAgent(), {})
    assert "pdf_path" in r


@_has_pdf
def test_extract_pdf_text_real_pdf():
    result = extract_pdf_text(TEST_PDF)
    assert result["success"] is True
    assert result["pages"] >= 1
