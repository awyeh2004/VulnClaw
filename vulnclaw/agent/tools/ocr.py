"""Local OCR tool (easyocr / pytesseract / Windows.Media.Ocr) + vision-LLM fallback."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

from vulnclaw.agent.tools.subprocess_util import run_subprocess_capture

if TYPE_CHECKING:
    from vulnclaw.agent.agent_context import AgentContext


# ── OCR 工具（本地 GPU 加速）────────────────────────────────────────────────────


def _ocr_with_cached_reader(easyocr_module, image_path: str, lang: str) -> str:
    """Run easyocr on the image, reusing a process-wide cached Reader to avoid
    reloading the model on every call (GPU warm-up dominates single-shot cost)."""
    # The cache/lock intentionally remain module-global in builtin_tools.py (the
    # facade) rather than here: tests monkeypatch builtin_tools._OCR_READER_CACHE
    # to reset it, so the moved helper resolves both from that module at call time.
    from vulnclaw.agent.builtin_tools import _OCR_READER_CACHE, _OCR_READER_LOCK

    key = (lang, "en")
    reader = _OCR_READER_CACHE.get(key)
    if reader is None:
        with _OCR_READER_LOCK:
            reader = _OCR_READER_CACHE.get(key)
            if reader is None:
                reader = easyocr_module.Reader([lang], gpu=True)
                _OCR_READER_CACHE[key] = reader
    chunks = reader.readtext(image_path, detail=0)
    return " ".join(chunk for chunk in chunks if chunk)


def execute_ocr(agent: AgentContext, args: dict[str, Any]) -> str:
    """本地 OCR：优先 easyocr（GPU 加速），降级到 pytesseract/Windows.Media.Ocr，
    全部失败时可选降级到 vision LLM 理解图片。

    完全本地运行，无需外部 API。easyocr reader 进程内缓存复用，避免重复加载模型。

    Args:
        agent: Agent 上下文
        args: {"image_path": str, "method": str, "lang": str, "use_llm": bool, "prompt": str}
            - image_path: 图片路径（必需）
            - method: "auto"（默认）/"easyocr"/"pytesseract"/"windows"/"llm"
            - lang: 语言代码，默认 "en"（easyocr 支持 "ch_sim" 中文）
            - use_llm: 本地 OCR 全部失败时是否降级到 vision LLM（默认 true）
            - prompt: 覆盖 vision LLM 的默认“提取文字”指令。图形类题目（波形/频谱/
              二维码画出来的字）要传一句“描述这张图里画了什么、有没有字形”，否则
              模型只会找印刷体字符并回空。
    """
    image_path = str(args.get("image_path", "")).strip()
    method = str(args.get("method", "auto")).strip().lower()
    lang = str(args.get("lang", "en")).strip()
    use_llm = bool(args.get("use_llm", True))
    prompt = str(args.get("prompt", "") or "").strip() or None
    
    if not image_path:
        return "[!] ocr requires 'image_path'"
    
    # 检查文件是否存在
    if not os.path.exists(image_path):
        return f"[!] image not found: {image_path}"
    
    # 显式指定只用 vision LLM
    if method == "llm":
        vision = _ocr_via_vision_llm(image_path, prompt)
        return f"[+] vision-llm: {vision}" if vision else "[!] vision LLM OCR failed or no credentials"
    
    results = []
    
    # 尝试 easyocr（推荐，GPU 加速；进程内缓存 reader）
    if method in {"auto", "easyocr"}:
        try:
            import easyocr as _easyocr
        except ImportError:
            results.append("[!] easyocr not installed")
        else:
            try:
                text = _ocr_with_cached_reader(_easyocr, image_path, lang)
                if text.strip():
                    # NOTE (2026-10-19): this used to report a "confidence" computed as
                    # the share of alphabetic characters in the output. That is not a
                    # confidence -- it says nothing about whether the model read the
                    # image correctly, and it reads HIGHEST on exactly the wrong output.
                    # Measured on a synthetic image whose true text is
                    # ``flag{easyocr_ok}``: easyocr returned ``flagleasyccr_ok}``
                    # (two substitutions plus a dropped brace) and still scored 0.87.
                    # A fabricated number the model can quote is worse than none, so
                    # the value is gone and the caveat below replaces it.
                    results.append(
                        f"[+] easyocr: {text.strip()} "
                        "(no confidence score: OCR substitutes lookalike glyphs — "
                        "0/O, l/1, {/l, }/J — so a flag read from an image must be "
                        "confirmed against another source before submitting)"
                    )
                    if method == "easyocr":
                        return "\n".join(results)
            except Exception as e:
                results.append(f"[!] easyocr failed: {str(e)[:100]}")
    
    # 尝试 pytesseract
    if method in {"auto", "pytesseract"}:
        try:
            import pytesseract
            from PIL import Image
            img = Image.open(image_path)
            text = pytesseract.image_to_string(img, lang=lang).strip()
            if text:
                results.append(f"[+] pytesseract: {text}")
                if method == "pytesseract":
                    return "\n".join(results)
        except Exception as e:
            results.append(f"[!] pytesseract failed: {str(e)[:100]}")
    
    # 尝试 Windows.Media.Ocr（Windows 10/11 原生）
    if method in {"auto", "windows"}:
        try:
            ps_code = f"""
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.Storage.StorageFile,Windows.Storage,ContentType=WindowsRuntime] | Out-Null
$null=[Windows.ApplicationModel.Core.CoreApplication,Windows.ApplicationModel.Core,ContentType=WindowsRuntime] | Out-Null
$b=[Windows.Storage.StorageFile]::GetFileFromPathAsync('{image_path.replace(chr(92), chr(92)*2)}')
$r=await $b
$e=[Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
$a=await $e.RecognizeAsync($r)
$a.Text
"""
            result = run_subprocess_capture(
                ["powershell", "-Command", ps_code],
                timeout=10,
                errors="replace",
            )
            if result["success"] and result["stdout"].strip():
                results.append(f"[+] Windows OCR: {result['stdout'].strip()}")
        except Exception as e:
            results.append(f"[!] Windows OCR failed: {str(e)[:100]}")
    
    # 本地 OCR 全部无结果时, 降级到 vision LLM 理解图片内容
    if use_llm and not any(r.startswith("[+]") for r in results):
        vision = _ocr_via_vision_llm(image_path, prompt)
        if vision:
            results.append(f"[+] vision-llm: {vision}")
            if method in {"auto", "easyocr", "pytesseract", "windows"}:
                return "\n".join(results)
    
    if not results:
        return "[!] All OCR methods failed. Install easyocr for GPU-accelerated OCR."
    
    return "\n".join(results)


# Vision budget. Reasoning models spend ``max_tokens`` on ``reasoning_content``
# first, so a small budget returns HTTP 200 with an EMPTY ``content``. Measured
# 2026-10-28 against api.deepseek.com/v1 with deepseek-v4-flash-vision-exp on a
# waveform PNG: max_tokens=500 -> content "", reasoning_content 500 tokens
# (truncated mid-sentence); max_tokens=2000 -> content "NO_TEXT", 458 reasoning
# tokens. The old 500 silently turned every "read this image" step into a
# failure the caller could not distinguish from "no text in the image".
#
# An empty ``content`` is therefore always a truncated attempt, never an answer:
# a model that found nothing says so ("NO_TEXT") and that arrives as content.
# Budgets measured on a synthetic "flag{...}" image: 1500 -> "", 4000 -> text.
_VISION_MAX_TOKENS = 2000
_VISION_RETRY_MAX_TOKENS = 6000


def _vision_chat(
    base_url: str,
    api_key: str,
    model: str,
    text_prompt: str,
    image_url: str,
    max_tokens: int,
) -> tuple[str, dict]:
    """One vision request. Returns (content, diagnostics).

    An empty ``content`` means the completion budget ran out before the model
    emitted an answer (reasoning models spend it on ``reasoning_content`` first);
    the caller retries with a larger budget instead of reporting "no text".
    """
    import httpx

    r = httpx.post(
        f"{base_url}/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": text_prompt},
                        {"type": "image_url", "image_url": {"url": image_url}},
                    ],
                }
            ],
            "max_tokens": max_tokens,
        },
        timeout=120,
    )
    if r.status_code != 200:
        return "", {"status": r.status_code}
    data = r.json()
    message = ((data.get("choices") or [{}])[0] or {}).get("message") or {}
    content = (message.get("content") or "").strip()
    diag = {
        "status": r.status_code,
        "finish_reason": ((data.get("choices") or [{}])[0] or {}).get("finish_reason"),
        "reasoning_chars": len((message.get("reasoning_content") or "").strip()),
    }
    return content, diag


def _ocr_via_vision_llm(image_path: str, prompt: str | None = None) -> str:
    """Fallback OCR: ask a vision-capable LLM to read the image.

    Uses the configured vision model (``llm.vision_model``) via the
    OpenAI-compatible endpoint, independent of the agent's main model so an
    image-agnostic main model never breaks OCR. Returns the model's text answer,
    or an empty string on any failure (OCR must never crash the tool).

    ``prompt`` overrides the default "extract text" instruction, which is what
    drawing-type images need: a waveform/spectrogram render often has no glyphs
    to OCR, and the useful answer is a description ("NO_TEXT, this is a solid
    loud block") rather than a transcription.
    """
    import base64
    import mimetypes

    try:
        from vulnclaw.config.settings import load_config

        llm = load_config().llm
        api_key = getattr(llm, "api_key", "") or ""
        base_url = str(getattr(llm, "base_url", "") or "").rstrip("/")
        model = str(getattr(llm, "vision_model", "") or "deepseek-v4-flash-vision-exp")
        if not api_key:
            return ""
        # Vision fallback needs an OpenAI-compatible endpoint; DeepSeek and other
        # compatible providers work. Non-standard endpoints may not accept image
        # messages, so only attempt when base_url looks like an OpenAI-compatible
        # API (/v1 or /chat/completions convention).
        if "/v1" not in base_url and "/v4" not in base_url:
            return ""
    except Exception:
        return ""

    mime = mimetypes.guess_type(image_path)[0] or "image/png"
    try:
        with open(image_path, "rb") as f:
            b64 = base64.b64encode(f.read()).decode()
    except OSError:
        return ""

    text_prompt = prompt or (
        "Extract all readable text from this image verbatim. "
        "If it contains a flag or secret, output it exactly. "
        "Otherwise describe the visible content concisely."
    )
    image_url = f"data:{mime};base64,{b64}"
    try:
        for budget in (_VISION_MAX_TOKENS, _VISION_RETRY_MAX_TOKENS):
            content, _diag = _vision_chat(
                base_url, api_key, model, text_prompt, image_url, budget
            )
            if content:
                return content
        return ""
    except Exception:
        return ""
