"""Local OCR tool (easyocr / pytesseract) + vision-LLM fallback."""

from __future__ import annotations

import os
import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from vulnclaw.agent.agent_context import AgentContext


# ── OCR 工具（本地 GPU 加速）────────────────────────────────────────────────────

#: Cached answer for "can easyocr run on this machine's GPU?".
#: ``torch.cuda.is_available()`` initialises the CUDA context (~0.5 s) and the
#: answer cannot change inside a process, so it is asked once.
_CUDA_AVAILABLE: bool | None = None


def _cuda_available() -> bool:
    """Whether a CUDA build of torch with a visible device is importable.

    easyocr is asked for ``gpu=<this>`` instead of a hardcoded ``True``. On a
    CPU-only torch (teammates' laptops, CI) ``gpu=True`` only makes easyocr print
    "Neither CUDA nor MPS are available" and fall back to CPU anyway, so the flag
    costs nothing either way -- but asking torch directly keeps the log honest and
    lets a future caller distinguish "no GPU here" from "GPU rejected the work".
    """
    global _CUDA_AVAILABLE
    if _CUDA_AVAILABLE is None:
        try:
            import torch

            _CUDA_AVAILABLE = bool(torch.cuda.is_available())
        except Exception:
            _CUDA_AVAILABLE = False
    return _CUDA_AVAILABLE


#: A complete flag-shaped token: a word-ish prefix, balanced braces, printable body.
#: Spaces inside the braces are allowed on purpose -- OCR inserts them
#: (``DASCTF{test_ 123}`` is a real read of ``DASCTF{test_123}``), and treating
#: that as "mangled" would escalate to the vision model on every such read.
_FLAG_COMPLETE_RE = re.compile(r"(?<![A-Za-z0-9_])([A-Za-z][A-Za-z0-9_]{1,15})\{[^{}\n]{2,}\}")

#: A *failed attempt* at a flag token: the word is glued straight onto a brace or
#: onto more word characters before any brace appears -- ``flagleasyccr_ok}``
#: (dropped brace) or ``flag{easyocr_ok`` (missing close). Prose mentions
#: ("submit the flag") have a separator after the word and must NOT match.
_FLAG_ATTEMPT_RE = re.compile(
    r"(?<![A-Za-z0-9_])(flag|ctf|dasctf|ctf2|qwb)[A-Za-z0-9_{}]", re.IGNORECASE
)


def _flag_read_is_suspect(reads: list[str]) -> bool:
    """True when a local engine read something flag-shaped but not flag-valid.

    This is the "the first engine answered, but the answer may be wrong" case that
    a short-circuit would silently lose. Measured 2026-10-30: easyocr read the
    synthetic truth ``flag{easyocr_ok}`` as ``flagleasyccr_ok}`` -- two glyph
    substitutions plus a dropped brace. That string is a plausible flag to a
    model, fails every platform's judge, and used to be returned as a success.
    """
    if any(_FLAG_COMPLETE_RE.search(text) for text in reads):
        return False
    return any(_FLAG_ATTEMPT_RE.search(text) for text in reads)


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
                reader = easyocr_module.Reader([lang], gpu=_cuda_available())
                _OCR_READER_CACHE[key] = reader
    chunks = reader.readtext(image_path, detail=0)
    return " ".join(chunk for chunk in chunks if chunk)


def execute_ocr(agent: AgentContext, args: dict[str, Any]) -> str:
    """本地 OCR：优先 easyocr（GPU 加速），可选 pytesseract，必要时用 vision LLM 复核。

    easyocr reader 进程内缓存复用，避免重复加载模型。

    两个降级条件（都只在 ``method="auto"`` 下生效）：

    * 本地引擎**一个都没读到字** → 交给 vision LLM；
    * 本地读到的字**看起来是 flag 但格式不合法**（缺花括号 / 前缀被粘连成
      ``flagleasyccr_ok}``）→ 也交给 vision LLM 复核。这条是"有输出 ≠ 读对了"的
      落地：OCR 的典型错误是字形替换（0/O、l/1、{/l），而这种错误恰好会把 flag
      读成一个**看着像却永远提交不通过**的串。以前只在"完全读不到"时才升级，
      于是一个被读坏的 flag 会被当成成功结果返回。

    Args:
        agent: Agent 上下文
        args: {"image_path": str, "method": str, "lang": str, "use_llm": bool, "prompt": str}
            - image_path: 图片路径（必需）
            - method: "auto"（默认）/"easyocr"/"pytesseract"/"llm"
            - lang: 语言代码，默认 "en"（easyocr 支持 "ch_sim" 中文）
            - use_llm: 本地读不到、或读出的 flag 可疑时，是否用 vision LLM 复核（默认 true）
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
    # Text each local engine actually read (no caveat suffix): the flag-plausibility
    # check below must look at the read, not at this module's own prose.
    local_reads: list[str] = []

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
                    local_reads.append(text)
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
                local_reads.append(text)
                results.append(f"[+] pytesseract: {text}")
                if method == "pytesseract":
                    return "\n".join(results)
        except Exception as e:
            results.append(f"[!] pytesseract failed: {str(e)[:100]}")
    
    # Windows.Media.Ocr 分支已删除（2026-10-30 实测）：它用 `await $b`，而
    # PowerShell 5.1 没有 await 关键字（`await : 无法将"await"项识别为 cmdlet`），
    # 所以它**从未产出过任何文本**，只花 0.2–0.4 s（PowerShell 启动），并且失败时
    # 连 `[!]` 行都不写，静默得像"这台机器没有第二个引擎"。真要用 WinRT 得走
    # `[System.WindowsRuntimeSystemExtensions]` 的 AsTask 反射 + BitmapDecoder
    # 解成 SoftwareBitmap；本机实测只有 ja / zh-Hans-CN 两个 OCR 包（无 en-US），
    # 读 ASCII flag 会得到 `password` -> `囚 氛 vord` 这种结果，作为第二个意见不可信。
    # 需要时按上述两条注意点重建，别直接抄原来的 await 写法。

    # 本地引擎给出结果时也要判断"读得对不对"：OCR 最典型的错误是字形替换
    # （0/O、l/1、{/l），恰好把 flag 读成"看着像、提交不通过"的串。
    suspect = _flag_read_is_suspect(local_reads)

    # 本地全部无结果、或读出的 flag 可疑时，降级到 vision LLM 复核
    if use_llm and (not any(r.startswith("[+]") for r in results) or suspect):
        vision = _ocr_via_vision_llm(image_path, prompt)
        if vision:
            note = (
                " (cross-check: the local read looks like a mangled flag — "
                "glyph substitutions drop or move braces; prefer this reading)"
                if suspect
                else ""
            )
            results.append(f"[+] vision-llm{note}: {vision}")
            if method in {"auto", "easyocr", "pytesseract"}:
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
