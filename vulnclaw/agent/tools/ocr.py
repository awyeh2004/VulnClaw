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
        args: {"image_path": str, "method": str, "lang": str, "use_llm": bool}
            - image_path: 图片路径（必需）
            - method: "auto"（默认）/"easyocr"/"pytesseract"/"windows"
            - lang: 语言代码，默认 "en"（easyocr 支持 "ch_sim" 中文）
            - use_llm: 本地 OCR 全部失败时是否降级到 vision LLM（默认 true）
    """
    image_path = str(args.get("image_path", "")).strip()
    method = str(args.get("method", "auto")).strip().lower()
    lang = str(args.get("lang", "en")).strip()
    use_llm = bool(args.get("use_llm", True))
    
    if not image_path:
        return "[!] ocr requires 'image_path'"
    
    # 检查文件是否存在
    if not os.path.exists(image_path):
        return f"[!] image not found: {image_path}"
    
    # 显式指定只用 vision LLM
    if method == "llm":
        vision = _ocr_via_vision_llm(image_path)
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
                    confidence = len([c for c in text if c.isalpha()]) / max(len(text), 1)
                    results.append(f"[+] easyocr: {text.strip()} (confidence={confidence:.2f})")
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
        vision = _ocr_via_vision_llm(image_path)
        if vision:
            results.append(f"[+] vision-llm: {vision}")
            if method in {"auto", "easyocr", "pytesseract", "windows"}:
                return "\n".join(results)
    
    if not results:
        return "[!] All OCR methods failed. Install easyocr for GPU-accelerated OCR."
    
    return "\n".join(results)


def _ocr_via_vision_llm(image_path: str, prompt: str | None = None) -> str:
    """Fallback OCR: ask a vision-capable LLM to read the image.

    Uses the configured DeepSeek vision model (deepseek-v4-flash-vision-exp) via
    the OpenAI-compatible endpoint, independent of the agent's main model so an
    image-agnostic main model never breaks OCR. Returns the model's text answer,
    or an empty string on any failure (OCR must never crash the tool).
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
    with open(image_path, "rb") as f:
        b64 = base64.b64encode(f.read()).decode()

    text_prompt = prompt or (
        "Extract all readable text from this image verbatim. "
        "If it contains a flag or secret, output it exactly. "
        "Otherwise describe the visible content concisely."
    )
    try:
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
                            {
                                "type": "image_url",
                                "image_url": {"url": f"data:{mime};base64,{b64}"},
                            },
                        ],
                    }
                ],
                "max_tokens": 500,
            },
            timeout=60,
        )
        if r.status_code != 200:
            return ""
        data = r.json()
        return (data["choices"][0]["message"].get("content") or "").strip()
    except Exception:
        return ""
