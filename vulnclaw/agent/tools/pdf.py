"""PDF text/image extraction tool."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

from vulnclaw.agent.tools.subprocess_util import run_subprocess_capture

if TYPE_CHECKING:
    from vulnclaw.agent.agent_context import AgentContext


# ── PDF 文本提取封装（避免重复代码）────────────────────────────────────────────────────

_PDF_TOOL_NAMES = {"pdf_analyze"}

def extract_pdf_text(pdf_path: str, extract_images: bool = False) -> dict[str, Any]:
    """PDF 文本提取：优先 fitz（PyMuPDF），支持图片 OCR。
    
    Returns:
        {
            "success": bool,
            "text": str,
            "pages": int,
            "images": list[str],
            "error": str | None
        }
    """
    import fitz
    from pathlib import Path
    
    if not os.path.exists(pdf_path):
        return {
            "success": False,
            "text": "",
            "pages": 0,
            "images": [],
            "error": f"PDF not found: {pdf_path}",
        }
    
    try:
        doc = fitz.open(pdf_path)
        pages = len(doc)
        text = ""
        images = []
        
        for page in doc:
            # 提取文本
            text += page.get_text()
            
            # 如果需要提取图片
            if extract_images:
                for img in page.get_images():
                    xref = img[0]
                    base_image = doc.extract_image(xref)
                    if base_image:
                        images.append(base_image["image"])
        
        doc.close()
        
        return {
            "success": True,
            "text": text.strip(),
            "pages": pages,
            "images": images,
            "error": None,
        }
    except Exception as e:
        return {
            "success": False,
            "text": "",
            "pages": 0,
            "images": [],
            "error": str(e),
        }


def execute_pdf_analyze(agent: AgentContext, args: dict[str, Any]) -> str:
    """CTF 取证助手:提取 PDF 文本(优先 fitz/PyMuPDF),可按页输出并提取图片。

    适用于 PDF 里藏 flag、题面文字在 Flate 流中、图片版 PDF 等场景。
    """
    pdf_path = str(args.get("pdf_path", "")).strip()
    extract_images = bool(args.get("extract_images", False))
    page_limit = max(1, min(50, int(args.get("page_limit", 20))))
    if not pdf_path:
        return "[!] pdf_analyze requires 'pdf_path'"
    if not os.path.exists(pdf_path):
        return f"[!] pdf not found: {pdf_path}"

    try:
        import fitz  # PyMuPDF
    except ImportError:
        return "[!] PyMuPDF (fitz) not installed; pip install pymupdf"

    try:
        doc = fitz.open(pdf_path)
        total = len(doc)
        lines = [f"[pdf] {pdf_path} | {total} pages"]
        full_text = []
        for i, page in enumerate(doc[:page_limit]):
            txt = page.get_text().strip()
            img_info = ""
            if extract_images:
                imgs = page.get_images()
                if imgs:
                    img_info = f" | {len(imgs)} images"
            header = f"\n===== PAGE {i + 1}{img_info} ====="
            if txt:
                lines.append(header)
                lines.append(txt[:1500])
            elif img_info:
                lines.append(header + " (no text; images only — use ocr on rendered pages)")
            else:
                lines.append(header + " (empty)")
            full_text.append(txt)
        if total > page_limit:
            lines.append(f"\n[... {total - page_limit} more pages not shown; text still extracted below ...]")

        # 追加全部文本供后续搜索(不受 page_limit 截断)
        all_text = "\n".join(full_text)
        lines.append("\n=== FULL TEXT (page-limited) ===")
        lines.append(all_text[:4000])
        doc.close()
        return "\n".join(lines)
    except Exception as e:
        return f"[!] pdf_analyze failed: {str(e)[:200]}"
