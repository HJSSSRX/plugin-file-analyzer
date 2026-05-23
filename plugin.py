from __future__ import annotations

"""File Analyzer Cell — file type detection, entropy, and timeline tools."""

import math
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from forhacker.plugin.base import BasePlugin, Tool

# Common file signatures (magic bytes): extension -> (offset, bytes)
SIGNATURES: dict[str, tuple[int, bytes]] = {
    "exe": (0, b"MZ"),
    "zip": (0, b"PK\x03\x04"),
    "docx": (0, b"PK\x03\x04"),
    "pdf": (0, b"%PDF"),
    "png": (0, b"\x89PNG\r\n\x1a\n"),
    "jpg": (0, b"\xff\xd8\xff"),
    "gif": (0, b"GIF87a"),
    "gif2": (0, b"GIF89a"),
    "bmp": (0, b"BM"),
    "rar": (0, b"Rar!\x1a\x07"),
    "7z": (0, b"7z\xbc\xaf'\x1c"),
    "gz": (0, b"\x1f\x8b"),
    "elf": (0, b"\x7fELF"),
    "sqlite": (0, b"SQLite format 3\x00"),
    "ole2": (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),
    "evtx": (0, b"ElfFile\x00"),
    "prefetch": (0, b"SCCA"),
}


class FileAnalyzerPlugin(BasePlugin):
    name = "file-analyzer"
    version = "0.1.0"
    domain = "forensics"
    risk_levels = {
        "detect_file_type": "LOW",
        "calculate_entropy": "LOW",
        "file_timeline": "LOW",
    }

    def register_tools(self) -> list[Tool]:
        return [
            Tool(
                name="detect_file_type",
                description="Detect file type via magic bytes and extension",
                domain="forensics",
                risk_level="LOW",
            ),
            Tool(
                name="calculate_entropy",
                description="Calculate Shannon entropy to detect packed/encrypted content",
                domain="forensics",
                risk_level="LOW",
            ),
            Tool(
                name="file_timeline",
                description="Collect MAC timestamps for timeline analysis",
                domain="forensics",
                risk_level="LOW",
            ),
        ]


def run_detect_file_type(target: str) -> dict[str, Any]:
    """Detect file type by magic bytes. Works on any file, Windows or Linux."""
    path = Path(target)
    if not path.exists():
        return {"error": f"File not found: {target}"}
    if not path.is_file():
        return {"error": f"Not a regular file: {target}"}

    data = path.read_bytes()[:16]
    detections = []
    for name, (offset, sig) in SIGNATURES.items():
        if data[offset : offset + len(sig)] == sig:
            detections.append(name)

    return {
        "file": str(path.absolute()),
        "size": path.stat().st_size,
        "extension": path.suffix.lower(),
        "magic_matches": detections,
        "likely_type": detections[0] if detections else "unknown",
    }


def run_calculate_entropy(target: str, block_size: int = 4096) -> dict[str, Any]:
    """Calculate Shannon entropy. High entropy (>7.5) suggests packed/encrypted data."""
    path = Path(target)
    if not path.exists():
        return {"error": f"File not found: {target}"}

    data = path.read_bytes()
    if not data:
        return {"file": str(path.absolute()), "entropy": 0.0, "verdict": "empty"}

    # Overall file entropy
    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)

    # Block-level entropy (for detecting mixed content)
    block_entropies = []
    for i in range(0, len(data), block_size):
        block = data[i : i + block_size]
        if not block:
            continue
        bc = Counter(block)
        bt = len(block)
        be = 0.0
        for c in bc.values():
            bp = c / bt
            be -= bp * math.log2(bp)
        block_entropies.append(round(be, 4))

    verdict = "normal"
    if entropy > 7.5:
        verdict = "likely_encrypted_or_packed"
    elif entropy < 3.0:
        verdict = "low_entropy_text_or_sparse"

    return {
        "file": str(path.absolute()),
        "size": total,
        "entropy": round(entropy, 4),
        "max_block_entropy": max(block_entropies) if block_entropies else 0.0,
        "verdict": verdict,
    }


def run_file_timeline(directory: str) -> dict[str, Any]:
    """Collect MAC timestamps for all files in a directory."""
    root = Path(directory)
    if not root.exists():
        return {"error": f"Directory not found: {directory}"}

    entries: list[dict[str, Any]] = []
    for fpath in root.rglob("*"):
        if not fpath.is_file():
            continue
        st = fpath.stat()
        entries.append(
            {
                "path": str(fpath.relative_to(root)),
                "size": st.st_size,
                "modified": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
                "accessed": datetime.fromtimestamp(st.st_atime, tz=timezone.utc).isoformat(),
                "created": datetime.fromtimestamp(st.st_ctime, tz=timezone.utc).isoformat(),
            }
        )

    entries.sort(key=lambda e: e["modified"], reverse=True)
    return {
        "directory": str(root.absolute()),
        "file_count": len(entries),
        "entries": entries[:500],
    }
