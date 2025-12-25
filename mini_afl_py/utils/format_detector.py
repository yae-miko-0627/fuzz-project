"""FormatDetector

提供简单的文件格式检测器，通过扩展名与文件头/内容启发式判断常见格式。

返回的格式标识符示例： 'lua', 'mjs', 'png', 'jpeg', 'jpg', 'elf', 'pcap', 'xml', 'other'
"""
from pathlib import Path
from typing import Optional


def _by_extension(path: Path) -> Optional[str]:
    s = path.suffix.lower()
    if not s:
        return None
    if s in ('.lua',):
        return 'lua'
    if s in ('.mjs', '.js'):
        return 'mjs'
    if s in ('.png',):
        return 'png'
    if s in ('.jpg', '.jpeg'):
        return 'jpeg'
    if s in ('.pcap', '.pcapng'):
        return 'pcap'
    if s in ('.xml',):
        return 'xml'
    if s in ('.so', '.elf', '.bin', '.o', '.exe'):
        return 'elf'
    return None


def _by_magic(data: bytes) -> Optional[str]:
    if not data:
        return None
    # ELF
    if data.startswith(b"\x7fELF"):
        return 'elf'
    # PNG
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return 'png'
    # JPEG
    if data.startswith(b"\xff\xd8"):
        return 'jpeg'
    # PCAP (few magic variants)
    if len(data) >= 4:
        m_le = int.from_bytes(data[0:4], byteorder='little', signed=False)
        m_be = int.from_bytes(data[0:4], byteorder='big', signed=False)
        if m_le in (0xa1b2c3d4, 0xa1b23c4d) or m_be in (0xa1b2c3d4, 0xa1b23c4d):
            return 'pcap'
    # XML-ish
    txt = None
    try:
        txt = data.decode('utf-8', errors='ignore').lstrip()
    except Exception:
        txt = None
    if isinstance(txt, str):
        if txt.startswith('<?xml') or txt.startswith('<!DOCTYPE') or txt.startswith('<'):
            return 'xml'
        # heuristic for lua / js: look for typical tokens
        low = txt.lower()
        if 'function' in low and 'end' in low:
            return 'lua'
        if 'import ' in low or 'export ' in low or 'require(' in low:
            return 'mjs'

    return None


def detect_from_path(path: Path) -> str:
    """根据路径先尝试扩展名判断，然后读取前 1KB 做魔数/内容检测，返回格式字符串。"""
    ext = _by_extension(path)
    if ext:
        return ext
    try:
        with path.open('rb') as f:
            data = f.read(1024)
    except Exception:
        data = b''
    mg = _by_magic(data)
    if mg:
        return mg
    return 'other'


def detect_from_bytes(data: bytes) -> str:
    """从字节流检测格式并返回字符串标识。"""
    mg = _by_magic(data)
    if mg:
        return mg
    return 'other'


__all__ = ["detect_from_path", "detect_from_bytes"]
