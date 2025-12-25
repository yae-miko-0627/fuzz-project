"""
XML 特殊变异器

功能：
- 识别并保护 XML prolog（<?xml ... ?>）、DOCTYPE、注释（<!-- -->）与 CDATA（<![CDATA[...]]>）区域；
- 识别并保护可能为校验和的字段（常见 hex 长度，如 32/40/64），避免变异这些字段；
- 对文本节点与属性值进行变异，但在输出前保证必要的 XML 转义（& < > " '）；
- 对变体进行基本的 well-formedness 校验（使用 xml.etree.ElementTree 尝试解析），仅在解析通过时产出变体；
- 在变异时复用已有的基础变异器（Havoc/Interest/Arith），并提供每个可变 span 的上限控制。

实现为保守策略：不尝试修复或重写复杂校验和，仅跳过这些字段以保证结构与校验字段不被破坏。
"""
from __future__ import annotations

import re
import random
from typing import Iterable, List, Optional, Tuple
import xml.etree.ElementTree as ET

from .havoc_mutator import HavocMutator
from .interest_mutator import InterestMutator
from .arith_mutator import ArithMutator


# 常见校验和模式：纯十六进制字符串长度为 32/40/64
CHECKSUM_RE = re.compile(r"\b[0-9a-fA-F]{32}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{64}\b")


def _decode_text(data: bytes) -> Optional[str]:
    try:
        return data.decode('utf-8')
    except Exception:
        try:
            return data.decode('latin-1')
        except Exception:
            return None


def _escape_xml(s: str) -> str:
    # 保证 &, <, >, ", ' 被正确转义
    s = s.replace('&', '&amp;')
    s = s.replace('<', '&lt;')
    s = s.replace('>', '&gt;')
    s = s.replace('"', '&quot;')
    s = s.replace("'", '&apos;')
    return s


def _unescape_xml(s: str) -> str:
    # 仅用于在内存中修改前把转义转换回字符
    s = s.replace('&apos;', "'")
    s = s.replace('&quot;', '"')
    s = s.replace('&gt;', '>')
    s = s.replace('&lt;', '<')
    s = s.replace('&amp;', '&')
    return s


def _find_protected_spans(text: str) -> List[Tuple[int, int]]:
    """返回需要保护的不变区间（start, end）用于后续避免变异。

    保护：XML prolog, DOCTYPE, comments, CDATA 区域。
    """
    spans: List[Tuple[int, int]] = []
    # XML prolog（声明）
    m = re.search(r'<\?xml[^>]*\?>', text, flags=re.IGNORECASE)
    if m:
        spans.append((m.start(), m.end()))
    # DOCTYPE 声明
    m = re.search(r'<!DOCTYPE[^>]*>', text, flags=re.IGNORECASE | re.DOTALL)
    if m:
        spans.append((m.start(), m.end()))
    # 注释
    for m in re.finditer(r'<!--.*?-->', text, flags=re.DOTALL):
        spans.append((m.start(), m.end()))
    # CDATA 区段
    for m in re.finditer(r'<!\[CDATA\[.*?\]\]>', text, flags=re.DOTALL):
        spans.append((m.start(), m.end()))
    # 合并并排序
    spans.sort()
    merged: List[Tuple[int, int]] = []
    for s, e in spans:
        if not merged or s > merged[-1][1]:
            merged.append((s, e))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], e))
    return merged


def _is_in_spans(pos: int, spans: List[Tuple[int, int]]) -> bool:
    for s, e in spans:
        if s <= pos < e:
            return True
    return False


class XmlMutator:
    """XML 专用变异器。

    参数:
      mutators: 基础变异器列表（按优先顺序）
      per_span_limit: 每个可变 span 的最大产出数
      max_variants: 全局最大产出数
    """

    def __init__(self, mutators: Optional[List] = None, per_span_limit: int = 50, max_variants: int = 200):
        if mutators is None:
            mutators = [HavocMutator(rounds=4, max_changes=4), InterestMutator(max_positions=64), ArithMutator(max_positions=32)]
        self.mutators = mutators
        self.per_span_limit = int(per_span_limit)
        self.max_variants = int(max_variants)

    def mutate(self, data: bytes) -> Iterable[bytes]:
        text = _decode_text(data)
        if text is None:
            return

        protected = _find_protected_spans(text)

        # 我们把可变区域限定为：属性值与文本节点，但排除受保护的 spans 和 checksum-like 字段
        variants = 0

        # 1) 属性值变异：匹配 key="value" 或 key='value'
        for m in re.finditer(r"([a-zA-Z_:][a-zA-Z0-9_:\-\.]*)\s*=\s*(\"([^\"]*)\"|'([^']*)')", text):
            if variants >= self.max_variants:
                break
            attr_start, attr_end = m.start(2), m.end(2)
            # 内容区位
            # value 分组可能在第 3 或第 4 组；获取内部内容的索引范围
            if m.group(3) is not None:
                inner = (m.start(3), m.end(3))
            else:
                inner = (m.start(4), m.end(4))
            # 跳过受保护区
            if _is_in_spans(inner[0], protected):
                continue
            val_text = text[inner[0]:inner[1]]
            # 跳过 checksum-like 值
            if CHECKSUM_RE.fullmatch(val_text.strip()):
                continue

            per_span = 0
            for mut in self.mutators:
                if variants >= self.max_variants or per_span >= self.per_span_limit:
                    break
                try:
                    # 将属性值传给 mutator（bytes）
                    for v in mut.mutate(val_text.encode('utf-8', errors='ignore')):
                        if variants >= self.max_variants or per_span >= self.per_span_limit:
                            break
                        try:
                            v_text = v.decode('utf-8')
                        except Exception:
                            v_text = v.decode('latin-1', errors='ignore')
                        # 保护 checksum-like（若变更后仍匹配则跳过）
                        if CHECKSUM_RE.fullmatch(v_text.strip()):
                            continue
                        # 转义并构造新文档
                        v_text_escaped = _escape_xml(v_text)
                        new_doc = text[:inner[0]] + v_text_escaped + text[inner[1]:]
                        # 校验是否为良构（well-formed）XML
                        try:
                            ET.fromstring(new_doc)
                        except Exception:
                            continue
                        yield new_doc.encode('utf-8')
                        variants += 1
                        per_span += 1
                except Exception:
                    continue

        # 2) 文本节点变异（内容在 > ... < 之间，但排除标签、受保护的 spans 以及前面已处理的 CDATA）
        # 简单匹配： >...< 中间不包含 '<' 或 '>'
        for m in re.finditer(r'>([^<>]+)<', text):
            if variants >= self.max_variants:
                break
            inner = (m.start(1), m.end(1))
            if _is_in_spans(inner[0], protected):
                continue
            t_text = text[inner[0]:inner[1]]
            if not t_text.strip():
                continue
            if CHECKSUM_RE.fullmatch(t_text.strip()):
                continue
            per_span = 0
            for mut in self.mutators:
                if variants >= self.max_variants or per_span >= self.per_span_limit:
                    break
                try:
                    for v in mut.mutate(t_text.encode('utf-8', errors='ignore')):
                        if variants >= self.max_variants or per_span >= self.per_span_limit:
                            break
                        try:
                            v_text = v.decode('utf-8')
                        except Exception:
                            v_text = v.decode('latin-1', errors='ignore')
                        if CHECKSUM_RE.fullmatch(v_text.strip()):
                            continue
                        v_text_escaped = _escape_xml(v_text)
                        new_doc = text[:inner[0]] + v_text_escaped + text[inner[1]:]
                        try:
                            ET.fromstring(new_doc)
                        except Exception:
                            continue
                        yield new_doc.encode('utf-8')
                        variants += 1
                        per_span += 1
                except Exception:
                    continue

        # 3) 少量全局 Havoc 变体（对整个文档，但保持保护 spans 不被改写）
        if variants < self.max_variants:
            try:
                h = HavocMutator(rounds=6, max_changes=6)
                # 构建可变缓冲区：将受保护的 spans 替换为占位符
                placeholder = '\uFFFD'
                temp = list(text)
                for s, e in protected:
                    for i in range(s, e):
                        temp[i] = placeholder
                masked = ''.join(temp)
                for v in h.mutate(masked.encode('utf-8', errors='ignore')):
                    if variants >= self.max_variants:
                        break
                    try:
                        v_text = v.decode('utf-8')
                    except Exception:
                        v_text = v.decode('latin-1', errors='ignore')
                    # 从原始文本恢复受保护的 spans
                    out_chars = list(v_text)
                    for s, e in protected:
                        out_chars[s:e] = list(text[s:e])
                    candidate = ''.join(out_chars)
                    try:
                        ET.fromstring(candidate)
                    except Exception:
                        continue
                    yield candidate.encode('utf-8')
                    variants += 1
            except Exception:
                pass

        return


__all__ = ["XmlMutator"]
