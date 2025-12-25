"""
MJS (ECMAScript module .mjs) 专用变异器

特点：
- 识别并保护 shebang（#!）以及 `import` / `export` 语句行和 `require(...)` 调用处的字符串路径，避免破坏模块边界；
- 内置增强字典（JS 关键字与常用 API）用于插入/替换标识符；
- 使用已有基础变异器（Havoc/Interest/Arith）对字符串字面量、数字字面量与非保护文本块进行变异；
- 变异后进行括号/中括号/大括号与引号闭合修复，仅在基本平衡检查通过时输出变体；
- 对产出数量设置上限以防止爆炸。

说明：本实现采用轻量文本级策略；若需更严格的语法验证，可后续集成基于 Node 的解析器（`acorn` / `esprima`）。
"""
from __future__ import annotations

import re
import random
from typing import Iterable, List, Optional, Tuple

from .havoc_mutator import HavocMutator
from .interest_mutator import InterestMutator
from .arith_mutator import ArithMutator


DEFAULT_DICT = [
    # JS 关键字
    "var", "let", "const", "function", "return", "if", "else", "for", "while", "switch", "case",
    "break", "continue", "class", "extends", "import", "export", "from", "default", "new", "try", "catch",
    "finally", "throw", "async", "await", "yield", "typeof", "instanceof", "in", "of",
    # 常用 API
    "console", "log", "JSON", "parse", "stringify", "Math", "Date", "setTimeout", "setInterval",
    "Promise", "fetch", "require", "module", "exports"
]


def _decode_text(data: bytes) -> Optional[str]:
    try:
        return data.decode('utf-8')
    except Exception:
        try:
            return data.decode('latin-1')
        except Exception:
            return None


def _encode_text(s: str, orig_bytes: bytes) -> bytes:
    try:
        return s.encode('utf-8')
    except Exception:
        try:
            return s.encode('latin-1')
        except Exception:
            return s.encode('utf-8', errors='ignore')


def _count_unescaped(text: str, ch: str) -> int:
    cnt = 0
    i = 0
    while True:
        i = text.find(ch, i)
        if i == -1:
            break
        # 统计前置反斜杠数量
        back = 0
        j = i - 1
        while j >= 0 and text[j] == '\\':
            back += 1
            j -= 1
        if back % 2 == 0:
            cnt += 1
        i += 1
    return cnt


def _fix_brackets_and_quotes(s: str) -> str:
    pairs = [('(', ')'), ('[', ']'), ('{', '}')]
    for o, c in pairs:
        opens = s.count(o)
        closes = s.count(c)
        if opens > closes:
            s = s + (c * (opens - closes))
    # 引号
    for q in ['"', "'", '`']:
        if _count_unescaped(s, q) % 2 == 1:
            s = s + q
    return s


def _find_protected_spans(text: str) -> List[Tuple[int, int]]:
    """保护 shebang 与 import/export/require 语句行（行级保护）。"""
    spans: List[Tuple[int, int]] = []
    # shebang 行
    if text.startswith('#!'):
        nl = text.find('\n')
        if nl == -1:
            spans.append((0, len(text)))
        else:
            spans.append((0, nl+1))
    # import/export 行（按行简单处理）
    for m in re.finditer(r'^(\s*(?:import|export)\b.*)$', text, flags=re.MULTILINE):
        spans.append((m.start(1), m.end(1)))
    # require('...') 字符串：保护 require 内的字符串字面量
    for m in re.finditer(r"require\(\s*(['\"])(.*?)\1\s*\)", text):
        # 保护 require(...) 内被引号包裹的路径
        q = m.group(1)
        inner_start = m.start(2)
        inner_end = m.end(2)
        spans.append((inner_start, inner_end))
    # 合并
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


class MjsMutator:
    def __init__(self, mutators: Optional[List] = None, dict_tokens: Optional[List[str]] = None,
                 per_span_limit: int = 50, max_variants: int = 200):
        if mutators is None:
            mutators = [HavocMutator(rounds=4, max_changes=4), InterestMutator(max_positions=64), ArithMutator(max_positions=32)]
        self.mutators = mutators
        self.dict_tokens = dict_tokens or DEFAULT_DICT
        self.per_span_limit = int(per_span_limit)
        self.max_variants = int(max_variants)

    def _insert_dict_token(self, text: str) -> str:
        words = list(re.finditer(r"\b[a-zA-Z_$][a-zA-Z0-9_$]*\b", text))
        if not words:
            pos = len(text)
        else:
            m = random.choice(words)
            pos = m.end()
        tok = random.choice(self.dict_tokens)
        return text[:pos] + " " + tok + text[pos:]

    def _replace_number_literals(self, text: str) -> str:
        nums = ["0", "1", "-1", "2", "-2", "0xFF", "1e3"]
        def repl(m):
            if random.random() < 0.5:
                return random.choice(nums)
            return m.group(0)
        return re.sub(r"\b\d+(?:\.\d+)?(?:e[+-]?\d+)?\b", repl, text, flags=re.IGNORECASE)

    def _basic_balance_check(self, s: str) -> bool:
        # 检查括号/方括号/大括号与引号的简单平衡
        for o, c in [('(', ')'), ('[', ']'), ('{', '}')]:
            if s.count(o) != s.count(c):
                return False
        for q in ['"', "'", '`']:
            if _count_unescaped(s, q) % 2 != 0:
                return False
        return True

    def mutate(self, data: bytes) -> Iterable[bytes]:
        text = _decode_text(data)
        if text is None:
            return

        protected = _find_protected_spans(text)
        variants = 0

        # 策略 A：在标识符边界插入字典 token
        if variants < self.max_variants:
            try:
                new_text = self._insert_dict_token(text)
                new_text = _fix_brackets_and_quotes(new_text)
                if self._basic_balance_check(new_text):
                    yield _encode_text(new_text, data)
                    variants += 1
            except Exception:
                pass

        # 策略 B：替换数字字面量
        if variants < self.max_variants:
            try:
                new_text = self._replace_number_literals(text)
                new_text = _fix_brackets_and_quotes(new_text)
                if self._basic_balance_check(new_text):
                    yield _encode_text(new_text, data)
                    variants += 1
            except Exception:
                pass

        # 策略 C：变异字符串字面量（单/双/反引号）
        string_re = re.compile(r"(['\"])(.*?)(?<!\\)\1|(`)(.*?)(?<!\\)\3", flags=re.DOTALL)
        for m in string_re.finditer(text):
            if variants >= self.max_variants:
                break
            # 确定内部范围
            if m.group(1):
                inner = (m.start(2), m.end(2))
                quote = m.group(1)
            else:
                inner = (m.start(4), m.end(4))
                quote = '`'
            if _is_in_spans(inner[0], protected):
                continue
            val = text[inner[0]:inner[1]]
            per_span = 0
            for mut in self.mutators:
                if variants >= self.max_variants or per_span >= self.per_span_limit:
                    break
                try:
                    for v in mut.mutate(val.encode('utf-8', errors='ignore')):
                        if variants >= self.max_variants or per_span >= self.per_span_limit:
                            break
                        try:
                            v_text = v.decode('utf-8')
                        except Exception:
                            v_text = v.decode('latin-1', errors='ignore')
                        cand = text[:inner[0]] + v_text + text[inner[1]:]
                        cand = _fix_brackets_and_quotes(cand)
                        if not self._basic_balance_check(cand):
                            continue
                        yield _encode_text(cand, data)
                        variants += 1
                        per_span += 1
                except Exception:
                    continue

        # 策略 D：对非保护的代码片段应用基础变异（按保护区分割）
        if variants < self.max_variants:
            spans = []
            last = 0
            for s, e in protected:
                if last < s:
                    spans.append((last, s))
                last = e
            if last < len(text):
                spans.append((last, len(text)))

            for (s, e) in spans:
                if variants >= self.max_variants:
                    break
                chunk = text[s:e]
                per_span = 0
                for mut in self.mutators:
                    if variants >= self.max_variants or per_span >= self.per_span_limit:
                        break
                    try:
                        for v in mut.mutate(chunk.encode('utf-8', errors='ignore')):
                            if variants >= self.max_variants or per_span >= self.per_span_limit:
                                break
                            try:
                                v_text = v.decode('utf-8')
                            except Exception:
                                v_text = v.decode('latin-1', errors='ignore')
                            cand = text[:s] + v_text + text[e:]
                            cand = _fix_brackets_and_quotes(cand)
                            if not self._basic_balance_check(cand):
                                continue
                            yield _encode_text(cand, data)
                            variants += 1
                            per_span += 1
                    except Exception:
                        continue

        # 策略 E：在保留保护区的前提下执行小规模全局 Havoc
        if variants < self.max_variants:
            try:
                h = HavocMutator(rounds=4, max_changes=6)
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
                    out_chars = list(v_text)
                    for s, e in protected:
                        out_chars[s:e] = list(text[s:e])
                    candidate = ''.join(out_chars)
                    candidate = _fix_brackets_and_quotes(candidate)
                    if not self._basic_balance_check(candidate):
                        continue
                    yield _encode_text(candidate, data)
                    variants += 1
            except Exception:
                pass

        return


__all__ = ["MjsMutator"]
