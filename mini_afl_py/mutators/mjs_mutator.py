"""mjs 变异器 — 借鉴 AFL++ 常用变异策略，实现语法敏感与字节级混合变异。

特性：
- 文本级结构化变异：标识符微扰、数字微调、字符串扰动、操作符替换、注释切换、行交换
- 字节级/混沌变异（havoc）：位翻转、字节增减、插入/删除、重复块、覆盖
- 字典插入与拼接（splice）支持
- `safe_mode` 控制是否禁用破坏性字节级操作（用于解析严格的目标）

实现遵循简单可扩展接口：`mutate(data, num_mutations=1, other=None)`。
"""

from __future__ import annotations

import os
import random
import re
from typing import Iterable, List, Optional


IDENT_RE = re.compile(r"\b([A-Za-z_$][A-Za-z0-9_$]*)\b")
NUMBER_RE = re.compile(r"\b(\d+\.?\d*|\d*\.\d+)\b")
STRING_RE = re.compile(r"(`(?:\\`|[^`])*`|'(?:\\'|[^'])*'|\"(?:\\\"|[^\"])*\")")

JS_KEYWORDS = {
    'await','break','case','catch','class','const','continue','debugger','default','delete',
    'do','else','enum','export','extends','false','finally','for','function','if','import','in',
    'instanceof','let','new','null','return','super','switch','this','throw','true','try','typeof',
    'var','void','while','with','yield'
}


class MjsMutator:
    """完整的 MJS 变异器。

    参数:
      seed: 可选随机种子
      dict_tokens: 可选字典（字符串）列表，用于插入/覆盖
      safe_mode: True 时禁用破坏性字节操作
    """

    def __init__(self, seed: Optional[int] = None, dict_tokens: Optional[Iterable[str]] = None, *, safe_mode: bool = True) -> None:
        self.rng = random.Random(seed)
        self.dict_tokens: List[bytes] = [t.encode('utf-8') for t in dict_tokens] if dict_tokens else []
        self.safe_mode = bool(safe_mode)

    # Public API
    def mutate(self, data: bytes, num_mutations: int = 1, other: Optional[bytes] = None) -> bytes:
        """对输入进行 num_mutations 次变异。若提供 other，则可能执行 splice 操作。

        如果输入可作为 UTF-8 解码为文本，优先使用文本/语法相关变异；否则回退到字节级变异。
        """
        try:
            src = data.decode('utf-8')
            is_text = True
        except Exception:
            is_text = False

        if is_text:
            for _ in range(num_mutations):
                # 先尝试 determinisitic/text-aware 操作（小概率），否则进行 havoc
                if self.rng.random() < 0.6:
                    src = self._text_aware_mutation(src)
                else:
                    src = self._havoc_text_mutation(src)

                # optional splice
                if other and self.rng.random() < 0.15:
                    try:
                        src = self._splice_with(src, other)
                    except Exception:
                        pass

            return src.encode('utf-8', errors='ignore')

        # byte-level path
        out = bytearray(data)
        for _ in range(num_mutations):
            if not self.safe_mode and self.rng.random() < 0.6:
                out = self._havoc_bytes(out)
            else:
                out = self._simple_byte_mutation(out)
        return bytes(out)

    # Text-aware operations
    def _text_aware_mutation(self, src: str) -> str:
        ops = [
            self._rename_identifier,
            self._tweak_number,
            self._corrupt_string,
            self._flip_operator,
            self._toggle_comment_line,
            self._insert_literal,
            self._swap_adjacent_lines,
        ]
        op = self.rng.choice(ops)
        try:
            return op(src)
        except Exception:
            return src

    def _havoc_text_mutation(self, src: str) -> str:
        # 将文本转为 bytes 做混沌修改然后返回文本（保守）
        b = bytearray(src.encode('utf-8', errors='ignore'))
        b = self._havoc_bytes(b)
        try:
            return b.decode('utf-8', errors='ignore')
        except Exception:
            return src

    def _splice_with(self, src: str, other: bytes) -> str:
        try:
            other_s = other.decode('utf-8')
        except Exception:
            return src
        if not src or not other_s:
            return src
        a_lines = src.splitlines(True)
        b_lines = other_s.splitlines(True)
        if len(a_lines) < 1 or len(b_lines) < 1:
            return src
        ia = self.rng.randrange(len(a_lines))
        ib = self.rng.randrange(len(b_lines))
        # splice: take prefix of a up to ia, then suffix of b from ib
        new = ''.join(a_lines[:ia] + b_lines[ib:])
        return new

    # --- text-level primitive mutators
    def _rename_identifier(self, src: str) -> str:
        ids = list(IDENT_RE.finditer(src))
        if not ids:
            return src
        m = self.rng.choice(ids)
        name = m.group(1)
        if name in JS_KEYWORDS:
            return src
        new = self._mutate_ident(name)
        s, e = m.span(1)
        return src[:s] + new + src[e:]

    def _mutate_ident(self, s: str) -> str:
        r = self.rng.random()
        if r < 0.35 and len(s) > 1:
            i = self.rng.randrange(len(s))
            c = self.rng.choice('abcdefghijklmnopqrstuvwxyz0123456789_')
            return s[:i] + c + s[i+1:]
        elif r < 0.85:
            return s + self.rng.choice(['_x', '_v', str(self.rng.randrange(10, 99))])
        else:
            return s[::-1]

    def _tweak_number(self, src: str) -> str:
        nums = list(NUMBER_RE.finditer(src))
        if not nums:
            return src
        m = self.rng.choice(nums)
        val = m.group(1)
        try:
            if '.' in val:
                f = float(val)
                delta = self.rng.uniform(-100.0, 100.0)
                new = str(f + delta)
            else:
                i = int(val)
                delta = self.rng.randint(-1000, 1000)
                new = str(i + delta)
        except Exception:
            new = val
        s, e = m.span(1)
        return src[:s] + new + src[e:]

    def _corrupt_string(self, src: str) -> str:
        strs = list(STRING_RE.finditer(src))
        if not strs:
            return src
        m = self.rng.choice(strs)
        s = m.group(1)
        quote = s[0]
        inner = s[1:-1]
        r = self.rng.random()
        if r < 0.35 and inner:
            i = self.rng.randrange(len(inner))
            c = self.rng.choice('abcdefghijklmnopqrstuvwxyz0123456789')
            new_inner = inner[:i] + c + inner[i+1:]
        elif r < 0.75:
            new_inner = inner + self._random_text(8)
        else:
            new_inner = ''
        new = quote + new_inner + quote
        start, end = m.span(1)
        return src[:start] + new + src[end:]

    def _flip_operator(self, src: str) -> str:
        ops = [('===', '=='), ('==', '==='), ('!==', '!='), ('!=', '!==')]
        a, b = self.rng.choice(ops)
        if a in src:
            return src.replace(a, b, 1)
        if '<' in src and '>' in src and self.rng.random() < 0.3:
            src = src.replace('<', '__LT__', 1)
            src = src.replace('>', '<', 1)
            src = src.replace('__LT__', '>', 1)
        return src

    def _toggle_comment_line(self, src: str) -> str:
        lines = src.splitlines(True)
        if not lines:
            return src
        idx = self.rng.randrange(len(lines))
        line = lines[idx]
        stripped = line.lstrip()
        prefix_len = len(line) - len(stripped)
        if stripped.startswith('//'):
            new_line = ' ' * prefix_len + stripped[2:]
        else:
            new_line = ' ' * prefix_len + '//' + stripped
        lines[idx] = new_line
        return ''.join(lines)

    def _insert_literal(self, src: str) -> str:
        lits = ['undefined', 'null', '0', 'false']
        pos = self.rng.randrange(len(src) + 1)
        lit = self.rng.choice(lits)
        return src[:pos] + ' ' + lit + ' ' + src[pos:]

    def _swap_adjacent_lines(self, src: str) -> str:
        lines = src.splitlines(True)
        if len(lines) < 2:
            return src
        idx = self.rng.randrange(len(lines) - 1)
        lines[idx], lines[idx + 1] = lines[idx + 1], lines[idx]
        return ''.join(lines)

    def _random_text(self, max_len: int = 6) -> str:
        l = self.rng.randrange(1, max_len + 1)
        return ''.join(self.rng.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(l))

    # --- byte-level havoc primitives
    def _simple_byte_mutation(self, b: bytearray) -> bytearray:
        if not b:
            return b
        i = self.rng.randrange(len(b))
        b[i] = (b[i] + self.rng.randint(1, 255)) & 0xFF
        return b

    def _havoc_bytes(self, b: bytearray) -> bytearray:
        if not b:
            return b
        op = self.rng.choice(['bitflip', 'inc', 'dec', 'insert', 'delete', 'dup', 'overwrite', 'dict'])
        if op == 'bitflip':
            i = self.rng.randrange(len(b))
            bit = 1 << self.rng.randrange(0, 8)
            b[i] ^= bit
        elif op == 'inc':
            i = self.rng.randrange(len(b))
            b[i] = (b[i] + 1) & 0xFF
        elif op == 'dec':
            i = self.rng.randrange(len(b))
            b[i] = (b[i] - 1) & 0xFF
        elif op == 'insert':
            i = self.rng.randrange(len(b) + 1)
            n = self.rng.randint(1, min(16, max(1, len(b))))
            for _ in range(n):
                b.insert(i, self.rng.randrange(1, 255))
        elif op == 'delete' and len(b) > 1:
            i = self.rng.randrange(len(b))
            del b[i]
        elif op == 'dup':
            i = self.rng.randrange(len(b))
            j = self.rng.randrange(len(b))
            # duplicate small chunk
            L = self.rng.randint(1, min(64, len(b)))
            chunk = b[i:i+L]
            b[j:j] = chunk
        elif op == 'overwrite':
            i = self.rng.randrange(len(b))
            L = self.rng.randint(1, min(64, len(b)-i))
            for k in range(L):
                b[i+k] = self.rng.randrange(0, 256)
        elif op == 'dict' and self.dict_tokens:
            tok = self.rng.choice(self.dict_tokens)
            i = self.rng.randrange(len(b)+1)
            b[i:i] = tok
        return b

    # --- byte-level fallback for non-text inputs
    def _fallback_byte_mutation(self, data: bytes) -> bytes:
        b = bytearray(data)
        return bytes(self._havoc_bytes(b))


if __name__ == '__main__':
    sample = """// example ES module
export function add(a, b) {
  const s = `sum: ${a+b}`
  if (a === b) return true
  return a + b
}

export const VALUE = 42
"""
    m = MjsMutator(seed=1234, dict_tokens=['process','Buffer','require'], safe_mode=False)
    print('原始:')
    print(sample)
    for i in range(6):
        out = m.mutate(sample.encode('utf-8'), num_mutations=3)
        print(f'变异 {i+1}:')
        print(out.decode('utf-8', errors='ignore'))
