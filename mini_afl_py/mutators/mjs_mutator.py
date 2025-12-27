"""轻量级 MJS（ES module）变异器。

提供小巧且高效的 JS/MJS 特定变异策略，适合嵌入模糊测试循环：
- 标识符改名（小幅扰动）
- 数字微调
- 字符串内容破坏/插入
- 操作符替换（==/===, !=/!== 等）
- 注释切换/删除行
- 插入简单字面量（undefined/null/0）
- 交换相邻语句/行

仅使用 Python 标准库实现，带可复现的随机种子和示例。
"""
from __future__ import annotations

import random
import re
from typing import Optional


class MjsMutator:
    """轻量 MJS 变异器实现。"""

    IDENT_RE = re.compile(r"\b([A-Za-z_$][A-Za-z0-9_$]*)\b")
    NUMBER_RE = re.compile(r"\b(\d+\.?\d*|\d*\.\d+)\b")
    STRING_RE = re.compile(r"(`(?:\\`|[^`])*`|'(?:\\'|[^'])*'|\"(?:\\\"|[^\"])*\")")

    JS_KEYWORDS = {
        'await','break','case','catch','class','const','continue','debugger','default','delete',
        'do','else','enum','export','extends','false','finally','for','function','if','import','in',
        'instanceof','let','new','null','return','super','switch','this','throw','true','try','typeof',
        'var','void','while','with','yield'
    }

    def __init__(self, seed: Optional[int] = None) -> None:
        self.rng = random.Random(seed)

    def mutate(self, data: bytes, num_mutations: int = 1) -> bytes:
        """对 mjs/JS 文本进行 num_mutations 次变异并返回 utf-8 编码的结果。

        若输入无法解码为文本，则回退到字节层简单变异。
        """
        try:
            src = data.decode('utf-8')
        except Exception:
            return self._fallback_byte_mutation(data)

        lines = src.splitlines(True)

        for _ in range(num_mutations):
            ops = [self._rename_identifier, self._tweak_number, self._corrupt_string,
                   self._flip_operator, self._toggle_comment_line, self._insert_literal,
                   self._swap_adjacent_lines]
            op = self.rng.choice(ops)
            try:
                src = op(src, lines)
                lines = src.splitlines(True)
            except Exception:
                continue

        return src.encode('utf-8', errors='ignore')

    def _fallback_byte_mutation(self, data: bytes) -> bytes:
        b = bytearray(data)
        if not b:
            return data
        i = self.rng.randrange(len(b))
        b[i] = (b[i] + self.rng.randrange(1, 255)) & 0xFF
        return bytes(b)

    def _rename_identifier(self, src: str, lines) -> str:
        ids = list(self.IDENT_RE.finditer(src))
        if not ids:
            return src
        m = self.rng.choice(ids)
        name = m.group(1)
        if name in self.JS_KEYWORDS:
            return src
        new = self._mutate_ident(name)
        s, e = m.span(1)
        return src[:s] + new + src[e:]

    def _mutate_ident(self, s: str) -> str:
        r = self.rng.random()
        if r < 0.4 and len(s) > 1:
            i = self.rng.randrange(len(s))
            c = self.rng.choice('abcdefghijklmnopqrstuvwxyz0123456789_')
            return s[:i] + c + s[i+1:]
        elif r < 0.85:
            return s + self.rng.choice(['_x','_v',str(self.rng.randrange(10,99))])
        else:
            return s[::-1]

    def _tweak_number(self, src: str, lines) -> str:
        nums = list(self.NUMBER_RE.finditer(src))
        if not nums:
            return src
        m = self.rng.choice(nums)
        val = m.group(1)
        try:
            if '.' in val:
                f = float(val)
                delta = self.rng.uniform(-10.0, 10.0)
                new = str(f + delta)
            else:
                i = int(val)
                delta = self.rng.randint(-50, 50)
                new = str(max(0, i + delta))
        except Exception:
            new = val
        s, e = m.span(1)
        return src[:s] + new + src[e:]

    def _corrupt_string(self, src: str, lines) -> str:
        strs = list(self.STRING_RE.finditer(src))
        if not strs:
            return src
        m = self.rng.choice(strs)
        s = m.group(1)
        quote = s[0]
        inner = s[1:-1]
        r = self.rng.random()
        if r < 0.4 and inner:
            i = self.rng.randrange(len(inner))
            c = self.rng.choice('abcdefghijklmnopqrstuvwxyz0123456789')
            new_inner = inner[:i] + c + inner[i+1:]
        elif r < 0.8:
            new_inner = inner + self._random_text(4)
        else:
            new_inner = ''
        new = quote + new_inner + quote
        start, end = m.span(1)
        return src[:start] + new + src[end:]

    def _flip_operator(self, src: str, lines) -> str:
        # 简单替换关系/相等操作符以触发不同控制流
        ops = [ ('===','=='), ('==','==='), ('!==','!='), ('!=','!=='), ]
        a,b = self.rng.choice(ops)
        if a in src:
            return src.replace(a, b, 1)
        # 次要尝试替换 <-> >
        if '<' in src and '>' in src and self.rng.random() < 0.3:
            # 交换首个出现的 < 和 >
            src = src.replace('<','__LT__',1)
            src = src.replace('>','<',1)
            src = src.replace('__LT__','>',1)
        return src

    def _toggle_comment_line(self, src: str, lines) -> str:
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
        new_lines = lines[:idx] + [new_line] + lines[idx+1:]
        return ''.join(new_lines)

    def _insert_literal(self, src: str, lines) -> str:
        lits = ['undefined','null','0','false']
        pos = self.rng.randrange(len(src)+1)
        lit = self.rng.choice(lits)
        return src[:pos] + ' ' + lit + ' ' + src[pos:]

    def _swap_adjacent_lines(self, src: str, lines) -> str:
        if len(lines) < 2:
            return src
        idx = self.rng.randrange(len(lines)-1)
        new_lines = lines[:]
        new_lines[idx], new_lines[idx+1] = new_lines[idx+1], new_lines[idx]
        return ''.join(new_lines)

    def _random_text(self, max_len: int = 6) -> str:
        l = self.rng.randrange(1, max_len+1)
        return ''.join(self.rng.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(l))


if __name__ == '__main__':
    sample = """// example ES module
export function add(a, b) {
  const s = `sum: ${a+b}`
  if (a === b) return true
  return a + b
}

export const VALUE = 42
"""
    m = MjsMutator(seed=1234)
    print('原始:')
    print(sample)
    for i in range(6):
        out = m.mutate(sample.encode('utf-8'), num_mutations=2)
        print(f'变异 {i+1}:')
        print(out.decode('utf-8'))
