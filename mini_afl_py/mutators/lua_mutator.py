"""轻量级 Lua 变异器（用于模糊测试）。

实现若干文本/语义对齐的轻量变异策略：
- 标识符改名（小幅扰动）
- 数字微调（加/减小整数/浮点）
- 字符串内容破坏或插入随机字节
- 删除或注释整行/语句
- 在行间插入简单字面量（nil/true/false/0）
- 交换相邻行

仅使用标准库，实现简单且高效，适合嵌入到高速变异循环中。
"""
from __future__ import annotations

import random
import re
from typing import Optional


class LuaMutator:
    """ Lua 变异器。"""

    IDENT_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b")
    NUMBER_RE = re.compile(r"\b(\d+\.?\d*|\d*\.\d+)\b")
    STRING_RE = re.compile(r"('(?:\\'|[^'])*'|\"(?:\\\"|[^\"])*\")")

    def __init__(self, seed: Optional[int] = None) -> None:
        self.rng = random.Random(seed)

    def mutate(self, data: bytes, num_mutations: int = 1) -> bytes:
        """对 Lua 文本执行若干次变异并返回结果（utf-8 编码）。

        若输入无法解码为文本，则回退到字节级简单变异。
        """
        try:
            src = data.decode('utf-8')
        except Exception:
            return self._fallback_byte_mutation(data)

        lines = src.splitlines(True)

        for _ in range(num_mutations):
            ops = [self._rename_identifier, self._tweak_number, self._corrupt_string,
                   self._delete_or_comment_line, self._insert_literal, self._swap_adjacent_lines]
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
        # 在所有标识符中随机选择一个并做小幅修改（加后缀/替换字符）
        idents = list(self.IDENT_RE.finditer(src))
        if not idents:
            return src
        m = self.rng.choice(idents)
        name = m.group(1)
        # 保留 Lua 关键字表简单过滤（非穷尽）
        lua_keywords = {
            'and','break','do','else','elseif','end','false','for','function',
            'if','in','local','nil','not','or','repeat','return','then','true','until','while'
        }
        if name in lua_keywords:
            return src
        new = self._mutate_identifier(name)
        start, end = m.span(1)
        return src[:start] + new + src[end:]

    def _mutate_identifier(self, s: str) -> str:
        r = self.rng.random()
        if r < 0.4 and len(s) > 1:
            i = self.rng.randrange(len(s))
            c = self.rng.choice('abcdefghijklmnopqrstuvwxyz0123456789_')
            return s[:i] + c + s[i+1:]
        elif r < 0.8:
            return s + self.rng.choice(['_x', '_tmp', str(self.rng.randrange(10,99))])
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
                delta = self.rng.uniform(-5.0, 5.0)
                new = str(f + delta)
            else:
                i = int(val)
                delta = self.rng.randint(-10, 10)
                new = str(max(0, i + delta))
        except Exception:
            new = val
        start, end = m.span(1)
        return src[:start] + new + src[end:]

    def _corrupt_string(self, src: str, lines) -> str:
        strs = list(self.STRING_RE.finditer(src))
        if not strs:
            return src
        m = self.rng.choice(strs)
        s = m.group(1)
        quote = s[0]
        inner = s[1:-1]
        # 对字符串内容进行小幅破坏或插入
        r = self.rng.random()
        if r < 0.4 and inner:
            i = self.rng.randrange(len(inner))
            c = self.rng.choice('abcdefghijklmnopqrstuvwxyz0123456789')
            new_inner = inner[:i] + c + inner[i+1:]
        elif r < 0.8:
            new_inner = inner + self._random_text(3)
        else:
            new_inner = ''
        new = quote + new_inner + quote
        start, end = m.span(1)
        return src[:start] + new + src[end:]

    def _delete_or_comment_line(self, src: str, lines) -> str:
        # 随机删除一行或将其注释掉
        if not lines:
            return src
        idx = self.rng.randrange(len(lines))
        line = lines[idx]
        if self.rng.random() < 0.5:
            # 删除
            return ''.join(lines[:idx] + lines[idx+1:])
        else:
            # 注释（若已注释则解除注释）
            stripped = line.lstrip()
            prefix_len = len(line) - len(stripped)
            if stripped.startswith('--'):
                # 解除注释
                new_line = ' ' * prefix_len + stripped[2:]
            else:
                new_line = ' ' * prefix_len + '--' + stripped
            new_lines = lines[:idx] + [new_line] + lines[idx+1:]
            return ''.join(new_lines)

    def _insert_literal(self, src: str, lines) -> str:
        # 在随机位置插入简单字面量以破坏控制流
        litterals = ['nil', 'true', 'false', '0']
        pos = self.rng.randrange(len(src)+1)
        lit = self.rng.choice(litterals)
        # 在非字母位置插入以减少语法粘连
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
        sample = """-- 示例 Lua 脚本
local x = 42
local s = "hello"
for i=1,5 do
    x = x + i
    print(s, x)
end
"""
        m = LuaMutator(seed=2025)
        print('原始:')
        print(sample)
        for i in range(6):
                out = m.mutate(sample.encode('utf-8'), num_mutations=2)
                print(f'变异 {i+1}:')
                print(out.decode('utf-8'))
