"""
Lua 特殊变异器

功能要点：
- 识别 Lua 文本（尽量以 utf-8 解码），保护 shebang（若存在）和文件开头若干字节（可配置）；
- 内置增强字典（Lua 关键字、常用标准库函数与常见字面量），用于插入/替换；
- 在变异后尝试修复基本语法闭合：括号/中括号/大括号与成对引号（单/双引号）；
- 在内部复用已有基础变异器（Havoc/Interest/Arith）对字符串片段或整个文件做变异；
- 对变体数量与每种策略产出进行上限控制以防爆炸。

实现说明：此 mutator 采用文本为主的策略，尽量保持源码结构完整。对于不合法或二进制数据将尽早退回不产生变体。
"""
from __future__ import annotations

import re
import random
from typing import Iterable, List, Optional

from .havoc_mutator import HavocMutator
from .interest_mutator import InterestMutator
from .arith_mutator import ArithMutator


DEFAULT_DICT = [
    # Lua 关键字
    "and", "break", "do", "else", "elseif", "end", "false", "for", "function",
    "goto", "if", "in", "local", "nil", "not", "or", "repeat", "return", "then",
    "true", "until", "while",
    # 常用标准库函数 / 常见模式
    "print", "pairs", "ipairs", "next", "tonumber", "tostring", "string.sub", "string.match",
    "string.gsub", "table.insert", "table.remove", "math.floor", "math.ceil", "math.random",
    "io.open", "os.execute"  # 默认避免 I/O，保持注释状态
]


def _decode_text(data: bytes) -> Optional[str]:
    try:
        return data.decode("utf-8")
    except Exception:
        try:
            return data.decode("latin-1")
        except Exception:
            return None


def _encode_text(s: str, orig_bytes: bytes) -> bytes:
    # 尝试保留原始编码（utf-8 优先），回退到 latin-1
    try:
        return s.encode("utf-8")
    except Exception:
        try:
            return s.encode("latin-1")
        except Exception:
            return s.encode("utf-8", errors="ignore")


def _fix_brackets_and_quotes(s: str) -> str:
    # 修复括号、方括号、大括号
    pairs = [("(", ")"), ("[", "]"), ("{", "}")]
    for o, c in pairs:
        opens = s.count(o)
        closes = s.count(c)
        if opens > closes:
            s = s + (c * (opens - closes))
    # 修复引号（非转义的单/双引号计数）
    def count_unescaped(q):
        cnt = 0
        i = 0
        while True:
            i = s.find(q, i)
            if i == -1:
                break
            # 检查前导反斜杠数量
            back = 0
            j = i - 1
            while j >= 0 and s[j] == "\\":
                back += 1
                j -= 1
            if back % 2 == 0:
                cnt += 1
            i += 1
        return cnt

    for q in ["'", '"']:
        if count_unescaped(q) % 2 == 1:
            s = s + q
    return s


class LuaMutator:
    """Lua 源代码变异器。

    策略：
    - 优先在字符串、数字等 token 上应用基于 interest/arith 的替换；
    - 在标识符位置随机插入或替换字典 token；
    - 使用 HavocMutator 做少量随机编辑以增加多样性；
    - 每次变异后执行简单的语法闭合修复。
    """

    def __init__(self, mutators: Optional[List] = None, dict_tokens: Optional[List[str]] = None,
                 protect_prefix_lines: int = 1, max_variants: int = 200):
        # 使用简单的基础变异器集合（可被外部覆盖）
        if mutators is None:
            mutators = [HavocMutator(rounds=4, max_changes=4), InterestMutator(max_positions=32), ArithMutator(max_positions=16)]
        self.mutators = mutators
        self.dict_tokens = dict_tokens or DEFAULT_DICT
        self.protect_prefix_lines = int(protect_prefix_lines)
        self.max_variants = int(max_variants)

    def _split_protect_prefix(self, text: str):
        # 保护前 N 行（例如 shebang），避免破坏解释器行或文件注释头
        if self.protect_prefix_lines <= 0:
            return "", text
        parts = text.splitlines(keepends=True)
        prefix = ''.join(parts[:self.protect_prefix_lines])
        rest = ''.join(parts[self.protect_prefix_lines:])
        return prefix, rest

    def _insert_dict_token(self, text: str) -> str:
        # 在随机标识符边界插入一个字典 token
        # 找到所有单词边界位置
        words = list(re.finditer(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", text))
        if not words:
            # 如果找不到位置，直接在末尾附加
            pos = len(text)
        else:
            m = random.choice(words)
            pos = m.end()
        tok = random.choice(self.dict_tokens)
        return text[:pos] + " " + tok + text[pos:]

    def _replace_number_literals(self, text: str) -> str:
        # 将部分数字字面量替换为常用数值
        nums = ["0", "1", "-1", "2", "-2", "0xFF", "1e3"]
        def repl(m):
            if random.random() < 0.5:
                return random.choice(nums)
            return m.group(0)
        return re.sub(r"\b\d+(?:\.\d+)?(?:e[+-]?\d+)?\b", repl, text, flags=re.IGNORECASE)

    def mutate(self, data: bytes) -> Iterable[bytes]:
        text = _decode_text(data)
        if text is None:
            return

        prefix, body = self._split_protect_prefix(text)

        variants = 0

        # 策略 1：插入字典 token
        if variants < self.max_variants:
            try:
                new_body = self._insert_dict_token(body)
                new_body = _fix_brackets_and_quotes(new_body)
                yield _encode_text(prefix + new_body, data)
                variants += 1
            except Exception:
                pass

        # 策略 2：替换数字字面量
        if variants < self.max_variants:
            try:
                new_body = self._replace_number_literals(body)
                new_body = _fix_brackets_and_quotes(new_body)
                yield _encode_text(prefix + new_body, data)
                variants += 1
            except Exception:
                pass

        # 策略 3：对字符串/部分文本应用基础变异器（使用 Havoc/Interest/Arith）
        for mut in self.mutators:
            if variants >= self.max_variants:
                break
            try:
                # 应用到 body（文本）上的变异，mutator 接受 bytes
                for v in mut.mutate(body.encode("utf-8", errors="ignore") if isinstance(body, str) else body):
                    if variants >= self.max_variants:
                        break
                    # v 可能是 bytes，解码后修复
                    try:
                        vb = v.decode("utf-8")
                    except Exception:
                        vb = v.decode("latin-1", errors="ignore")
                    vb = _fix_brackets_and_quotes(vb)
                    yield _encode_text(prefix + vb, data)
                    variants += 1
            except Exception:
                continue

        # 策略 4：少量全文件 Havoc（仍保护前缀）
        if variants < self.max_variants:
            try:
                # 用 HavocMutator 生成一些随机变体
                h = HavocMutator(rounds=4, max_changes=6)
                for v in h.mutate(body.encode("utf-8", errors="ignore")):
                    if variants >= self.max_variants:
                        break
                    try:
                        vb = v.decode("utf-8")
                    except Exception:
                        vb = v.decode("latin-1", errors="ignore")
                    vb = _fix_brackets_and_quotes(vb)
                    yield _encode_text(prefix + vb, data)
                    variants += 1
            except Exception:
                pass

        return


__all__ = ["LuaMutator"]
