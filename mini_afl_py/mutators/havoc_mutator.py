"""
Havoc mutator

执行一系列随机的小编辑（翻转、异或、插入、删除、设置），组合为“havoc”风格的大扰动。

设计：多轮随机编辑，每轮随机选择若干次操作叠加在输入上，适合产生多样化且破坏性更强的变体。
"""
import random
import struct
from typing import Iterable, List, Optional


class HavocMutator:
    """随机组合多次编辑以产生较大扰动的变体。

    参数:
      rounds: 生成的变体轮数（每轮都会对原始输入应用若干随机修改并产出一个变体）。
      max_changes: 每轮中随机修改的最大次数（实际次数在 1..max_changes 之间）。
    """

    def __init__(self, rounds: int = 20, max_changes: int = 8, corpus: Optional[list] = None, tokens: Optional[list] = None):
        self.rounds = rounds
        self.max_changes = max_changes
        # 可选语料库，用于执行 copy / splice 风格的变异
        self.corpus = list(corpus) if corpus else []
        # 可选 token 列表（来自字典或用户提供），用于插入常见关键字/标记
        self.tokens = list(tokens) if tokens else []
        # 扩展的操作集合（包含算术、可变比特翻转、拼接、重复/缩短等）
        self.op_weights = {
            'flip': 12,
            'flip_nbits': 8,
            'xor': 12,
            'set': 10,
            'arith': 10,
            'arith_block': 6,
            'insert': 8,
            'insert_token': 6,
            'delete': 6,
            'repeat_block': 6,
            'shrink_block': 4,
            'block_xor': 6,
            'copy_block': 6,
            'splice': 10,
        }
        # 用于支持激进模式，保存原始参数以便恢复
        self._orig = {
            'rounds': int(self.rounds),
            'max_changes': int(self.max_changes),
            'op_weights': dict(self.op_weights)
        }

    def apply_aggression(self, scale: float) -> None:
        """把内部参数放大 `scale` 倍以进入更激进模式。"""
        try:
            s = max(1.0, float(scale))
            self.rounds = max(1, int(self._orig['rounds'] * s))
            self.max_changes = max(1, int(self._orig['max_changes'] * s))
            # 对某些破坏性操作提升权重以提高扰动几率
            new_weights = {}
            for k, v in self._orig['op_weights'].items():
                # 对 flip/insert/delete/splice 等操作放大
                if k in ('flip', 'flip_nbits', 'insert', 'delete', 'splice', 'copy_block', 'block_xor'):
                    new_weights[k] = max(1, int(v * (1.0 + (s - 1.0) * 1.2)))
                else:
                    new_weights[k] = max(1, int(v * (1.0 + (s - 1.0) * 0.6)))
            self.op_weights = new_weights
        except Exception:
            pass

    def clear_aggression(self) -> None:
        """恢复到原始参数。"""
        try:
            self.rounds = int(self._orig['rounds'])
            self.max_changes = int(self._orig['max_changes'])
            self.op_weights = dict(self._orig['op_weights'])
        except Exception:
            pass

    def _random_edit(self, data: bytearray):
        """在字节数组上执行单次随机编辑。

        支持的操作：
        - 'flip'  : 翻转某个字节内的单个位
        - 'xor'   : 对某个字节做随机异或
        - 'set'   : 将某个字节设为随机值
        - 'insert': 在随机位置插入一个随机字节
        - 'delete': 删除随机位置的字节
        - 'block_xor': 对一个随机长度的连续区块进行异或
        - 'copy_block': 从自身或语料库复制一段数据并插入到随机位置
        """
        # 根据权重随机选择操作
        actions = list(self.op_weights.keys())
        weights = [self.op_weights[a] for a in actions]
        action = random.choices(actions, weights=weights, k=1)[0]
        if action == 'flip':
            if not data:
                return
            idx = random.randrange(len(data))
            bit = 1 << random.randrange(8)
            data[idx] ^= bit
        elif action == 'flip_nbits':
            if not data:
                return
            idx = random.randrange(len(data))
            n = random.choice([1, 2, 4])
            mask = 0
            for _ in range(n):
                mask |= 1 << random.randrange(8)
            data[idx] ^= mask
        elif action == 'xor':
            if not data:
                return
            idx = random.randrange(len(data))
            data[idx] ^= random.randrange(1, 256)
        elif action == 'set':
            if not data:
                return
            idx = random.randrange(len(data))
            data[idx] = random.randrange(0, 256)
        elif action == 'arith':
            # 对单字节做小幅加/减
            if not data:
                return
            idx = random.randrange(len(data))
            delta = random.randint(-35, 35)
            data[idx] = (data[idx] + delta) & 0xFF
        elif action == 'arith_block':
            # 对多字节块按指定 endianness 做小幅算术变化
            if not data:
                return
            start = random.randrange(len(data))
            max_len = min(4, len(data) - start)
            length = random.randint(1, max_len)
            # interpret as little-endian integer
            block = data[start:start+length]
            val = int.from_bytes(block, 'little')
            delta = random.randint(-500, 500)
            val = (val + delta) & ((1 << (8 * length)) - 1)
            newb = val.to_bytes(length, 'little')
            for i in range(length):
                data[start + i] = newb[i]
        elif action == 'insert':
            idx = random.randrange(len(data)+1) if data else 0
            b = random.randrange(0, 256)
            data.insert(idx, b)
        elif action == 'insert_token':
            # 在随机位置插入一个常见 token（若可用）或短随机字节序列
            idx = random.randrange(len(data)+1) if data else 0
            if self.tokens and random.random() < 0.8:
                token = random.choice(self.tokens)
                if isinstance(token, str):
                    block = token.encode(errors='ignore')
                else:
                    block = bytes(token)
            else:
                length = random.randint(1, 8)
                block = bytes(random.getrandbits(8) for _ in range(length))
            for b in reversed(block):
                data.insert(idx, b)
        elif action == 'delete':
            if not data:
                return
            idx = random.randrange(len(data))
            del data[idx]
        elif action == 'repeat_block':
            # 复制一段自身块并重复插入，以扩展结构
            if not data:
                return
            start = random.randrange(len(data))
            length = random.randint(1, min(16, len(data)-start))
            block = data[start:start+length]
            times = random.randint(1, 4)
            idx = random.randrange(len(data)+1)
            for _ in range(times):
                for b in reversed(block):
                    data.insert(idx, b)
        elif action == 'shrink_block':
            # 删除一个连续区块以缩短结构
            if len(data) < 2:
                return
            start = random.randrange(len(data)-1)
            length = random.randint(1, min(16, len(data)-start))
            del data[start:start+length]
        elif action == 'block_xor':
            # 对一个随机长度的连续区块进行异或
            if not data:
                return
            start = random.randrange(len(data))
            max_len = min(16, len(data) - start)
            length = random.randint(1, max_len)
            key = random.randrange(1, 256)
            for i in range(start, start + length):
                data[i] ^= key
        elif action == 'copy_block':
            # 从自身或语料库复制一段数据并插入到随机位置
            if self.corpus and random.random() < 0.6:
                other = random.choice(self.corpus)
            else:
                other = bytes(data)
            if not other:
                return
            start = random.randrange(len(other))
            length = random.randint(1, min(64, len(other)-start))
            block = other[start:start+length]
            idx = random.randrange(len(data)+1) if data else 0
            for b in reversed(block):
                data.insert(idx, b)
        elif action == 'splice':
            # 从语料库或自身选取另一条样本并在随机位置做拼接/替换
            if not self.corpus:
                return
            other = random.choice(self.corpus)
            if not other:
                return
            # 选择拼接模式：插入 / 覆盖
            start_other = random.randrange(len(other))
            len_other = random.randint(1, min(64, len(other)-start_other))
            block = other[start_other:start_other+len_other]
            if not data:
                for b in reversed(block):
                    data.insert(0, b)
                return
            mode = random.choice(['insert', 'overwrite'])
            idx = random.randrange(len(data))
            if mode == 'insert':
                for b in reversed(block):
                    data.insert(idx, b)
            else:
                # overwrite
                for i in range(len(block)):
                    if idx + i < len(data):
                        data[idx + i] = block[i]
                    else:
                        data.append(block[i])

    def mutate(self, data: bytes) -> Iterable[bytes]:
        """对输入执行多轮随机编辑，每轮产出一个变体。"""
        if data is None:
            return
        for _ in range(self.rounds):
            out = bytearray(data)
            # 随机决定本轮的编辑次数（至少 1 次）
            changes = random.randint(1, self.max_changes)
            for __ in range(changes):
                self._random_edit(out)
            yield bytes(out)
