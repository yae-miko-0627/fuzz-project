"""
Havoc mutator

执行一系列随机的小编辑（翻转、异或、插入、删除、设置），组合为“havoc”风格的大扰动。

设计：多轮随机编辑，每轮随机选择若干次操作叠加在输入上，适合产生多样化且破坏性更强的变体。
"""
import random
from typing import Iterable, List


class HavocMutator:
    """随机组合多次编辑以产生较大扰动的变体。

    参数:
      rounds: 生成的变体轮数（每轮都会对原始输入应用若干随机修改并产出一个变体）。
      max_changes: 每轮中随机修改的最大次数（实际次数在 1..max_changes 之间）。
    """

    def __init__(self, rounds: int = 20, max_changes: int = 8, corpus: list = None):
        self.rounds = rounds
        self.max_changes = max_changes
        # 可选语料库，用于执行 copy / splice 风格的变异
        self.corpus = list(corpus) if corpus else []
        self.op_weights = {
            'flip': 20,
            'xor': 20,
            'set': 15,
            'insert': 15,
            'delete': 10,
            'block_xor': 10,
            'copy_block': 10,
        }

    def _random_edit(self, data: bytearray):
        """在字节数组上执行单次随机编辑。

        支持的操作：
        - 'flip'  : 翻转某个字节内的单个位
        - 'xor'   : 对某个字节做随机异或
        - 'set'   : 将某个字节设为随机值
        - 'insert': 在随机位置插入一个随机字节
        - 'delete': 删除随机位置的字节
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
        elif action == 'insert':
            idx = random.randrange(len(data)+1) if data else 0
            b = random.randrange(0, 256)
            data.insert(idx, b)
        elif action == 'delete':
            if not data:
                return
            idx = random.randrange(len(data))
            del data[idx]
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
            if self.corpus and random.random() < 0.5:
                other = random.choice(self.corpus)
            else:
                other = bytes(data)
            if not other:
                return
            start = random.randrange(len(other))
            length = random.randint(1, min(16, len(other)-start))
            block = other[start:start+length]
            idx = random.randrange(len(data)+1) if data else 0
            for b in reversed(block):
                data.insert(idx, b)

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
