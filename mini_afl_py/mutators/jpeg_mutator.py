"""轻量级 JPEG 变异器（用于模糊测试）。

只使用标准库，提供若干段级和字节级变异：截断、段复制、段损坏、字节翻转、段交换等。
设计目标是小而有效、可在高速变异循环中使用。
"""
from __future__ import annotations

import random
from typing import List, Tuple, Optional


class JPEGMutator:
    """简单的 JPEG 专用变异器。"""

    def __init__(self, seed: Optional[int] = None) -> None:
        self.rng = random.Random(seed)

    def mutate(self, data: bytes, num_mutations: int = 1) -> bytes:
        """对 JPEG 二进制做若干次变异，返回变异后的字节串。

        如果解析段失败，会回退为字节层面的简单变异。
        """
        try:
            segments = self._parse_segments(data)
        except Exception:
            return self._fallback_byte_mutation(data)

        out = bytearray(data)
        for _ in range(num_mutations):
            ops = [self._truncate_at_segment, self._flip_bytes_in_segment,
                   self._duplicate_segment, self._corrupt_segment_length,
                   self._swap_adjacent_segments, self._tweak_app_payload]
            op = self.rng.choice(ops)
            try:
                out = op(out, segments)
                segments = self._parse_segments(bytes(out))
            except Exception:
                # 单次变异失败则跳过
                continue

        return bytes(out)

    def _parse_segments(self, data: bytes) -> List[Tuple[int, int, int]]:
        """解析 JPEG 段，返回列表 (marker, start, end) 的偏移。

        marker: 两字节的值 (0xFF00 | code)。start: 段起始偏移（标记首字节），end: 段结束后第一个字节的偏移。
        仅做轻量解析以便在变异器中使用。
        """
        i = 0
        n = len(data)
        segs: List[Tuple[int, int, int]] = []
        while i + 1 < n:
            if data[i] != 0xFF:
                i += 1
                continue
            # 找到 0xFF 后的标记字节
            j = i + 1
            marker = data[j]
            code = 0xFF00 | marker
            # SOI (FFD8) 和 EOI (FFD9) 以及 RSTx (FFD0-FFD7) 无长度字段
            if marker == 0xD8 or marker == 0xD9 or (0xD0 <= marker <= 0xD7):
                segs.append((code, i, j + 1))
                i = j + 1
                continue
            # 其他大多数段紧随两字节长度（包含长度字段本身）
            if j + 2 > n - 1:
                # 不能读取长度，停止解析
                break
            length = (data[j + 1] << 8) | data[j + 2]
            seg_end = j + 1 + length
            if seg_end > n:
                # 长度超出文件，截断为文件末尾
                seg_end = n
            segs.append((code, i, seg_end))
            i = seg_end
        return segs

    def _fallback_byte_mutation(self, data: bytes) -> bytes:
        b = bytearray(data)
        if not b:
            return data
        i = self.rng.randrange(len(b))
        b[i] = (b[i] + self.rng.randrange(1, 255)) & 0xFF
        return bytes(b)

    def _truncate_at_segment(self, out: bytearray, segments: List[Tuple[int, int, int]]) -> bytearray:
        # 在某个段边界处截断（避免删除 SOI）
        if len(segments) <= 2:
            return out
        # 选择非首段和非末段的位置截断
        idx = self.rng.randrange(1, max(2, len(segments) - 1))
        _, _, cut = segments[idx]
        return out[:cut]

    def _flip_bytes_in_segment(self, out: bytearray, segments: List[Tuple[int, int, int]]) -> bytearray:
        # 在随机段内翻转几个字节，避免 SOI/EOI
        choices = [s for s in segments if s[0] not in (0xFFD8, 0xFFD9)]
        if not choices:
            return out
        _, start, end = self.rng.choice(choices)
        if end - start <= 2:
            return out
        count = max(1, (end - start) // 20)
        for _ in range(self.rng.randrange(1, count + 1)):
            i = self.rng.randrange(start + 2, end)  # skip marker+len
            out[i] = (out[i] ^ self.rng.randrange(1, 256)) & 0xFF
        return out

    def _duplicate_segment(self, out: bytearray, segments: List[Tuple[int, int, int]]) -> bytearray:
        # 复制一个段插入到其后
        choices = [s for s in segments if s[0] not in (0xFFD8, 0xFFD9)]
        if not choices:
            return out
        _, start, end = self.rng.choice(choices)
        seg = out[start:end]
        insert_at = end
        return out[:insert_at] + seg + out[insert_at:]

    def _corrupt_segment_length(self, out: bytearray, segments: List[Tuple[int, int, int]]) -> bytearray:
        # 修改段长度字段（如果存在），生成不一致长度以触发解析差异
        choices = [s for s in segments if s[0] not in (0xFFD8, 0xFFD9) and s[2] - s[1] >= 4]
        if not choices:
            return out
        _, start, end = self.rng.choice(choices)
        # 长度字段位于 start+2 和 start+3（标记两字节之后）
        if start + 3 >= len(out):
            return out
        new_len = self.rng.randrange(2, max(3, end - (start + 1) + 50))
        out[start + 2] = (new_len >> 8) & 0xFF
        out[start + 3] = new_len & 0xFF
        return out

    def _swap_adjacent_segments(self, out: bytearray, segments: List[Tuple[int, int, int]]) -> bytearray:
        # 交换相邻两个段的位置
        if len(segments) < 3:
            return out
        idx = self.rng.randrange(1, len(segments) - 1)
        a = segments[idx]
        b = segments[idx + 1]
        a_bytes = out[a[1]:a[2]]
        b_bytes = out[b[1]:b[2]]
        start = a[1]
        end = b[2]
        return out[:start] + b_bytes + a_bytes + out[end:]

    def _tweak_app_payload(self, out: bytearray, segments: List[Tuple[int, int, int]]) -> bytearray:
        # 在 APPn 段中插入/替换小片段
        app_choices = [s for s in segments if 0xFFE0 <= s[0] <= 0xFFEF]
        if not app_choices:
            return out
        _, start, end = self.rng.choice(app_choices)
        if end - start <= 4:
            return out
        # 在 payload 中插入少量随机字节
        insert_pos = self.rng.randrange(start + 4, end)  # 留下头部
        chunk = bytearray(self.rng.getrandbits(8) for _ in range(self.rng.randrange(1, 8)))
        return out[:insert_pos] + chunk + out[insert_pos:]


if __name__ == "__main__":
    # 最小示例 JPEG（SOI + APP0 JFIF + EOI）用于展示变异
    example = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x02\x00\x00\x01\x00\x01\x00\x00\xFF\xD9"
    m = JPEGMutator(seed=123)
    print("原始长度:", len(example))
    for i in range(6):
        out = m.mutate(example, num_mutations=2)
        print(f"变异 {i+1}: 长度={len(out)} 头部={out[:8].hex()} 末尾={out[-4:].hex()}")

# 兼容性别名：有些调用/导入使用 `JpegMutator` 名称
JpegMutator = JPEGMutator
