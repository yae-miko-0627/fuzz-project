"""
JPEG 专用变异器（适用于 .jpg/.jpeg）

实现要点：
- 解析 JPEG 段并保护 SOI/EOI 以及常见头段，主要对 SOS（scan data）之间的压缩数据进行变异；
- 对可变数据使用已有基础变异器（Bitflip/Arith/Interest/Havoc），变体通过截断或填充保持原始扫描区长度不变；
- 提供 per_scan_limit 与 max_variants 控制产出；
- 采用保守文本/二进制策略，不重建哈夫曼表或重新编码，仅做字节级扰动以供模糊触发解析/解码错误。

限制：变异通常会产生不可解码的图像，但这在 fuzzing 中可用以触发解码器缺陷；如需更高可用性，可后续实现基于 jpeg 解码/重编码的变异。
"""
from __future__ import annotations

import struct
from typing import Iterable, List, Optional

from .bitflip_mutator import BitflipMutator
from .arith_mutator import ArithMutator
from .interest_mutator import InterestMutator
from .havoc_mutator import HavocMutator


SOI = b"\xff\xd8"
EOI = b"\xff\xd9"


class JpegMutator:
    def __init__(self, mutators: Optional[List] = None, per_scan_limit: int = 50, max_variants: int = 200):
        if mutators is None:
            mutators = [BitflipMutator(max_bits=256), ArithMutator(max_positions=64), InterestMutator(max_positions=64), HavocMutator(rounds=4, max_changes=6)]
        self.mutators = mutators
        self.per_scan_limit = int(per_scan_limit)
        self.max_variants = int(max_variants)

    def _is_jpeg(self, data: bytes) -> bool:
        return data.startswith(SOI) and data.endswith(EOI)

    def mutate(self, data: bytes) -> Iterable[bytes]:
        if not self._is_jpeg(data):
            return

        L = len(data)

        # 查找 SOS (0xFFDA) 和 EOI (0xFFD9)。我们将把 SOS 头后的数据段视为压缩扫描数据，直到下一个 0xFF 标记表示 EOI 或下一个段。
        # 简化方法：找到第一个 SOS 标记和最后一个 EOI 标记；中间部分视为扫描数据。
        sos_idx = data.find(b"\xff\xda")
        eoi_idx = data.rfind(EOI)
        if sos_idx == -1 or eoi_idx == -1 or sos_idx >= eoi_idx:
            return

        # SOS 头长度：标记后的两个字节表示该头长度
        try:
            # 标记位于 sos_idx，长度位于 sos_idx+2..+4
            sos_len = struct.unpack('>H', data[sos_idx+2:sos_idx+4])[0]
            scan_start = sos_idx + 2 + sos_len
        except Exception:
            # 回退：假定扫描数据紧跟在 marker+2 之后开始
            scan_start = sos_idx + 2

        scan_end = eoi_idx
        if scan_start >= scan_end:
            return

        scan_data = data[scan_start:scan_end]

        variants = 0
        per_scan = 0

        for mut in self.mutators:
            if variants >= self.max_variants or per_scan >= self.per_scan_limit:
                break
            try:
                for v in mut.mutate(scan_data):
                    if variants >= self.max_variants or per_scan >= self.per_scan_limit:
                        break
                    if v is None:
                        continue
                    # 保持长度
                    if len(v) != len(scan_data):
                        if len(v) > len(scan_data):
                            v_use = v[:len(scan_data)]
                        else:
                            v_use = v + b'\x00' * (len(scan_data) - len(v))
                    else:
                        v_use = v

                    out = bytearray()
                    out.extend(data[:scan_start])
                    out.extend(v_use)
                    out.extend(data[scan_end:])

                    yield bytes(out)
                    variants += 1
                    per_scan += 1
            except Exception:
                continue

        return


__all__ = ["JpegMutator"]
