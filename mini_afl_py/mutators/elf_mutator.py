"""
ELF 特殊变异器

功能：检测 ELF 文件并只对节区（section）内容进行变异，保护 ELF 头和节表不被破坏。
变异时复用已有基础变异器（bitflip/arith/interest/havoc），对每个可变节单独应用变异并产出完整文件变体。

限制：实现为轻量解析器，仅支持常见的 ELF32/ELF64 小端格式；遇到解析错误时静默返回不产生变体。
"""
from __future__ import annotations

import struct
from typing import Iterable, List, Optional

from .bitflip_mutator import BitflipMutator
from .arith_mutator import ArithMutator
from .interest_mutator import InterestMutator
from .havoc_mutator import HavocMutator


SHT_NOBITS = 8


def _is_elf(data: bytes) -> bool:
    return len(data) >= 4 and data[0:4] == b"\x7fELF"


class ElfMutator:
    """只对 ELF 节区内容进行变异的变异器包装器。

    参数:
      mutators: 可选的基础变异器列表（若为 None，则使用默认集合）
      per_section_limit: 每个节最大产出变体数量（防止爆炸）
    """

    def __init__(self, mutators: Optional[List] = None, per_section_limit: int = 200):
        if mutators is None:
            mutators = [
                BitflipMutator(max_bits=128),
                ArithMutator(max_positions=32),
                InterestMutator(max_positions=32),
                HavocMutator(rounds=6, max_changes=6),
            ]
        self.mutators = mutators
        self.per_section_limit = int(per_section_limit)

    def _parse_section_table(self, data: bytes):
        """解析 ELF 头和节表，返回节的 (sh_offset, sh_size, sh_type) 列表。"""
        if not _is_elf(data):
            return []

        # e_ident：前 16 字节
        if len(data) < 16:
            return []
        ei_class = data[4]
        ei_data = data[5]

        # 支持小端（1 = 小端, 2 = 大端）——优先小端
        if ei_data == 1:
            endian = '<'
        elif ei_data == 2:
            endian = '>'
        else:
            return []

        # 32 位或 64 位
        try:
            if ei_class == 1:  # ELF32
                # e_shoff 在偏移 32（uint32），e_shentsize 在 46（uint16），e_shnum 在 48（uint16）
                if len(data) < 52:
                    return []
                e_shoff = struct.unpack(endian + 'I', data[32:36])[0]
                e_shentsize = struct.unpack(endian + 'H', data[46:48])[0]
                e_shnum = struct.unpack(endian + 'H', data[48:50])[0]
                sh_fmt = endian + 'IIIIIIIIII'  # 粗略格式说明，按偏移提取需要的字段
                sec_size = 40
                entries = []
                for i in range(e_shnum):
                    off = e_shoff + i * e_shentsize
                    if off + sec_size > len(data):
                        break
                    sh = data[off:off+sec_size]
                    # sh_type 在偏移 4（uint32），sh_offset 在 16（uint32），sh_size 在 20（uint32）
                    sh_type = struct.unpack(endian + 'I', sh[4:8])[0]
                    sh_offset = struct.unpack(endian + 'I', sh[16:20])[0]
                    sh_size = struct.unpack(endian + 'I', sh[20:24])[0]
                    entries.append((sh_offset, sh_size, sh_type))
                return entries

            elif ei_class == 2:  # ELF64
                # e_shoff 在偏移 40（uint64），e_shentsize 在 58（uint16），e_shnum 在 60（uint16）
                if len(data) < 64:
                    return []
                e_shoff = struct.unpack(endian + 'Q', data[40:48])[0]
                e_shentsize = struct.unpack(endian + 'H', data[58:60])[0]
                e_shnum = struct.unpack(endian + 'H', data[60:62])[0]
                sec_size = 64
                entries = []
                for i in range(e_shnum):
                    off = e_shoff + i * e_shentsize
                    if off + sec_size > len(data):
                        break
                    sh = data[off:off+sec_size]
                    # sh_type 在偏移 4（uint32），sh_offset 在 24（uint64），sh_size 在 32（uint64）
                    sh_type = struct.unpack(endian + 'I', sh[4:8])[0]
                    sh_offset = struct.unpack(endian + 'Q', sh[24:32])[0]
                    sh_size = struct.unpack(endian + 'Q', sh[32:40])[0]
                    entries.append((sh_offset, sh_size, sh_type))
                return entries
        except Exception:
            return []

        return []

    def mutate(self, data: bytes) -> Iterable[bytes]:
        """对 ELF 数据的每个有数据的节分别应用基础变异器，产出完整文件变体。"""
        try:
            sections = self._parse_section_table(data)
        except Exception:
            sections = []

        if not sections:
            return

        L = len(data)
        count_total = 0
        for sh_offset, sh_size, sh_type in sections:
            # 跳过没有实际数据的节（如 .bss / SHT_NOBITS）或异常偏移
            if sh_size == 0:
                continue
            if sh_offset >= L or sh_offset + sh_size > L:
                continue
            if sh_type == SHT_NOBITS:
                continue

            section_bytes = data[sh_offset:sh_offset+sh_size]

            # 对该节依次应用各基础变异器
            per_sec_count = 0
            for mut in self.mutators:
                try:
                    for v in mut.mutate(section_bytes):
                        if v is None:
                            continue
                        # 构造新文件：替换节区数据
                        new_data = bytearray(data)
                        # 保证长度一致（不改变节大小）——若变体长度不同，尝试截断或填充
                        if len(v) != sh_size:
                            if len(v) > sh_size:
                                # 截断到原节大小
                                v_use = v[:sh_size]
                            else:
                                # 填充为原节大小（用 0 填充）
                                v_use = v + b"\x00" * (sh_size - len(v))
                        else:
                            v_use = v
                        new_data[sh_offset:sh_offset+sh_size] = v_use
                        yield bytes(new_data)
                        per_sec_count += 1
                        count_total += 1
                        if per_sec_count >= self.per_section_limit:
                            break
                    if per_sec_count >= self.per_section_limit:
                        break
                except Exception:
                    continue

        return


__all__ = ["ElfMutator"]
