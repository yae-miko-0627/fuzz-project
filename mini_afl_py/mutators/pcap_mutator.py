"""PCAP 变异器（AFL++ 风格混合包感知与字节级变异）。

设计目标：
- 在包级别执行语义友好的操作（删除/复制/交换/插入包、用其他样本拼接包），
- 在字节级执行通用的 havoc 操作（bitflip、arith、insert/delete 等），
- 在结构修改后更新对应的 `incl_len` 字段以保持文件一致性（在可能的情况下），
- 若解析失败则回退为字节级随机变异。

实现注意事项：仅实现对 libpcap classic 格式（global header 24 bytes，packet header 16 bytes）的轻量支持，
不追求完整解析所有变体（pcap-ng 等）。接口与其他 mutator 保持一致，`mutate(data)` 返回一个生成器，
每次 yield 一个变体（与 `HavocMutator` 一致）。
"""

from __future__ import annotations

import struct
import random
from typing import Iterable, List, Optional, Tuple


class PcapMutator:
    """混合的 PCAP 变异器。

    参数:
      rounds: 每次 mutate() 产生的候选数量（轮次），每轮在原始输入上应用若干随机操作并 yield 一个变体。
      corpus: 可选语料库（字节序列列表），用于 splice/复制操作。
      seed: 随机种子，用于可重复性。
    """

    def __init__(self, rounds: int = 20, corpus: Optional[List[bytes]] = None, seed: Optional[int] = None):
        self.rounds = int(rounds)
        self.corpus = list(corpus) if corpus else []
        self.rng = random.Random(seed)

    # --- parsing helpers -------------------------------------------------
    def _parse_pcap(self, data: bytes) -> Tuple[dict, List[dict]]:
        """解析简单的 pcap 文件结构。

        返回 (global_header, packets)
        - global_header 包含键 'endian' 和原始 header bytes
        - packets 为列表，每项是 dict：{'hdr_off','data_off','incl_off','incl_len','orig_len'}
        在无法解析时抛出异常。
        """
        if len(data) < 24:
            raise ValueError('data too short for pcap global header')
        # 先用小端读魔数（安全）
        magic = struct.unpack_from('<I', data, 0)[0]
        if magic == 0xa1b2c3d4:
            endian = '<'
        elif magic == 0xd4c3b2a1:
            endian = '>'
        else:
            # 非标准魔数，抛出异常让上层回退
            raise ValueError('unsupported pcap magic')

        packets: List[dict] = []
        off = 24
        n = len(data)
        while off + 16 <= n:
            try:
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from(endian + 'IIII', data, off)
            except struct.error:
                break
            data_start = off + 16
            data_end = data_start + incl_len
            if data_end > n:
                break
            pkt = {
                'hdr_off': off,
                'ts_off': off,
                'incl_off': off + 8,
                'data_off': data_start,
                'incl_len': incl_len,
                'orig_len': orig_len,
            }
            packets.append(pkt)
            off = data_end

        gh = {'endian': endian, 'raw': data[:24]}
        return gh, packets

    def _fallback(self, data: bytes) -> Iterable[bytes]:
        """简单的字节级回退变异，保证在解析失败时仍能产出候选。"""
        if not data:
            return
        for _ in range(min(5, self.rounds)):
            b = bytearray(data)
            # 随机单字节改动
            i = self.rng.randrange(len(b))
            b[i] = (b[i] + self.rng.randrange(1, 255)) & 0xFF
            yield bytes(b)

    # --- low-level helpers ------------------------------------------------
    def _write_incl(self, out: bytearray, incl_off: int, endian: str, new_len: int) -> None:
        try:
            struct.pack_into(endian + 'I', out, incl_off, int(new_len) & 0xFFFFFFFF)
        except Exception:
            pass

    # --- packet-level operations -----------------------------------------
    def _drop_packet(self, out: bytearray, gh: dict, pkts: List[dict]) -> bytearray:
        if not pkts:
            return out
        idx = self.rng.randrange(len(pkts))
        pkt = pkts[idx]
        start = pkt['hdr_off']
        end = pkt['data_off'] + pkt['incl_len']
        return out[:start] + out[end:]

    def _dup_packet(self, out: bytearray, gh: dict, pkts: List[dict]) -> bytearray:
        if not pkts:
            return out
        pkt = self.rng.choice(pkts)
        start = pkt['hdr_off']
        end = pkt['data_off'] + pkt['incl_len']
        segment = out[start:end]
        insert_at = end
        return out[:insert_at] + segment + out[insert_at:]

    def _swap_adjacent(self, out: bytearray, gh: dict, pkts: List[dict]) -> bytearray:
        if len(pkts) < 2:
            return out
        idx = self.rng.randrange(len(pkts) - 1)
        a = pkts[idx]
        b = pkts[idx + 1]
        a_start = a['hdr_off']
        a_end = a['data_off'] + a['incl_len']
        b_start = b['hdr_off']
        b_end = b['data_off'] + b['incl_len']
        a_bytes = out[a_start:a_end]
        b_bytes = out[b_start:b_end]
        return out[:a_start] + b_bytes + a_bytes + out[b_end:]

    def _mutate_packet_bytes(self, out: bytearray, gh: dict, pkts: List[dict]) -> bytearray:
        if not pkts:
            return out
        pkt = self.rng.choice(pkts)
        ds = pkt['data_off']
        L = pkt['incl_len']
        if L <= 0:
            return out
        # number of byte edits proportional to size
        edits = max(1, min(8, L // 32))
        for _ in range(edits):
            i = self.rng.randrange(ds, ds + L)
            op = self.rng.choice(['flip', 'xor', 'set', 'arith'])
            if op == 'flip':
                bit = 1 << self.rng.randrange(8)
                out[i] ^= bit
            elif op == 'xor':
                out[i] ^= self.rng.randrange(1, 256)
            elif op == 'set':
                out[i] = self.rng.randrange(0, 256)
            else:
                delta = self.rng.randint(-20, 20)
                out[i] = (out[i] + delta) & 0xFF
        return out

    def _corrupt_incl_len(self, out: bytearray, gh: dict, pkts: List[dict]) -> bytearray:
        if not pkts:
            return out
        pkt = self.rng.choice(pkts)
        new_len = max(0, pkt['incl_len'] + self.rng.randint(-8, 32))
        self._write_incl(out, pkt['incl_off'], gh['endian'], new_len)
        return out

    def _splice_with_corpus(self, out: bytearray, gh: dict, pkts: List[dict]) -> bytearray:
        # 从语料库中选择另一条样本（若有），把其一个包插入到当前文件末尾
        if not self.corpus:
            return out
        other = self.rng.choice(self.corpus)
        try:
            ogh, opkts = self._parse_pcap(other)
        except Exception:
            return out
        if not opkts:
            return out
        pkt = self.rng.choice(opkts)
        start = pkt['hdr_off']
        end = pkt['data_off'] + pkt['incl_len']
        segment = other[start:end]
        return out + bytearray(segment)

    # --- havoc-like byte ops across whole file ----------------------------
    def _havoc_bytes(self, out: bytearray) -> bytearray:
        ops = ['flip', 'xor', 'set', 'insert', 'delete', 'copy']
        n = max(1, min(10, len(out) // 100))
        for _ in range(n):
            op = self.rng.choice(ops)
            if op == 'flip' and out:
                idx = self.rng.randrange(len(out))
                bit = 1 << self.rng.randrange(8)
                out[idx] ^= bit
            elif op == 'xor' and out:
                idx = self.rng.randrange(len(out))
                out[idx] ^= self.rng.randrange(1, 256)
            elif op == 'set' and out:
                idx = self.rng.randrange(len(out))
                out[idx] = self.rng.randrange(0, 256)
            elif op == 'insert':
                idx = self.rng.randrange(len(out)+1) if out else 0
                out.insert(idx, self.rng.randrange(0, 256))
            elif op == 'delete' and out:
                idx = self.rng.randrange(len(out))
                del out[idx]
            elif op == 'copy' and out:
                if len(out) > 4:
                    s = self.rng.randrange(0, len(out)-1)
                    l = self.rng.randrange(1, min(64, len(out)-s))
                    seg = out[s:s+l]
                    idx = self.rng.randrange(len(out)+1)
                    for b in reversed(seg):
                        out.insert(idx, b)
        return out

    # --- public mutate API -----------------------------------------------
    def mutate(self, data: bytes) -> Iterable[bytes]:
        """按轮产生变体；在解析失败时回退为字节级变异生成器。"""
        try:
            gh, pkts = self._parse_pcap(data)
        except Exception:
            yield from self._fallback(data)
            return

        # 先产出少量包级确定性变体
        # truncate at random packet
        if pkts and self.rng.random() < 0.3:
            idx = self.rng.randrange(len(pkts))
            out = bytearray(data[: pkts[idx]['hdr_off']])
            yield bytes(out)

        # duplicate a packet
        if pkts and self.rng.random() < 0.3:
            out = self._dup_packet(bytearray(data), gh, pkts)
            yield bytes(out)

        # splice from corpus
        if self.corpus and self.rng.random() < 0.25:
            out = self._splice_with_corpus(bytearray(data), gh, pkts)
            yield bytes(out)

        # 然后进行若干轮混合变异
        for _ in range(self.rounds):
            out = bytearray(data)
            # packet-level ops count
            pkt_ops = self.rng.randint(0, 3)
            for __ in range(pkt_ops):
                op = self.rng.choice(['drop', 'dup', 'swap', 'pkt_bytes', 'incl_corrupt'])
                if op == 'drop':
                    out = self._drop_packet(out, gh, pkts)
                elif op == 'dup':
                    out = self._dup_packet(out, gh, pkts)
                elif op == 'swap':
                    out = self._swap_adjacent(out, gh, pkts)
                elif op == 'pkt_bytes':
                    out = self._mutate_packet_bytes(out, gh, pkts)
                else:
                    out = self._corrupt_incl_len(out, gh, pkts)
                # try reparsing; if fails fallback to byte havoc
                try:
                    gh, pkts = self._parse_pcap(bytes(out))
                except Exception:
                    # parsing failed; allow byte-level havoc to proceed
                    pass

            # byte-level havoc
            out = self._havoc_bytes(out)

            yield bytes(out)


if __name__ == '__main__':
    # quick local smoke test
    global_hdr = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    pkt_hdr = struct.pack('<IIII', 0, 0, 4, 4)
    pkt_data = b'ABCD'
    example = global_hdr + pkt_hdr + pkt_data
    m = PcapMutator(rounds=6, seed=1)
    print('原始长度:', len(example))
    for i, out in enumerate(m.mutate(example)):
        print(f'变异 {i+1}: 长度={len(out)}')
