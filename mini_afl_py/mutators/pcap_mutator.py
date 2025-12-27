"""轻量级 PCAP 变异器。

提供对常见 libpcap 文件格式的轻量解析与若干包级/字节级变异：
- 截断到某包、复制包、包内字节翻转、交换相邻包、破坏包长度字段

仅使用标准库实现，适合高速模糊测试中的快速候选生成。
"""
from __future__ import annotations

import struct
import random
from typing import List, Tuple, Optional


class PcapMutator:
    """轻量 PCAP 变异器实现（支持 pcap 普通格式）。"""

    def __init__(self, seed: Optional[int] = None) -> None:
        self.rng = random.Random(seed)

    def mutate(self, data: bytes, num_mutations: int = 1) -> bytes:
        try:
            global_hdr, packets = self._parse_pcap(data)
        except Exception:
            return self._fallback_byte_mutation(data)

        out = bytearray(data)
        for _ in range(num_mutations):
            ops = [self._truncate_at_packet, self._flip_bytes_in_packet,
                   self._duplicate_packet, self._swap_adjacent_packets,
                   self._corrupt_incl_len]
            op = self.rng.choice(ops)
            try:
                out = op(out, global_hdr, packets)
                # reparse after structural changes
                global_hdr, packets = self._parse_pcap(bytes(out))
            except Exception:
                continue

        return bytes(out)

    def _parse_pcap(self, data: bytes) -> Tuple[dict, List[Tuple[int,int,int,int]]]:
        # 返回 (global_header_dict, packets_list)
        # packets_list 中每项为 (offset_ts_sec, offset_ts_usec, offset_incl_len, offset_data_start)
        if len(data) < 24:
            raise ValueError('too short')
        magic = struct.unpack_from('<I', data, 0)[0]
        if magic == 0xa1b2c3d4:
            endian = '<'
        elif magic == 0xd4c3b2a1:
            endian = '>'
        else:
            # 不能识别的魔法数，尝试小端
            endian = '<'

        # global header fields but we only need to know header size
        # parse packet records
        off = 24
        n = len(data)
        packets = []
        while off + 16 <= n:
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from(endian + 'IIII', data, off)
            data_start = off + 16
            data_end = data_start + incl_len
            if data_end > n:
                # malformed, truncate parsing
                break
            packets.append((off, off+4, off+8, data_start))
            off = data_end

        global_hdr = {'endian': endian}
        return global_hdr, packets

    def _fallback_byte_mutation(self, data: bytes) -> bytes:
        b = bytearray(data)
        if not b:
            return data
        i = self.rng.randrange(len(b))
        b[i] = (b[i] + self.rng.randrange(1,255)) & 0xFF
        return bytes(b)

    def _truncate_at_packet(self, out: bytearray, gh: dict, packets) -> bytearray:
        if not packets:
            return out
        idx = self.rng.randrange(len(packets))
        off = packets[idx][0]
        return out[:off]

    def _flip_bytes_in_packet(self, out: bytearray, gh: dict, packets) -> bytearray:
        if not packets:
            return out
        pkt = self.rng.choice(packets)
        data_start = pkt[3]
        # get incl_len from header
        incl_len = struct.unpack_from(gh['endian'] + 'I', out, pkt[2])[0]
        if incl_len == 0:
            return out
        for _ in range(max(1, incl_len // 50)):
            i = self.rng.randrange(data_start, data_start + incl_len)
            out[i] = (out[i] ^ self.rng.randrange(1,256)) & 0xFF
        return out

    def _duplicate_packet(self, out: bytearray, gh: dict, packets) -> bytearray:
        if not packets:
            return out
        pkt = self.rng.choice(packets)
        start = pkt[0]
        # compute incl_len
        incl_len = struct.unpack_from(gh['endian'] + 'I', out, pkt[2])[0]
        data_start = pkt[3]
        data_end = data_start + incl_len
        segment = out[start:data_end]
        insert_at = data_end
        return out[:insert_at] + segment + out[insert_at:]

    def _swap_adjacent_packets(self, out: bytearray, gh: dict, packets) -> bytearray:
        if len(packets) < 2:
            return out
        idx = self.rng.randrange(len(packets) - 1)
        a_start = packets[idx][0]
        a_incl = struct.unpack_from(gh['endian'] + 'I', out, packets[idx][2])[0]
        a_data_start = packets[idx][3]
        a_end = a_data_start + a_incl
        b_start = packets[idx+1][0]
        b_incl = struct.unpack_from(gh['endian'] + 'I', out, packets[idx+1][2])[0]
        b_data_start = packets[idx+1][3]
        b_end = b_data_start + b_incl
        a_bytes = out[a_start:a_end]
        b_bytes = out[b_start:b_end]
        return out[:a_start] + b_bytes + a_bytes + out[b_end:]

    def _corrupt_incl_len(self, out: bytearray, gh: dict, packets) -> bytearray:
        if not packets:
            return out
        pkt = self.rng.choice(packets)
        off_incl = pkt[2]
        # set a new incl_len possibly larger or smaller
        new_len = max(0, self.rng.randrange(0, 65535))
        struct.pack_into(gh['endian'] + 'I', out, off_incl, new_len)
        return out


if __name__ == '__main__':
    # 最小 pcap 示例：global header + one empty packet
    # 使用小端 magic 0xd4c3b2a1 for demonstration
    global_hdr = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    # one packet: ts_sec, ts_usec, incl_len, orig_len, data
    pkt_hdr = struct.pack('<IIII', 0, 0, 4, 4)
    pkt_data = b'ABCD'
    example = global_hdr + pkt_hdr + pkt_data
    m = PcapMutator(seed=1)
    print('原始长度:', len(example))
    for i in range(6):
        out = m.mutate(example, num_mutations=2)
        print(f'变异 {i+1}: 长度={len(out)}')
