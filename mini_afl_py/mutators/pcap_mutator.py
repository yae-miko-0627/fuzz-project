"""
PCAP 专用变异器

说明：解析 pcap 全局头与每个 packet header（pcap/libpcap 格式），保护全局头与每个包的报头字段（ts_sec/ts_usec/incl_len/orig_len），只对 packet data 部分应用基础变异器。

实现要点：
- 支持常见 little-endian pcap magic (0xa1b2c3d4) 和 nanosecond variant (0xa1b23c4d)；
- 对每个 packet data 使用已有变异器（Bitflip/Havoc/Arith/Interest）生成变体，保持 incl_len 大小不变（通过截断或填充）；
- 提供每包产出上限与全局上限；
- 对不可解析或异常数据安全返回（不抛异常）。
"""
from __future__ import annotations

import struct
from typing import Iterable, List, Optional

from .bitflip_mutator import BitflipMutator
from .havoc_mutator import HavocMutator
from .arith_mutator import ArithMutator
from .interest_mutator import InterestMutator


class PcapMutator:
    """PCAP 文件级变异器。

    参数：
      mutators: 列表，基础变异器实例（若 None 则使用默认集合）
      per_packet_limit: 每个 packet 最大产出变体数
      max_variants: 全局最大产出变体数
    """

    def __init__(self, mutators: Optional[List] = None, per_packet_limit: int = 20, max_variants: int = 200):
        if mutators is None:
            mutators = [BitflipMutator(max_bits=256), ArithMutator(max_positions=64), InterestMutator(max_positions=64), HavocMutator(rounds=4, max_changes=6)]
        self.mutators = mutators
        self.per_packet_limit = int(per_packet_limit)
        self.max_variants = int(max_variants)

    def _parse_global_header(self, data: bytes):
        # 全局头为 24 字节
        if len(data) < 24:
            return None
        magic = data[0:4]
        # 检测字节序与时间戳精度
        # 常见的 magic 值：
        # 0xa1b2c3d4（小端），0xd4c3b2a1（大端）
        # 0xa1b23c4d（纳秒小端），0x4d3cb2a1（纳秒大端）
        m = struct.unpack('<I', magic)[0]
        if m == 0xa1b2c3d4 or m == 0xa1b23c4d:
            endian = '<'
        else:
            # 尝试大端解析
            m2 = struct.unpack('>I', magic)[0]
            if m2 == 0xa1b2c3d4 or m2 == 0xa1b23c4d:
                endian = '>'
            else:
                return None
        # 解包全局头（大部分字段暂不使用，但保留头部字节）
        return endian

    def mutate(self, data: bytes) -> Iterable[bytes]:
        try:
            endian = self._parse_global_header(data)
        except Exception:
            endian = None
        if endian is None:
            return

        # 全局头（保持不变）
        if len(data) < 24:
            return
        global_hdr = data[:24]
        offset = 24
        L = len(data)

        variants = 0

        # 遍历每个数据包记录
        while offset + 16 <= L and variants < self.max_variants:
            # 每包头字段：ts_sec(4), ts_usec(4), incl_len(4), orig_len(4)
            try:
                ph = data[offset:offset+16]
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + 'IIII', ph)
            except Exception:
                break
            offset += 16
            if offset + incl_len > L:
                # 数据格式异常，停止解析
                break
            packet_data = data[offset:offset+incl_len]
            offset += incl_len

            if not packet_data:
                continue

            per_pkt_count = 0
            for mut in self.mutators:
                if variants >= self.max_variants or per_pkt_count >= self.per_packet_limit:
                    break
                try:
                    for v in mut.mutate(packet_data):
                        if variants >= self.max_variants or per_pkt_count >= self.per_packet_limit:
                            break
                        if v is None:
                            continue
                        # 确保与原始 incl_len 相同长度
                        if len(v) != incl_len:
                            if len(v) > incl_len:
                                v_use = v[:incl_len]
                            else:
                                v_use = v + b'\x00' * (incl_len - len(v))
                        else:
                            v_use = v

                        # 构建新的 pcap：复制全局头和所有包记录，替换当前包的数据
                        out = bytearray()
                        out.extend(global_hdr)

                        # 再次迭代以重建文件内容
                        roff = 24
                        pkt_index = 0
                        replaced = False
                        while roff + 16 <= L:
                            ph2 = data[roff:roff+16]
                            try:
                                ts2, tus2, il2, ol2 = struct.unpack(endian + 'IIII', ph2)
                            except Exception:
                                break
                            roff += 16
                            payload = data[roff:roff+il2]
                            roff += il2
                            if not replaced and pkt_index == per_pkt_count + 0:
                                # 这种按索引定位的方法不够健壮；应通过比较原始 payload 来定位
                                pass
                            # 我们通过扫描并比较原始 payload 的方式进行替换；即在匹配到与原始 packet_data 相同位置时进行替换
                            # 由于已捕获 packet_data，检查 payload 是否等于 packet_data 且尚未替换
                            if (not replaced) and payload == packet_data:
                                # 写入包头
                                out.extend(ph2)
                                out.extend(v_use)
                                replaced = True
                            else:
                                out.extend(ph2)
                                out.extend(payload)
                            pkt_index += 1

                        # 如果未能替换（不应发生），则跳过该变体
                        if not replaced:
                            continue

                        yield bytes(out)
                        variants += 1
                        per_pkt_count += 1
                except Exception:
                    continue

        return


__all__ = ["PcapMutator"]
