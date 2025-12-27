"""轻量且高效的 ELF 专用变异器。

特性（轻量实现）：
- 使用 stdlib `struct` 做最小 ELF 头 / 节表解析（支持 ELF32/ELF64 小端/大端）。
- 变异策略：头字段微扰（e_entry/e_phoff/e_shoff/e_type 等小幅偏移）、字符串表（SHT_STRTAB）内字符串替换/截断/交换、节内字节级小幅翻转。
- 安全性：输出数量受 `max_outputs` 限制；对边界和解析失败做回退处理。解析失败时回退到简单字节级变异。

设计目标：在保持轻量和高吞吐的同时提高触发格式相关代码路径的概率。
"""

from __future__ import annotations

import struct
import random
from typing import Iterable, Optional, List, Tuple


SHT_STRTAB = 3
SHT_NOBITS = 8


def _is_elf(data: bytes) -> bool:
	return len(data) >= 4 and data[0:4] == b"\x7fELF"


class ElfMutator:
	"""ELF 专用变异器（轻量实现）。

	参数:
	  seed: 可选随机种子，用于复现。
	  max_outputs: 每次 `mutate` 产出变体的上限（防止爆发）。
	"""

	def __init__(self, seed: Optional[int] = None, max_outputs: int = 40) -> None:
		self.rng = random.Random(seed)
		self.max_outputs = int(max_outputs)

	def mutate(self, data: bytes) -> Iterable[bytes]:
		"""对 ELF 数据产生若干变体（generator）。

		若无法解析 ELF，则回退为字节级简单变异以保证产出。
		"""
		# 尝试解析 ELF header 和节表
		try:
			hdr = self._parse_elf_header(data)
			sections = self._parse_section_table(data, hdr) if hdr else []
		except Exception:
			hdr = None
			sections = []

		count = 0

		# 1) 头部微扰
		if hdr:
			for out in self._mutate_header_fields(data, hdr):
				yield out
				count += 1
				if count >= self.max_outputs:
					return

		# 2) 针对字符串表做轻量替换/截断/交换
		if sections:
			strtabs = [s for s in sections if s.get('type') == SHT_STRTAB and s.get('size', 0) > 4]
			for off, size, idx in [(s['offset'], s['size'], s['index']) for s in strtabs]:
				for out in self._mutate_string_table(data, off, size):
					yield out
					count += 1
					if count >= self.max_outputs:
						return

		# 3) 节内字节级小扰动（对非 NOBITS 节）
		for s in sections:
			if s.get('type') == SHT_NOBITS:
				continue
			off = s.get('offset', 0)
			size = s.get('size', 0)
			if size <= 0 or off + size > len(data):
				continue
			for out in self._mutate_section_bytes(data, off, size):
				yield out
				count += 1
				if count >= self.max_outputs:
					return

		# 若什么都没生成，则返回一个简单的字节扰动
		if count == 0:
			yield from self._fallback_mutations(data)

	# ----------------- 解析与变异助手 -----------------
	def _parse_elf_header(self, data: bytes) -> Optional[dict]:
		if not _is_elf(data) or len(data) < 16:
			return None
		ei_class = data[4]
		ei_data = data[5]
		if ei_data == 1:
			endian = '<'
		elif ei_data == 2:
			endian = '>'
		else:
			return None

		try:
			if ei_class == 1 and len(data) >= 52:  # ELF32
				e_entry = struct.unpack_from(endian + 'I', data, 24)[0]
				e_phoff = struct.unpack_from(endian + 'I', data, 28)[0]
				e_shoff = struct.unpack_from(endian + 'I', data, 32)[0]
				e_shentsize = struct.unpack_from(endian + 'H', data, 46)[0]
				e_shnum = struct.unpack_from(endian + 'H', data, 48)[0]
				e_shstrndx = struct.unpack_from(endian + 'H', data, 50)[0]
				return {'class': 32, 'endian': endian, 'e_entry': e_entry, 'e_phoff': e_phoff, 'e_shoff': e_shoff, 'e_shentsize': e_shentsize, 'e_shnum': e_shnum, 'e_shstrndx': e_shstrndx}
			elif ei_class == 2 and len(data) >= 64:  # ELF64
				e_entry = struct.unpack_from(endian + 'Q', data, 24)[0]
				e_phoff = struct.unpack_from(endian + 'Q', data, 32)[0]
				e_shoff = struct.unpack_from(endian + 'Q', data, 40)[0]
				e_shentsize = struct.unpack_from(endian + 'H', data, 58)[0]
				e_shnum = struct.unpack_from(endian + 'H', data, 60)[0]
				e_shstrndx = struct.unpack_from(endian + 'H', data, 62)[0]
				return {'class': 64, 'endian': endian, 'e_entry': e_entry, 'e_phoff': e_phoff, 'e_shoff': e_shoff, 'e_shentsize': e_shentsize, 'e_shnum': e_shnum, 'e_shstrndx': e_shstrndx}
		except Exception:
			return None
		return None

	def _parse_section_table(self, data: bytes, hdr: dict) -> List[dict]:
		"""返回节表列表：每项包含 offset,size,type,index。"""
		out = []
		if not hdr:
			return out
		endian = hdr['endian']
		ei_class = hdr['class']
		shoff = hdr.get('e_shoff', 0)
		shentsize = hdr.get('e_shentsize', 0)
		shnum = hdr.get('e_shnum', 0)
		if shoff == 0 or shnum == 0:
			return out
		for i in range(min(shnum, 200)):
			off = shoff + i * shentsize
			if off + shentsize > len(data):
				break
			if ei_class == 32:
				sh_type = struct.unpack_from(endian + 'I', data, off + 4)[0]
				sh_offset = struct.unpack_from(endian + 'I', data, off + 16)[0]
				sh_size = struct.unpack_from(endian + 'I', data, off + 20)[0]
			else:
				sh_type = struct.unpack_from(endian + 'I', data, off + 4)[0]
				sh_offset = struct.unpack_from(endian + 'Q', data, off + 24)[0]
				sh_size = struct.unpack_from(endian + 'Q', data, off + 32)[0]
			out.append({'index': i, 'offset': sh_offset, 'size': sh_size, 'type': sh_type})
		return out

	# ----------------- 具体变异策略 -----------------
	def _mutate_header_fields(self, data: bytes, hdr: dict) -> Iterable[bytes]:
		"""对 e_entry/e_phoff/e_shoff/e_type 等做小幅扰动并产生变体。"""
		endian = hdr['endian']
		cls = hdr['class']
		try:
			if cls == 32 and len(data) >= 52:
				e_entry_off = 24
				e_type_off = 16
				e_entry = struct.unpack_from(endian + 'I', data, e_entry_off)[0]
				for d in (1, -1, 16, -16, 256):
					nd = bytearray(data)
					struct.pack_into(endian + 'I', nd, e_entry_off, (e_entry + d) & 0xFFFFFFFF)
					yield bytes(nd)
				for t in (2, 3):
					nd = bytearray(data)
					struct.pack_into(endian + 'H', nd, e_type_off, t)
					yield bytes(nd)
			elif cls == 64 and len(data) >= 64:
				e_entry_off = 24
				e_type_off = 16
				e_entry = struct.unpack_from(endian + 'Q', data, e_entry_off)[0]
				for d in (1, -1, 16, -16, 256):
					nd = bytearray(data)
					struct.pack_into(endian + 'Q', nd, e_entry_off, (e_entry + d) & 0xFFFFFFFFFFFFFFFF)
					yield bytes(nd)
				for t in (2, 3):
					nd = bytearray(data)
					struct.pack_into(endian + 'H', nd, e_type_off, t)
					yield bytes(nd)
			# 也对 e_ident 的部分字节做少量可见变异，便于 demo 观察
			try:
				nd = bytearray(data)
				# 切换 class 字段（offset 4）在 1/2 之间
				if len(nd) > 5:
					nd[4] = 2 if nd[4] == 1 else 1
					yield bytes(nd)
				nd2 = bytearray(data)
				# 切换 data 字段（offset 5）在 little/big 端表示之间
				if len(nd2) > 6:
					nd2[5] = 2 if nd2[5] == 1 else 1
					yield bytes(nd2)
			except Exception:
				pass
		except Exception:
			return

	def _mutate_string_table(self, data: bytes, off: int, size: int) -> Iterable[bytes]:
		"""对字符串表做轻量替换/截断/交换变异，保持总体长度不大幅变化。"""
		if off + size > len(data) or size < 4:
			return
		tbl = data[off:off+size]
		strs: List[Tuple[int, bytes]] = []
		cur = 0
		while cur < len(tbl):
			end = tbl.find(b'\x00', cur)
			if end == -1:
				break
			s = tbl[cur:end]
			strs.append((cur, s))
			cur = end + 1

		common = [b'main', b'_start', b'init', b'malloc', b'free']
		out_count = 0
		for idx, s in strs:
			if out_count >= 6:
				break
			if len(s) == 0:
				continue
			nd = bytearray(data)
			new_s = s
			r = self.rng.random()
			if r < 0.3:
				new_s = self.rng.choice(common)
			elif r < 0.6:
				new_s = s[::-1]
			else:
				new_s = s[:max(1, len(s)//2)]
			write = new_s + b'\x00' * max(0, len(s) - len(new_s))
			nd[off + idx: off + idx + len(write)] = write
			out_count += 1
			yield bytes(nd)

		if len(strs) >= 2:
			a,b = self.rng.sample(strs, 2)
			nd = bytearray(data)
			sa = a[1]; sb = b[1]
			la = len(sa); lb = len(sb)
			va = (sb[:la] + b'\x00'*max(0, la-lb))[:la]
			vb = (sa[:lb] + b'\x00'*max(0, lb-la))[:lb]
			nd[off + a[0]: off + a[0] + la] = va
			nd[off + b[0]: off + b[0] + lb] = vb
			yield bytes(nd)

	def _mutate_section_bytes(self, data: bytes, off: int, size: int) -> Iterable[bytes]:
		"""在节的 payload 中进行少量字节翻转或随机异或。"""
		if size <= 0 or off + size > len(data):
			return
		max_changes = max(1, min(8, size // 64))
		for _ in range(2):
			nd = bytearray(data)
			changes = self.rng.randrange(1, max_changes+1)
			for _c in range(changes):
				i = self.rng.randrange(off, off + size)
				nd[i] = (nd[i] ^ self.rng.randrange(1, 256)) & 0xFF
			yield bytes(nd)

	def _fallback_mutations(self, data: bytes) -> Iterable[bytes]:
		if not data:
			return
		b = bytearray(data)
		i = self.rng.randrange(len(b))
		b[i] = (b[i] ^ self.rng.randrange(1, 256)) & 0xFF
		yield bytes(b)


if __name__ == "__main__":
	sample = b"\x7fELF" + b"\x01\x01\x01\x00" + bytes(60)
	m = ElfMutator(seed=42, max_outputs=10)
	print("原始长度:", len(sample))
	k = 0
	for v in m.mutate(sample):
		k += 1
		# 打印前 40 字节，便于观察 header 相关字段的变更
		print(f"变体 {k}: 长度={len(v)} head={v[:40].hex()}")
		if k >= 8:
			break

