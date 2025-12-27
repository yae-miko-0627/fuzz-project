"""轻量级的 XML 变异器，用于模糊测试。

仅使用标准库，提供小巧且有效的 XML 专用变异策略。
"""
from __future__ import annotations

import random
import xml.etree.ElementTree as ET
from typing import Optional, List


class XMLMutator:
	"""紧凑的 XML 变异器，包含若干简单的变异策略。

	方法刻意保持简短并仅依赖标准库，以便在模糊测试循环中高效运行。
	"""

	def __init__(self, seed: Optional[int] = None) -> None:
		self._rng = random.Random(seed)

	def mutate(self, data: bytes, num_mutations: int = 1) -> bytes:
		try:
			root = ET.fromstring(data)
		except Exception:
			# 如果解析失败，回退为简单的字节级变异
			return self._fallback_mutation(data)

		for _ in range(num_mutations):
			ops = [self._insert_element, self._delete_element, self._tweak_attribute,
				   self._tweak_text, self._replace_entity]
			op = self._rng.choice(ops)
			try:
				op(root)
			except Exception:
				# 忽略单次操作失败并继续后续变异
				continue

		return ET.tostring(root, encoding="utf-8")

	def _fallback_mutation(self, data: bytes) -> bytes:
		b = bytearray(data)
		if not b:
			return data
		i = self._rng.randrange(len(b))
		b[i] = (b[i] + self._rng.randrange(1, 255)) & 0xFF
		return bytes(b)

	def _random_element(self, root: ET.Element) -> ET.Element:
		elems = list(root.iter())
		return self._rng.choice(elems) if elems else root

	def _insert_element(self, root: ET.Element) -> None:
		parent = self._random_element(root)
		# 创建一个小的随机标签，可带少量文本
		tag = "x" + str(self._rng.randrange(1000))
		new = ET.Element(tag)
		if self._rng.random() < 0.6:
			new.text = self._small_random_text()
		# 在随机位置作为子节点插入
		idx = self._rng.randrange(len(list(parent))) if list(parent) else 0
		children = list(parent)
		if children:
			parent.insert(idx, new)
		else:
			parent.append(new)

	def _delete_element(self, root: ET.Element) -> None:
		# 避免删除根节点本身
		elems = [e for e in list(root.iter()) if e is not root]
		if not elems:
			return
		target = self._rng.choice(elems)
		parent = self._find_parent(root, target)
		if parent is not None:
			for i, c in enumerate(list(parent)):
				if c is target:
					parent.remove(c)
					return

	def _tweak_attribute(self, root: ET.Element) -> None:
		el = self._random_element(root)
		if el.attrib:
			key = self._rng.choice(list(el.attrib.keys()))
			val = el.attrib.get(key, "")
			el.attrib[key] = self._small_mutation_string(val)
		else:
			# 添加一个小属性
			name = "a" + str(self._rng.randrange(100))
			el.attrib[name] = self._small_random_text()

	def _tweak_text(self, root: ET.Element) -> None:
		el = self._random_element(root)
		base = el.text or ""
		el.text = self._small_mutation_string(base)

	def _replace_entity(self, root: ET.Element) -> None:
		# 在所有文本节点中进行简单的实体替换（非完整 XML 实体解析）
		replacements = [("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"), ("&quot;", '"')]
		old, new = self._rng.choice(replacements)
		for el in root.iter():
			if el.text and old in el.text:
				el.text = el.text.replace(old, new, 1)

	def _small_random_text(self, max_len: int = 8) -> str:
		length = self._rng.randrange(1, max_len + 1)
		return ''.join(self._rng.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(length))

	def _small_mutation_string(self, s: str) -> str:
		if not s:
			return self._small_random_text()
		r = self._rng.random()
		if r < 0.4:
			# 替换一个字符
			i = self._rng.randrange(len(s))
			c = self._rng.choice('abcdxyz0123')
			return s[:i] + c + s[i+1:]
		elif r < 0.7:
			# 插入小片段
			i = self._rng.randrange(len(s)+1)
			return s[:i] + self._small_random_text(3) + s[i:]
		else:
			# 截断或追加
			if self._rng.random() < 0.5:
				return s[:max(1, len(s)//2)]
			else:
				return s + self._small_random_text(3)

	def _find_parent(self, root: ET.Element, child: ET.Element) -> Optional[ET.Element]:
		# 使用简单的深度优先搜索查找父节点（ElementTree 无父指针）
		stack: List[ET.Element] = [root]
		while stack:
			node = stack.pop()
			for c in list(node):
				if c is child:
					return node
				stack.append(c)
		return None


if __name__ == "__main__":
	example = b"""<?xml version='1.0'?>\n<root><item id=\"1\">hello &amp; world</item><group><sub>text</sub></group></root>"""
	m = XMLMutator(seed=42)
	print("Original:\n", example.decode('utf-8'))
	for i in range(5):
		out = m.mutate(example, num_mutations=2)
		print(f"\nMutation {i+1}:\n", out.decode('utf-8'))

# 兼容导入别名（有的代码期望 XmlMutator）
XmlMutator = XMLMutator

