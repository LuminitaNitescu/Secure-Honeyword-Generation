from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Optional

import fasttext


class EmbeddingBackend(ABC):
	@property
	@abstractmethod
	def name(self) -> str:
		pass

	@abstractmethod
	def load(self) -> None:
		pass

	@abstractmethod
	def nearest_neighbors(self, word: str, k: int) -> List[str]:
		pass


class FastTextBackend(EmbeddingBackend):
	def __init__(self, model_path: str) -> None:
		self.model_path = model_path
		self._model: Optional[fasttext.FastText] = None

	@property
	def name(self) -> str:
		return "fasttext"

	def load(self) -> None:
		if self._model is None:
			self._model = fasttext.load_model(self.model_path)

	def nearest_neighbors(self, word: str, k: int) -> List[str]:
		if k <= 0:
			return []
		self.load()
		neighbors = self._model.get_nearest_neighbors(word, k)
		return [neighbor for _score, neighbor in neighbors]