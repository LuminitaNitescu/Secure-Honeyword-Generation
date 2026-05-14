import sys

from config import DEFAULT_K, DEFAULT_L, DEFAULT_MODEL_PATH, DEFAULT_SEED
from embedding import FastTextBackend
from hgt import HoneywordGenerator


def main() -> None:
	if len(sys.argv) < 2:
		print("Usage: python mainv2.py <password>")
		return

	password = sys.argv[1].strip()
	if not password:
		print("Password cannot be empty.")
		return

	backend = FastTextBackend(DEFAULT_MODEL_PATH)
	generator = HoneywordGenerator(
		backend=backend,
		k=DEFAULT_K,
		l=DEFAULT_L,
		seed=DEFAULT_SEED,
	)
	honeywords = generator.generate(password)
	print(honeywords)
	print(len(honeywords))


if __name__ == "__main__":
	main()
