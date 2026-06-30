from __future__ import annotations

import argparse
from typing import Optional


def aggregate_sorted_file(input_path: str, output_path: str) -> None:
	with open(input_path, "r", encoding="utf-8") as reader, open(
		output_path, "w", encoding="utf-8"
	) as writer:
		current: Optional[str] = None
		count = 0
		max_count = 0
		max_count_password = None
		for raw_line in reader:
			line = raw_line.rstrip("\n")
			if line == "":
				continue
			if current is None:
				current = line
				count = 1
				continue
			if line == current:
				count += 1
				continue
			if count > max_count:
				max_count = count
				max_count_password = current
			writer.write(f"{current}\t{count}\n")
			current = line
			count = 1
 
		if current is not None:
			if count > max_count:
				max_count = count
				max_count_password = current
			writer.write(f"{current}\t{count}\n")
		print(f"Max count: {max_count}, password: {max_count_password}")
	   


def main() -> None:
	parser = argparse.ArgumentParser(
		description="Aggregate a sorted password file into 'password\\tcount' lines."
	)
	parser.add_argument("input", help="Path to sorted password file.")
	parser.add_argument("output", help="Path to write aggregates.")
	args = parser.parse_args()

	aggregate_sorted_file(args.input, args.output)


if __name__ == "__main__":
	main()
