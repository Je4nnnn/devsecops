#!/usr/bin/env python3
import argparse
import sys
import xml.etree.ElementTree as ET


def cobertura_percent(path: str) -> float:
    root = ET.parse(path).getroot()
    rate = root.attrib.get("line-rate")
    if rate is None:
        raise ValueError("coverage.xml no contiene el atributo line-rate")
    return float(rate) * 100.0


def lcov_percent(path: str) -> float:
    found = hit = 0
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line.startswith("LF:"):
                found += int(line.split(":", 1)[1])
            elif line.startswith("LH:"):
                hit += int(line.split(":", 1)[1])
    if found == 0:
        raise ValueError("lcov.info no contiene lineas medibles")
    return (hit / found) * 100.0


def main() -> int:
    parser = argparse.ArgumentParser(description="Quality gate de cobertura para Jenkins")
    parser.add_argument("--type", choices=["cobertura", "lcov"], required=True)
    parser.add_argument("--file", required=True)
    parser.add_argument("--minimum", type=float, required=True)
    parser.add_argument("--label", default="Coverage")
    args = parser.parse_args()

    try:
        percent = cobertura_percent(args.file) if args.type == "cobertura" else lcov_percent(args.file)
    except Exception as exc:
        print(f"GATE {args.label}: ERROR leyendo cobertura: {exc}", file=sys.stderr)
        return 1

    print(f"GATE {args.label}: cobertura {percent:.2f}% / minimo {args.minimum:.2f}%")
    if percent < args.minimum:
        print(f"GATE {args.label}: FAIL", file=sys.stderr)
        return 1

    print(f"GATE {args.label}: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
