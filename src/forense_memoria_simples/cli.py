"""Interface de linha de comando do forense-memoria-simples."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .ioc import scan_iocs
from .report import build_report
from .strings import extract_strings_from_file


def build_parser() -> argparse.ArgumentParser:
    """Constrói o parser de argumentos da CLI."""
    parser = argparse.ArgumentParser(
        prog="forense-memoria",
        description="Extrai strings imprimíveis e faz scan de IOCs de um dump de memória.",
    )
    parser.add_argument("file", help="Caminho do arquivo binário/dump a analisar")
    parser.add_argument(
        "--min-len",
        type=int,
        default=4,
        help="Tamanho mínimo de uma string extraída (padrão: 4)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Formato do relatório (padrão: text)",
    )
    parser.add_argument(
        "--output",
        help="Caminho do arquivo de saída (padrão: stdout)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Ponto de entrada da CLI.

    Args:
        argv: Argumentos de linha de comando (usa sys.argv se None).

    Returns:
        Código de saída (0 = sucesso).
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    strings = extract_strings_from_file(args.file, min_len=args.min_len)
    iocs = scan_iocs(strings)
    report = build_report(args.file, strings, iocs)

    text = report.to_json() if args.format == "json" else report.to_text()

    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
