"""Testes do módulo de relatório."""

import json

from forense_memoria_simples.ioc import IOC
from forense_memoria_simples.report import Report, build_report
from forense_memoria_simples.strings import ExtractedString


def test_build_report_contagem():
    strings = [ExtractedString(value="aaaa", offset=0)]
    iocs = [IOC(type="ipv4", value="1.2.3.4", string_index=0, context="aaaa 1.2.3.4")]
    report = build_report("dump.bin", strings, iocs)
    assert report.total_strings == 1
    assert report.ipv4_count == 1
    assert report.url_count == 0
    assert report.suspicious_command_count == 0


def test_report_texto_contem_resumo():
    report = Report(file_path="dump.bin", total_strings=5, iocs=[])
    texto = report.to_text()
    assert "dump.bin" in texto
    assert "Strings extraídas: 5" in texto
    assert "Nenhum IOC encontrado" in texto


def test_report_texto_lista_detalhes_dos_iocs():
    iocs = [
        IOC(type="url", value="https://evil.com", string_index=2, context="a https://evil.com b")
    ]
    report = Report(file_path="dump.bin", total_strings=3, iocs=iocs)
    texto = report.to_text()
    assert "https://evil.com" in texto
    assert "[url]" in texto


def test_report_json_eh_valido_e_contem_campos():
    report = Report(file_path="dump.bin", total_strings=2, iocs=[])
    payload = json.loads(report.to_json())
    assert payload["file_path"] == "dump.bin"
    assert payload["total_strings"] == 2
    assert payload["ioc_count"] == 0
    assert payload["iocs"] == []
