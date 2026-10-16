"""Testes da interface de linha de comando."""

from forense_memoria_simples.cli import main


def test_cli_saida_texto_contem_resumo(tmp_path, capsys):
    arquivo = tmp_path / "dump.bin"
    arquivo.write_bytes(b"conteudo limpo sem indicadores aqui")
    codigo = main([str(arquivo), "--min-len", "3"])
    assert codigo == 0
    capturado = capsys.readouterr()
    assert "Strings extraídas" in capturado.out
    assert "IOCs encontrados" in capturado.out


def test_cli_formato_json(tmp_path, capsys):
    arquivo = tmp_path / "dump.bin"
    arquivo.write_bytes(b"192.168.1.1")
    codigo = main([str(arquivo), "--format", "json"])
    assert codigo == 0
    capturado = capsys.readouterr()
    import json

    payload = json.loads(capturado.out)
    assert payload["ioc_count"] >= 1
    assert payload["iocs"][0]["type"] == "ipv4"
