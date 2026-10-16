"""Testes do módulo de IOC."""

from forense_memoria_simples.ioc import IOC, scan_iocs
from forense_memoria_simples.strings import ExtractedString


def _mk_strings(valores):
    return [ExtractedString(value=v, offset=i) for i, v in enumerate(valores)]


def test_detecta_enderecos_ipv4():
    strings = _mk_strings(
        [
            "conexao para 192.168.1.10",
            "sem ip aqui",
            "10.0.0.1 e 255.255.255.255",
        ]
    )
    iocs = scan_iocs(strings)
    ips = [ioc.value for ioc in iocs if ioc.type == "ipv4"]
    assert "192.168.1.10" in ips
    assert "10.0.0.1" in ips
    assert "255.255.255.255" in ips


def test_nao_detecta_ipv4_invalido():
    strings = _mk_strings(["999.999.999.999 nao e ip valido"])
    iocs = scan_iocs(strings)
    assert not any(ioc.type == "ipv4" for ioc in iocs)


def test_detecta_urls():
    strings = _mk_strings(["baixe em https://evil.com/payload.exe e ftp://ftp.x.br/"])
    iocs = scan_iocs(strings)
    urls = [ioc.value for ioc in iocs if ioc.type == "url"]
    assert any("https://evil.com/payload.exe" in u for u in urls)
    assert any("ftp://ftp.x.br/" in u for u in urls)


def test_detecta_comandos_suspeitos():
    strings = _mk_strings(["powershell -enc ABCD", "net user attacker /add"])
    iocs = scan_iocs(strings)
    comandos = [ioc.value for ioc in iocs if ioc.type == "suspicious_command"]
    assert "powershell" in comandos
    assert "net user" in comandos


def test_string_index_eh_posicao_na_lista():
    strings = _mk_strings(["limpo", "192.168.0.1"])
    iocs = scan_iocs(strings)
    assert len(iocs) == 1
    assert iocs[0].type == "ipv4"
    assert iocs[0].string_index == 1
    assert iocs[0].context == "192.168.0.1"


def test_sem_ioc_retorna_lista_vazia():
    strings = _mk_strings(["apenas texto inofensivo aqui"])
    assert scan_iocs(strings) == []


def test_ioc_eh_dataclass_imutavel():
    ioc = IOC(type="ipv4", value="1.2.3.4", string_index=0, context="x 1.2.3.4")
    assert ioc.type == "ipv4"
    try:
        ioc.type = "url"
    except Exception:
        pass
    else:
        raise AssertionError("esperava imutabilidade (frozen dataclass)")
