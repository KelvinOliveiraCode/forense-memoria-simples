"""Testes do módulo de extração de strings."""

from forense_memoria_simples.strings import extract_strings


def test_extrai_strings_imprimiveis_de_binario():
    data = b"hello world\x00malware.exe\x01http://evil.com/x"
    valores = [s.value for s in extract_strings(data, min_len=3)]
    assert "hello world" in valores
    assert "malware.exe" in valores
    assert "http://evil.com/x" in valores


def test_min_len_filtra_strings_curtas():
    data = b"ab\x00cd\x00efgh\x00ijkl"
    valores = [s.value for s in extract_strings(data, min_len=4)]
    assert valores == ["efgh", "ijkl"]


def test_dados_vazios_retornam_lista_vazia():
    assert extract_strings(b"", min_len=4) == []


def test_offset_indica_inicio_da_string():
    data = b"\x00\x00ABCD\x00"
    resultado = extract_strings(data, min_len=2)
    assert len(resultado) == 1
    assert resultado[0].value == "ABCD"
    assert resultado[0].offset == 2


def test_quebra_em_bytes_nao_imprimiveis():
    data = b"linha1\r\nlinha2\t"
    valores = [s.value for s in extract_strings(data, min_len=3)]
    assert valores == ["linha1", "linha2"]


def test_min_len_invalido_erra():
    try:
        extract_strings(b"abcd", min_len=0)
    except ValueError:
        pass
    else:
        raise AssertionError("esperava ValueError para min_len < 1")
