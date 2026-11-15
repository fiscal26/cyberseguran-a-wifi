#!/usr/bin/env python3
"""Laboratório offline de senhas WPA2-Personal com PMKID; Python padrão."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from candidates import DEFAULT_SUFFIXES, combinations, mask_space, skip_candidates, variations


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


@dataclass
class SearchState:
    position: int = 0
    tested: int = 0
    skipped: int = 0
    elapsed: float = 0.0
    status: str = "running"


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


def parse_mac(value: str, label: str) -> bytes:
    # Aceita aa:bb:cc:dd:ee:ff, aa-bb-... ou 12 dígitos corridos.
    cleaned = value.replace(":", "").replace("-", "").strip()
    return hex_bytes(cleaned, label, 6)


def format_record(ssid: str, password: str, ap: bytes, station: bytes) -> str:
    """Monta um registro WPA*01 de laboratório a partir de uma senha conhecida."""
    ssid_bytes = ssid.encode("utf-8")
    pmk = derive_pmk(password, ssid_bytes)  # valida a senha e o tamanho do SSID
    pmkid = calculate_pmkid(pmk, ap, station)
    if pmkid == bytes(16):
        raise ValueError("PMKID resultou em zeros; troque os MACs")
    return f"WPA*01*{pmkid.hex()}*{ap.hex()}*{station.hex()}*{ssid_bytes.hex()}***"


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
    # UTF-8 com BOM é comum em arquivos salvos por editores no Windows.
    for number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
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


def match_password(records: list[Record], raw: bytes) -> Record | None:
    password = raw.decode("ascii")
    keys: dict[bytes, bytes] = {}
    for record in records:
        if record.ssid not in keys:
            keys[record.ssid] = derive_pmk(password, record.ssid)
        actual = calculate_pmkid(keys[record.ssid], record.ap, record.station)
        if hmac.compare_digest(actual, record.pmkid):
            return record
    return None


def valid_password(raw: bytes) -> bool:
    return 8 <= len(raw) <= 63 and all(32 <= c <= 126 for c in raw)


def crack(records: list[Record], candidates: Iterable[bytes]) -> Result:
    if not records:
        raise ValueError("é necessário ao menos um registro")
    tested = skipped = 0
    for raw in candidates:
        if not valid_password(raw):
            skipped += 1
            continue
        tested += 1
        record = match_password(records, raw)
        if record is not None:
            return Result(record, raw.decode("ascii"), tested, skipped)
    return Result(None, None, tested, skipped)


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def session_identity(args) -> str:
    settings = {"version": 1, "mode": args.command, "capture": file_digest(args.capture), "ssid": args.ssid}
    if args.command == "crack":
        settings.update(wordlist=file_digest(args.wordlist), variations=args.variations, suffixes=args.suffix)
    else:
        settings.update(charset=args.charset, minimum=args.min_length, maximum=args.max_length,
                        prefix=args.prefix, suffix=args.suffix)
    return hashlib.sha256(json.dumps(settings, sort_keys=True).encode()).hexdigest()


def save_session(path: Path, identity: str, state: SearchState):
    path.parent.mkdir(parents=True, exist_ok=True)
    # Arquivo temporário com permissão privada e troca atômica; não salva senhas.
    descriptor, name = tempfile.mkstemp(prefix=".wifi-session-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump({"version": 1, "identity": identity, "state": asdict(state)}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def load_session(path: Path, identity: str) -> SearchState:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if data["version"] != 1 or data["identity"] != identity:
            raise ValueError("arquivos ou parâmetros diferentes dos usados na sessão")
        state = SearchState(**data["state"])
        counts = (state.position, state.tested, state.skipped)
        if any(type(value) is not int or value < 0 for value in counts):
            raise ValueError("contadores inválidos na sessão")
        if state.position != state.tested + state.skipped:
            raise ValueError("contadores inconsistentes na sessão")
        if not isinstance(state.elapsed, (int, float)) or not 0 <= state.elapsed < float("inf"):
            raise ValueError("tempo inválido na sessão")
        if state.status not in ("running", "paused", "interrupted"):
            raise ValueError("sessão concluída; inicie outra busca sem --resume")
        return state
    except (KeyError, TypeError, AttributeError) as exc:
        raise ValueError("arquivo de sessão inválido") from exc


def run_search(records, candidates, state, limit, session=None, identity=""):
    started = last_update = time.perf_counter()
    previous_elapsed = state.elapsed
    processed = 0
    state.status = "running"
    last_counts = (state.position, state.tested, state.skipped)

    def checkpoint():
        state.elapsed = previous_elapsed + time.perf_counter() - started
        if session is not None:
            save_session(session, identity, state)

    checkpoint()
    try:
        for raw in candidates:
            if processed >= limit:
                state.status = "paused"
                break
            last_counts = (state.position, state.tested, state.skipped)
            valid = valid_password(raw)
            # Só avança depois de concluir a verificação; Ctrl+C não perde uma candidata.
            record = match_password(records, raw) if valid else None
            state.position += 1
            state.tested += int(valid)
            state.skipped += int(not valid)
            processed += 1
            if record is not None:
                state.status = "found"
                return Result(record, raw.decode("ascii"), state.tested, state.skipped)
            now = time.perf_counter()
            if now - last_update >= 5:
                checkpoint()
                rate = state.tested / state.elapsed if state.elapsed else 0
                print(f"Progresso: {state.position} candidatas processadas; {rate:.1f} testes/s.",
                      file=sys.stderr, flush=True)
                last_update = now
        else:
            state.status = "exhausted"
        return Result(None, None, state.tested, state.skipped)
    except KeyboardInterrupt:
        # Repetir uma candidata é preferível a perdê-la se o sinal chegar entre
        # a comparação, a atualização dos contadores e a exibição do resultado.
        state.position, state.tested, state.skipped = last_counts
        state.status = "interrupted"
        raise
    finally:
        checkpoint()


def report(result: Result, elapsed: float) -> int:
    print(f"Candidatos testados: {result.tested}; candidatas inválidas ignoradas: {result.skipped}.")
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
    demo = subparsers.add_parser("demo", help="executa um exemplo sintético, sem usar a rede")
    demo.add_argument("--variations", action="store_true", help="encontra uma senha ausente da lista original")
    gen = subparsers.add_parser("gerar", help="cria um registro .22000 de laboratório a partir de SSID e senha conhecidos")
    gen.add_argument("--ssid", required=True, help="nome da rede de laboratório (UTF-8)")
    gen.add_argument("--senha", required=True, help="frase-senha conhecida dessa rede (8 a 63 caracteres)")
    gen.add_argument("--ap", help="MAC do roteador em hexadecimal; padrão: aleatório")
    gen.add_argument("--cliente", help="MAC do cliente em hexadecimal; padrão: aleatório")
    gen.add_argument("--saida", type=Path, help="arquivo .22000 de destino (anexa ao final); padrão: imprime na tela")
    search = subparsers.add_parser("crack", help="testa uma lista local contra PMKID(s)")
    search.add_argument("capture", type=Path, help="arquivo de texto .22000 com registros WPA*01")
    search.add_argument("wordlist", type=Path, help="arquivo local: uma senha por linha")
    search.add_argument("--variations", action="store_true", help="gera variações de caixa, substituições e sufixos")
    search.add_argument("--suffix", action="append", help="sufixo das variações; repetível; substitui os padrões")
    brute = subparsers.add_parser("brute", help="testa combinações de um alfabeto e intervalo definidos")
    brute.add_argument("capture", type=Path)
    brute.add_argument("--charset", required=True, help="caracteres permitidos na parte variável")
    brute.add_argument("--min-length", required=True, type=int, help="tamanho mínimo da parte variável")
    brute.add_argument("--max-length", required=True, type=int, help="tamanho máximo da parte variável")
    brute.add_argument("--prefix", default="", help="texto fixo antes da parte variável")
    brute.add_argument("--suffix", default="", help="texto fixo depois da parte variável")
    for command in (search, brute):
        command.add_argument("--ssid", help="filtra o SSID pelo nome UTF-8 exato")
        command.add_argument("--limit", type=int, default=100000, help="máximo de candidatas por execução (padrão: 100000)")
        command.add_argument("--session", type=Path, help="arquivo de progresso para retomada")
        command.add_argument("--resume", action="store_true", help="retoma --session com os mesmos parâmetros")
    args = parser.parse_args(argv)
    try:
        if args.command == "demo":
            examples = Path(__file__).resolve().parent / "examples"
            records = load_records(examples / "aula.22000")
            words = wordlist_lines(examples / ("palavras.txt" if args.variations else "senhas.txt"))
            if args.variations:
                words = variations(words)
            print("Demonstração sintética: rede fictícia Aula-WiFi, senha conhecida Aula2026!.")
            print(f"Registros carregados: {len(records)}.")
            started = time.perf_counter()
            return report(crack(records, words), time.perf_counter() - started)
        elif args.command == "gerar":
            ap = parse_mac(args.ap, "MAC do AP") if args.ap else os.urandom(6)
            station = parse_mac(args.cliente, "MAC do cliente") if args.cliente else os.urandom(6)
            line = format_record(args.ssid, args.senha, ap, station)
            if args.saida:
                with args.saida.open("a", encoding="utf-8") as stream:
                    stream.write(line + "\n")
                print(f"Registro de laboratório anexado em {args.saida}.", file=sys.stderr)
                print("Use-o com: python3 wifi_lab.py crack <este_arquivo> <sua_lista.txt>", file=sys.stderr)
            else:
                print(line)
            return 0
        else:
            if args.limit < 1:
                raise ValueError("--limit deve ser maior que zero")
            if args.resume and args.session is None:
                raise ValueError("--resume exige --session")
            if args.session and args.session.exists() and not args.resume:
                raise ValueError("a sessão já existe; use --resume ou escolha outro arquivo")
            records = load_records(args.capture, args.ssid)
            if args.command == "crack":
                if args.suffix and not args.variations:
                    raise ValueError("--suffix exige --variations no modo crack")
                if args.suffix:
                    for suffix in args.suffix:
                        if any(ord(c) < 32 or ord(c) > 126 for c in suffix):
                            raise ValueError("sufixos devem usar ASCII imprimível")
                # Abre antes de criar a sessão para detectar arquivo ausente.
                with args.wordlist.open("rb"):
                    pass
            else:
                total = mask_space(args.charset, args.min_length, args.max_length, args.prefix, args.suffix)
                print(f"Espaço de busca: {total} combinações. Limite desta execução: {args.limit}.")
            identity = session_identity(args) if args.session else ""
            state = load_session(args.session, identity) if args.resume else SearchState()
            if args.command == "crack":
                words = wordlist_lines(args.wordlist)
                if args.variations:
                    words = variations(words, args.suffix if args.suffix is not None else DEFAULT_SUFFIXES)
                words = skip_candidates(words, state.position)
            else:
                words = combinations(args.charset, args.min_length, args.max_length,
                                     args.prefix, args.suffix, state.position)
        print(f"Registros carregados: {len(records)}. A busca termina na primeira correspondência.")
        result = run_search(records, words, state, args.limit, args.session, identity)
        if state.status == "paused":
            print(f"Busca parcial: limite atingido após {state.position} candidatas; {state.tested} testadas e {state.skipped} ignoradas.")
            print("Use os mesmos parâmetros com --resume para continuar." if args.session else
                  "Use --session para poder retomar; esta execução não salvou o progresso.")
            return 3
        return report(result, state.elapsed)
    except (OSError, ValueError) as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nTeste interrompido.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
