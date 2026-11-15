import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wifi_lab import (  # noqa: E402
    Record,
    calculate_pmkid,
    crack,
    derive_pmk,
    load_records,
    parse_record,
    wordlist_lines,
)


class CryptoTests(unittest.TestCase):
    def test_known_wpa_pmk_vector(self):
        self.assertEqual(
            derive_pmk("password", b"IEEE").hex(),
            "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e",
        )

    def test_pmkid_against_openssl_reference(self):
        # Referência calculada independentemente com openssl dgst -sha1 -mac HMAC.
        self.assertEqual(
            calculate_pmkid(
                bytes(range(32)), bytes.fromhex("001122334455"), bytes.fromhex("aabbccddeeff")
            ).hex(),
            "7efac3ddea5b159b76b957a970777f32",
        )

    def test_passphrase_constraints(self):
        for password in ["short", "a" * 64, "senhaé123", "pass\x001234"]:
            with self.subTest(password=password), self.assertRaises(ValueError):
                derive_pmk(password, b"IEEE")

    def test_valid_passphrase_boundaries_and_spaces(self):
        for password in ["a" * 8, "b" * 63, " space  "]:
            with self.subTest(length=len(password)):
                self.assertEqual(len(derive_pmk(password, b"IEEE")), 32)


class InputAndSearchTests(unittest.TestCase):
    def setUp(self):
        self.records = load_records(ROOT / "examples/aula.22000")
        self.line = next(
            line for line in (ROOT / "examples/aula.22000").read_text().splitlines()
            if line.startswith("WPA")
        )

    def test_example_found_and_wrong_list_exhausted(self):
        result = crack(self.records, [b"12345678", b"short", b"Aula2026!"])
        self.assertEqual((result.password, result.tested, result.skipped), ("Aula2026!", 2, 1))
        result = crack(self.records, [b"12345678"])
        self.assertIsNone(result.record)
        self.assertEqual(result.tested, 1)

    def test_invalid_lines(self):
        parts = self.line.split("*")
        variants = ["garbage", self.line.replace("WPA*01", "WPA*02")]
        for index, value in [(2, "00" * 16), (3, "zz" * 6), (4, "00"), (5, "61" * 33), (6, "00")]:
            modified = parts.copy()
            modified[index] = value
            variants.append("*".join(modified))
        for line in variants:
            with self.subTest(line=line), self.assertRaises(ValueError):
                parse_record(line)

    def test_filter_and_deduplication(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "records.22000"
            path.write_text("# comentario\n" + self.line + "\n" + self.line, encoding="ascii")
            self.assertEqual(len(load_records(path, "Aula-WiFi")), 1)
            with self.assertRaises(ValueError):
                load_records(path, "Outra rede")

    def test_wordlist_preserves_spaces_and_skips_non_ascii(self):
        password = " space  "
        source = self.records[0]
        record = Record(
            calculate_pmkid(derive_pmk(password, source.ssid), source.ap, source.station),
            source.ap, source.station, source.ssid,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "words.txt"
            path.write_bytes(b"\xffinvalid\r\n space  \r\n")
            result = crack([record], wordlist_lines(path))
            self.assertEqual((result.password, result.skipped), (password, 1))

    def test_multiple_ssids(self):
        original = self.records[0]
        other = Record(original.pmkid, original.ap, original.station, b"OutraRede")
        result = crack([other, original], [b"Aula2026!"])
        self.assertEqual(result.record, original)


class CLITests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, str(ROOT / "wifi_lab.py"), *map(str, args)],
            cwd="/tmp", capture_output=True, text=True, check=False,
        )

    def test_demo_from_another_directory(self):
        result = self.run_cli("demo")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Senha encontrada: 'Aula2026!'", result.stdout)

    def test_no_match_and_missing_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "words.txt"
            path.write_text("wrongpass\n")
            result = self.run_cli("crack", ROOT / "examples/aula.22000", path)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("Nenhuma correspondência", result.stdout)
            result = self.run_cli("crack", Path(directory) / "missing.22000", path)
            self.assertEqual(result.returncode, 2)
            self.assertIn("Erro:", result.stderr)


if __name__ == "__main__":
    unittest.main()
