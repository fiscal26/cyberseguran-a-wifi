import itertools
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from candidates import combinations, mask_space, variations
from wifi_lab import SearchState, load_records, load_session, run_search, save_session


class GeneratorTests(unittest.TestCase):
    def test_variations_recover_password_absent_from_input(self):
        generated = list(variations([b"aula"]))
        self.assertIn(b"Aula2026!", generated)
        self.assertIn(b"4ul4!", generated)
        self.assertEqual(len(generated), len(set(generated)))
        self.assertEqual(list(variations([b"aula"], ["X"])),
                         [b"aulaX", b"AulaX", b"AULAX", b"4ul4X"])

    def test_combinations_cover_every_value_and_resume_across_lengths(self):
        expected = [b"prefix" + bytes(value)
                    for length in (2, 3)
                    for value in itertools.product(b"ab", repeat=length)]
        self.assertEqual(mask_space("ab", 2, 3, "prefix"), len(expected))
        for offset in range(len(expected) + 1):
            self.assertEqual(list(combinations("ab", 2, 3, "prefix", start=offset)), expected[offset:])

    def test_invalid_mask_rejected(self):
        for charset, lo, hi, prefix in [("", 8, 8, ""), ("aa", 8, 8, ""),
                                        ("é", 8, 8, ""), ("ab", 1, 1, ""),
                                        ("ab", 9, 8, ""), ("ab", 63, 63, "x")]:
            with self.subTest(charset=charset, lo=lo), self.assertRaises(ValueError):
                mask_space(charset, lo, hi, prefix)

    def test_single_character_alphabet(self):
        self.assertEqual(list(combinations("x", 8, 9)), [b"xxxxxxxx", b"xxxxxxxxx"])
        self.assertEqual(list(combinations("ab", 1, 1, "prefix", "!")), [b"prefixa!", b"prefixb!"])


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.records = load_records(ROOT / "examples/aula.22000")

    def test_interruption_preserves_unfinished_candidate(self):
        state = SearchState()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "a.session.json"
            with patch("wifi_lab.match_password", side_effect=[None, KeyboardInterrupt()]):
                with self.assertRaises(KeyboardInterrupt):
                    run_search(self.records, [b"wrongpass", b"Aula2026!"], state, 10, path, "identity")
            resumed = load_session(path, "identity")
            self.assertEqual((resumed.position, resumed.tested, resumed.status), (1, 1, "interrupted"))
            result = run_search(self.records, [b"Aula2026!"], resumed, 10)
            self.assertEqual(result.password, "Aula2026!")

    def test_corrupt_and_mismatched_sessions_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "a.session.json"
            save_session(path, "abc", SearchState(position=1, tested=1, status="paused"))
            with self.assertRaises(ValueError):
                load_session(path, "changed")
            data = json.loads(path.read_text())
            data["state"]["skipped"] = 3
            path.write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                load_session(path, "abc")
            path.write_text("[]")
            with self.assertRaises(ValueError):
                load_session(path, "abc")

    def test_limit_equal_to_space_reports_exhausted(self):
        state = SearchState()
        run_search(self.records, [b"wrongpass"], state, 1)
        self.assertEqual(state.status, "exhausted")

    def test_progress_does_not_expose_candidate(self):
        output = io.StringIO()
        with patch("wifi_lab.time.perf_counter", side_effect=[0, 0, 6, 6, 6]), patch("sys.stderr", output):
            run_search(self.records, [b"wrongpass"], SearchState(), 10)
        self.assertIn("Progresso: 1", output.getvalue())
        self.assertNotIn("wrongpass", output.getvalue())


class ExtendedCLITests(unittest.TestCase):
    def cli(self, *args):
        return subprocess.run([sys.executable, str(ROOT / "wifi_lab.py"), *map(str, args)],
                              cwd="/tmp", text=True, capture_output=True, check=False)

    def test_variation_demo(self):
        result = self.cli("demo", "--variations")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Senha encontrada: 'Aula2026!'", result.stdout)

    def test_brute_session_limit_resume_and_closed_session(self):
        with tempfile.TemporaryDirectory() as directory:
            session = Path(directory) / "a.session.json"
            args = ["brute", ROOT / "examples/aula.22000", "--charset", "6!",
                    "--prefix", "Aula202", "--min-length", "2", "--max-length", "2",
                    "--limit", "1", "--session", session]
            first = self.cli(*args)
            self.assertEqual(first.returncode, 3, first.stderr)
            self.assertIn("Busca parcial", first.stdout)
            self.assertNotIn("Nenhuma correspondência", first.stdout)
            second = self.cli(*args, "--resume")
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertIn("Senha encontrada: 'Aula2026!'", second.stdout)
            self.assertEqual(json.loads(session.read_text())["state"]["tested"], 2)
            self.assertNotIn("Aula2026!", session.read_text())
            self.assertEqual(self.cli(*args, "--resume").returncode, 2)

    def test_dictionary_resume_refuses_changed_wordlist(self):
        with tempfile.TemporaryDirectory() as directory:
            words, session = Path(directory) / "words.txt", Path(directory) / "a.session.json"
            words.write_text("wrongpass\nAula2026!\n")
            args = ["crack", ROOT / "examples/aula.22000", words,
                    "--limit", "1", "--session", session]
            self.assertEqual(self.cli(*args).returncode, 3)
            words.write_text("different\nAula2026!\n")
            result = self.cli(*args, "--resume")
            self.assertEqual(result.returncode, 2)
            self.assertIn("parâmetros diferentes", result.stderr)

    def test_dictionary_resume_and_existing_session_protected(self):
        with tempfile.TemporaryDirectory() as directory:
            session = Path(directory) / "a.session.json"
            args = ["crack", ROOT / "examples/aula.22000", ROOT / "examples/palavras.txt",
                    "--variations", "--session", session, "--limit", "7"]
            self.assertEqual(self.cli(*args).returncode, 3)
            before = session.read_bytes()
            self.assertEqual(self.cli(*args).returncode, 2)
            self.assertEqual(session.read_bytes(), before)
            result = self.cli(*args, "--resume")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Aula2026!", result.stdout)

    def test_bom_comments_and_mixed_capture_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bom.22000"
            path.write_text("# comentário em português\n" + (ROOT / "examples/aula.22000").read_text(),
                            encoding="utf-8-sig")
            result = self.cli("crack", path, ROOT / "examples/senhas.txt")
            self.assertEqual(result.returncode, 0, result.stderr)
            path.write_text("WPA*02*invalid\n")
            result = self.cli("crack", path, ROOT / "examples/senhas.txt")
            self.assertEqual(result.returncode, 2)
            self.assertIn("EAPOL", result.stderr)

    def test_invalid_options_and_missing_wordlist_do_not_create_session(self):
        with tempfile.TemporaryDirectory() as directory:
            session = Path(directory) / "a.session.json"
            args = ["crack", ROOT / "examples/aula.22000", Path(directory) / "missing.txt"]
            for extra in (["--limit", "0"], ["--resume"], ["--session", session]):
                with self.subTest(extra=extra):
                    self.assertEqual(self.cli(*args, *extra).returncode, 2)
                    self.assertFalse(session.exists())


if __name__ == "__main__":
    unittest.main()
