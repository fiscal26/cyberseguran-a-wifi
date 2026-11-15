import contextlib
import io
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wifi_lab import main
from windows_wifi import Connection, WindowsWifi, attempt, confirmed, profile_xml, run_windows


class FakeWifi:
    description = "Adaptador de teste"

    def __init__(self, initial=None):
        self.connection = initial
        self.disconnections = 0
        self.connections = []
        self.closed = False

    def current(self):
        return self.connection

    def connect(self, profile, temporary=True):
        self.connections.append((profile, temporary))

    def disconnect(self):
        self.disconnections += 1

    def close(self):
        self.closed = True


def options(**kwargs):
    return SimpleNamespace(**dict(ssid="Aula-WiFi", interface=None, limit=10, timeout=15) | kwargs)


class WindowsProfileTests(unittest.TestCase):
    def test_xml_escapes_key_and_encodes_ssid(self):
        root = ET.fromstring(profile_xml("Aula & ç", "Pass<&123", "WifiLab-test"))
        ns = {"w": "http://www.microsoft.com/networking/WLAN/profile/v1"}
        self.assertEqual(root.find("w:SSIDConfig/w:SSID/w:hex", ns).text, "Aula & ç".encode().hex().upper())
        self.assertEqual(root.find("w:MSM/w:security/w:sharedKey/w:keyMaterial", ns).text, "Pass<&123")
        self.assertEqual(root.find("w:MSM/w:security/w:authEncryption/w:authentication", ns).text, "WPA2PSK")
        self.assertEqual(root.find("w:connectionMode", ns).text, "manual")

    def test_invalid_ssids_and_keys(self):
        for ssid, password in [("", "password"), ("ç" * 17, "password"), ("ok", "short"), ("ok", "senhaé123")]:
            with self.subTest(ssid=ssid), self.assertRaises(ValueError):
                profile_xml(ssid, password, "name")

    def test_confirmation_checks_target_profile_mode_and_security(self):
        values = dict(profile="temp", ssid=b"target", mode=1, secure=True, auth=7, cipher=4)
        self.assertTrue(confirmed(Connection(**values), "temp", b"target"))
        self.assertFalse(confirmed(None, "temp", b"target"))
        for field, wrong in [("profile", "old"), ("ssid", b"other"), ("mode", 0),
                             ("secure", False), ("auth", 1), ("cipher", 0)]:
            with self.subTest(field=field):
                self.assertFalse(confirmed(Connection(**(values | {field: wrong})), "temp", b"target"))

    @unittest.skipIf(sys.platform == "win32", "teste da rejeição fora do Windows")
    def test_backend_rejects_other_operating_systems(self):
        with self.assertRaisesRegex(OSError, "exige Windows"):
            WindowsWifi()


class AttemptTests(unittest.TestCase):
    def test_attempt_uses_unique_temporary_profile(self):
        wifi = FakeWifi()
        with patch("windows_wifi.uuid.uuid4", return_value=SimpleNamespace(hex="unique")), \
             patch("windows_wifi.time.monotonic", side_effect=[0, 1]), \
             patch.object(wifi, "current", return_value=Connection("WifiLab-unique", b"Aula-WiFi", 1, True, 7, 4)):
            self.assertTrue(attempt(wifi, "Aula-WiFi", "Aula2026!", 15))
        self.assertTrue(wifi.connections[0][1])
        self.assertIn("WifiLab-unique", wifi.connections[0][0])

    def test_existing_connection_is_not_mistaken_for_success(self):
        wifi = FakeWifi(Connection("saved", b"Aula-WiFi", 0, True, 7, 4))
        with patch("windows_wifi.time.monotonic", side_effect=[0, 1, 16]), patch("windows_wifi.time.sleep"):
            self.assertFalse(attempt(wifi, "Aula-WiFi", "wrongpass", 15))


class WindowsRunnerTests(unittest.TestCase):
    def run_quiet(self, args, words, wifi):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return run_windows(args, words, wifi_factory=lambda _: wifi)

    def test_match_stops_and_closes_handle(self):
        wifi = FakeWifi()
        with patch("windows_wifi.attempt", side_effect=[False, True]) as verify:
            result = self.run_quiet(options(), [b"wrongpass", b"Aula2026!", b"notneeded"], wifi)
        self.assertEqual(result, 0)
        self.assertEqual(verify.call_count, 2)
        self.assertTrue(wifi.closed)
        self.assertEqual(wifi.disconnections, 4)

    def test_limit_and_exhaustion_are_distinct(self):
        with patch("windows_wifi.attempt", return_value=False):
            self.assertEqual(self.run_quiet(options(limit=1), [b"wrongpass", b"anotherpass"], FakeWifi()), 3)
            self.assertEqual(self.run_quiet(options(limit=1), [b"wrongpass"], FakeWifi()), 1)

    def test_restore_previous_saved_profile_without_password(self):
        initial = Connection("Perfil anterior", b"Original", 0, True, 7, 4)
        wifi = FakeWifi(initial)
        with patch("windows_wifi.attempt", return_value=False):
            self.run_quiet(options(), [b"wrongpass"], wifi)
        self.assertEqual(wifi.connections, [("Perfil anterior", False)])
        self.assertTrue(wifi.closed)

    def test_interruption_and_connection_errors_restore_and_close(self):
        for error in (KeyboardInterrupt, OSError):
            wifi = FakeWifi(Connection("Old", b"OldNet", 0, True, 7, 4))
            with self.subTest(error=error), patch("windows_wifi.attempt", side_effect=error):
                with self.assertRaises(error):
                    self.run_quiet(options(), [b"wrongpass"], wifi)
            self.assertTrue(wifi.closed)
            self.assertEqual(wifi.connections, [("Old", False)])

    def test_invalid_candidates_leave_connection_untouched(self):
        wifi = FakeWifi()
        self.assertEqual(self.run_quiet(options(), [b"short", b"\xffpassword"], wifi), 1)
        self.assertEqual(wifi.disconnections, 0)
        self.assertTrue(wifi.closed)

    def test_invalid_settings_do_not_open_adapter(self):
        for args in (options(ssid=""), options(limit=0), options(limit=1001), options(timeout=1)):
            factory = unittest.mock.Mock()
            with self.subTest(args=args), self.assertRaises(ValueError):
                run_windows(args, [], factory)
            factory.assert_not_called()

    def test_cli_routes_candidates_without_loading_wifi_backend(self):
        with patch("windows_wifi.run_windows", return_value=0) as run:
            self.assertEqual(main(["windows", "--ssid", "Aula-WiFi", "--wordlist",
                                   str(ROOT / "examples/palavras.txt"), "--variations"]), 0)
            self.assertIn(b"Aula2026!", list(run.call_args.args[1]))

    def test_invalid_cli_combination_does_not_connect(self):
        with patch("windows_wifi.run_windows") as run, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["windows", "--ssid", "Aula-WiFi", "--wordlist",
                                   str(ROOT / "examples/palavras.txt"), "--prefix", "X"]), 2)
            run.assert_not_called()

    @unittest.skipIf(sys.platform == "win32", "não aciona hardware Windows nos testes")
    def test_cli_reports_unsupported_platform(self):
        result = subprocess.run([sys.executable, str(ROOT / "wifi_lab.py"), "windows", "--ssid",
                                 "Aula-WiFi", "--wordlist", str(ROOT / "examples/senhas.txt")],
                                text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("exige Windows", result.stderr)


if __name__ == "__main__":
    unittest.main()
