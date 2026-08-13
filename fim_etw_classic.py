"""
DENEYSEL: Klasik "NT Kernel Logger" (SystemTraceControlGuid) tabanli ETW dosya
izleme scripti.

fim_etw.py'de kullandigimiz YONTEM modern bir API'dir (EnableTraceEx2 +
EVENT_TRACE_SYSTEM_LOGGER_MODE, Windows 8+ ile gelen "tek tek provider enable
etme" yaklasimi). Bu script ise cok daha ESKI, Windows XP'den beri var olan,
Process Monitor gibi araclarin da tarihsel olarak kullandigi "klasik" yontemi
dener: NT Kernel Logger session'i + FileIo MOF event class'i.

Amac: fim_etw.py'de Rename/SetDelete olaylarinin bu Windows surumunde
guvenilir tetiklenmemesi sorununu, FARKLI bir ETW mekanizmasiyla asip
asamayacagimizi test etmek.

Onemli fark: Klasik FileIo class'inda bazi olaylar (Create=32/64, Delete=35)
dosya adini DOGRUDAN METIN olarak tasir - modern provider'daki gibi sadece
FileObject pointer'i degil. Bu, correlation ihtiyacini bu olaylar icin
ortadan kaldirabilir.

NOT: Ayni anda sistemde sadece BIR "NT Kernel Logger" session'i calisabilir.
Baska bir arac (Procmon, xperf vb.) zaten kullaniyorsa bu script calismaz.

Kullanim: python fim_etw_classic.py  (Yonetici olarak)
Cikis: Ctrl+C
"""

import ctypes
from ctypes import wintypes
import sys
import os
import struct
import time
import json
import math
from datetime import datetime
import threading
import psutil
import re

# ==============================================================================
# GUID / STRUCT TANIMLARI (fim_etw.py ile ayni - dogrulanmis, dokunmuyoruz)
# ==============================================================================
class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8)
    ]

def make_guid(d1, d2, d3, d4_bytes):
    return GUID(d1, d2, d3, (ctypes.c_ubyte * 8)(*d4_bytes))

# Klasik NT Kernel Logger'in kontrol GUID'i - SABIT, degistirilemez.
SYSTEM_TRACE_CONTROL_GUID = make_guid(
    0x9E814AAD, 0x3204, 0x11D2, (0x9A, 0x82, 0x00, 0x60, 0x08, 0xA8, 0x69, 0x39)
)

# FileIo event class GUID'i (klasik MOF-tabanli dosya olaylari)
FILE_IO_GUID = make_guid(
    0x90CBDC39, 0x4A3E, 0x11D1, (0x84, 0xF4, 0x00, 0x00, 0xF8, 0x04, 0x64, 0xE3)
)

# Process event class GUID'i - yeni baslatilan process'lerin komut satirini
# gormek icin (Shadow Copy silme gibi "Defense Evasion" komutlarini yakalamak).
PROCESS_GUID = make_guid(
    0x3D6FA8D0, 0xFE05, 0x11D0, (0x9D, 0xDA, 0x00, 0xC0, 0x4F, 0xD7, 0xBA, 0x7C)
)
PROCESS_EVENT_TYPE_START = 1  # EVENT_TRACE_TYPE_START

KERNEL_LOGGER_NAME = "NT Kernel Logger"  # SABIT isim, degistirilemez

# ==============================================================================
# GURULTU AZALTMA - tekrar eden olaylari birlestirme (dedup)
# ==============================================================================
# Mantik: VS Code'un arka plan araclari (linter/formatter/dil sunucusu) gibi
# suracler, ayni dosyaya SANIYEDE BIRKAC KEZ dokunabiliyor - bunlarin HEPSINI
# tek tek basmak, gercek sinyali gurultuye gomer. Ayni (process, dosya,
# aksiyon) uclusu kisa bir pencerede (2 sn) tekrar geliyorsa, sadece ilkini
# gosteriyoruz.
DEDUPE_WINDOW_SECONDS = 2.0
_dedupe_cache = {}
_dedupe_lock = threading.Lock()


def is_duplicate_event(pid, action, file_path):
    key = (pid, action, file_path)
    now = time.monotonic()
    with _dedupe_lock:
        last_seen = _dedupe_cache.get(key)
        if last_seen is not None and (now - last_seen) < DEDUPE_WINDOW_SECONDS:
            return True
        _dedupe_cache[key] = now
        return False

# ==============================================================================
# ALARM LOG DOSYASI - otomatik test raporu icin (bkz. test_detection_suite.py)
# ==============================================================================
# Her alarm, ekrana basilmasinin YANI SIRA bu dosyaya da (JSON Lines formati,
# her satir bagimsiz bir JSON nesnesi) kaydedilir. test_detection_suite.py bu
# dosyayi okuyup, hangi senaryo sirasinda hangi alarmin geldigini zaman
# damgasina gore eslestirerek OTOMATIK bir PASS/FAIL raporu uretebilir -
# elle "terminale bak, karsilastir" yapmaya gerek kalmaz.
ALERT_LOG_PATH = "alerts_log.jsonl"
_alert_log_lock = threading.Lock()

# ==============================================================================
# CALISMA MODU - varsayilan SESSIZ (production/arka plan mantigiyla)
# ==============================================================================
# QUIET_MODE = True iken: rutin dosya olaylari (OLUSTURULDU/SILINDI/vb.)
# HICBIR ZAMAN ekrana basilmaz. Sadece GERCEK ALARM durumunda konusur.
# Bu, bir sistem tepsisi arac gibi arka planda sessizce calisip, sadece
# gercek bir tehdit oldugunda kullaniciyi uyaran gercekci bir tasarim.
# Gelistirme/debug icin False yaparsan eski (ayrintili) log geri doner.
QUIET_MODE = True

INCIDENT_INSTRUCTIONS = [
    "Bilgisayarınızı HEMEN İnternet/ağ bağlantısından ayırın (Wi-Fi'ı kapatın veya kabloyu çekin) - yayılmayı önler.",
    "Şüpheli programı KAPATMAYA ÇALIŞMAYIN kendi başınıza - IT/güvenlik ekibinizle iletişime geçin.",
    "HİÇBİR ŞEKİLDE fidye ÖDEMEYİN - ödeme, dosyalarınızın geri geleceğini garanti etmez.",
    "Bilgisayarı KAPATMAYIN - açık tutun, adli analiz (forensics) için kanıt kaybolabilir.",
    "Varsa GÜNCEL YEDEKLERİNİZİ (bulut/harici disk) bu bilgisayara BAĞLAMAYIN.",
    "Bu olayı IT/güvenlik ekibinize ve gerekiyorsa yetkililere bildirin.",
]


def show_incident_alert(title, pid, pname, detail):
    """Tum alarm turleri icin ORTAK, kullaniciya yonelik net uyari ekrani.
    Sadece 'bir sey oldu' demiyor, NE YAPILMASI GEREKTIGINI de soyluyor -
    gercek bir EDR/uyari sisteminin son kullaniciya gosterdigi seye benzer."""
    RED = "\033[91m"
    BOLD = "\033[1m"
    RESET = "\033[0m"
    print("\n" + f"{RED}{BOLD}" + "!" * 78 + f"{RESET}", flush=True)
    print(f"{RED}{BOLD}  SİSTEMİNİZDE RANSOMWARE ŞÜPHESİ TESPİT EDİLDİ{RESET}", flush=True)
    print(f"{RED}{BOLD}" + "!" * 78 + f"{RESET}", flush=True)
    print(f"{RED}  Tespit türü : {title}{RESET}", flush=True)
    print(f"{RED}  Süreç       : {pname} (PID: {pid}){RESET}", flush=True)
    print(f"{RED}  Detay       : {detail}{RESET}", flush=True)
    print(f"{RED}  Zaman       : {datetime.now().strftime('%H:%M:%S')}{RESET}", flush=True)
    print(f"{RED}{BOLD}  YAPMANIZ GEREKENLER:{RESET}", flush=True)
    for i, step in enumerate(INCIDENT_INSTRUCTIONS, 1):
        print(f"{RED}    {i}. {step}{RESET}", flush=True)
    print(f"{RED}{BOLD}" + "!" * 78 + f"{RESET}\n", flush=True)

    popup_message = (
        f"Tespit türü: {title}\n"
        f"Süreç: {pname} (PID: {pid})\n"
        f"Detay: {detail}\n\n"
        "YAPMANIZ GEREKENLER:\n" +
        "\n".join(f"{i}. {step}" for i, step in enumerate(INCIDENT_INSTRUCTIONS, 1))
    )
    threading.Thread(
        target=show_windows_popup,
        args=("⚠️ Ransomware Şüphesi Tespit Edildi", popup_message),
        daemon=True
    ).start()


def log_alert_to_file(alert_type, pid, pname, message):
    entry = {
        "timestamp": time.time(),
        "time_str": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "alert_type": alert_type,
        "pid": pid,
        "pname": pname,
        "message": message,
    }
    try:
        with _alert_log_lock:
            with open(ALERT_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass  # loglama basarisiz olsa bile ana tespit akisini bozma

    record_alert_and_check_incident(alert_type, pid, pname, message)


# ==============================================================================
# KESINLESMIS OLAY (CONFIRMED INCIDENT) - coklu kanit birikince kullaniciya sor
# ==============================================================================
# Mantik: Tek bir sinyal (ozellikle dusuk-orta guvenli olanlar) yanlis
# pozitif olabilir - ama AYNI process icin KISA SUREDE FARKLI turden 2+
# sinyal (ornek: hem davranissal hem entropi hem defense evasion) birikirse,
# bu tesadufi olma ihtimali cok dusuktur. Bu durumda kullaniciya butun
# kaniti TEK EKRANDA gosterip aksiyon sorusu soruyoruz - "adam demistim"
# yaklasimi: tek sinyalde erken alarma gerek yok, ama kanit birikince
# kullaniciyi bilgilendirilmis bir karara zorluyoruz.
INCIDENT_WINDOW_SECONDS = 60.0     # bu sure icindeki farkli alarm turleri birlikte degerlendirilir
INCIDENT_MIN_DISTINCT_TYPES = 2    # en az kac FARKLI alarm turu bir araya gelince "kesinlesmis olay" sayilir
INCIDENT_COOLDOWN_SECONDS = 120.0  # ayni PID icin tekrar tekrar sorma
_pid_alert_history = {}
_pid_incident_prompted = {}
_incident_lock = threading.Lock()


def record_alert_and_check_incident(alert_type, pid, pname, message):
    now = time.time()
    with _incident_lock:
        history = _pid_alert_history.setdefault(pid, [])
        history.append((alert_type, now, message))
        cutoff = now - INCIDENT_WINDOW_SECONDS
        _pid_alert_history[pid] = [h for h in history if h[1] >= cutoff]
        history = _pid_alert_history[pid]

        distinct_types = sorted(set(h[0] for h in history))
        if len(distinct_types) < INCIDENT_MIN_DISTINCT_TYPES:
            return
        last_prompt = _pid_incident_prompted.get(pid, 0.0)
        if now - last_prompt < INCIDENT_COOLDOWN_SECONDS:
            return
        _pid_incident_prompted[pid] = now
        evidence = list(history)

    # Kullaniciya soru sormak (input()) ETW callback thread'ini BLOKE
    # ETMEMELI - ayri bir thread'de calistiriyoruz, ana olay akisi durmuyor.
    threading.Thread(target=show_confirmed_incident_prompt,
                      args=(pid, pname, distinct_types, evidence), daemon=True).start()


def show_confirmed_incident_prompt(pid, pname, distinct_types, evidence):
    RED = "\033[91m"
    BOLD = "\033[1m"
    RESET = "\033[0m"
    print("\n" + f"{RED}{BOLD}" + "#" * 78 + f"{RESET}", flush=True)
    print(f"{RED}{BOLD}  KESİNLEŞMİŞ OLAY ŞÜPHESİ - BİRDEN FAZLA BAĞIMSIZ KANIT BİRİKTİ{RESET}", flush=True)
    print(f"{RED}{BOLD}" + "#" * 78 + f"{RESET}", flush=True)
    print(f"{RED}  Süreç: {pname} (PID: {pid})  |  Son {INCIDENT_WINDOW_SECONDS:.0f} saniyede {len(distinct_types)} FARKLI tespit türü:{RESET}", flush=True)
    for alert_type, ts, msg in evidence:
        time_str = datetime.fromtimestamp(ts).strftime("%H:%M:%S")
        print(f"{RED}    [{time_str}] {alert_type}: {msg[:100]}{RESET}", flush=True)
    print(f"{RED}{BOLD}" + "#" * 78 + f"{RESET}", flush=True)

    popup_message = (
        f"Süreç: {pname} (PID: {pid})\n"
        f"Son {INCIDENT_WINDOW_SECONDS:.0f} saniyede {len(distinct_types)} FARKLI tespit türü birikti:\n\n" +
        "\n".join(f"• {a}" for a in distinct_types) +
        "\n\nBu, gerçek bir ransomware olayı olabilir.\n\n"
        "Şüpheli süreci HEMEN DURDURMAK ister misiniz?\n"
        "(EVET = durdur / HAYIR = izlemeye devam et / İPTAL = bildirimi kapat)"
    )
    # ONEMLI: burada input() KULLANMIYORUZ - Windows'ta arka plan thread'inde
    # input() cagirmak GIL'i duzgun birakmayip TUM diger thread'leri (ETW
    # olay isleme dahil) donduruyordu (gercek testte kanitlandi - alarmlar
    # birikip test bitince toptan cikiyordu). MessageBoxW kendi native mesaj
    # dongusunu kullaniyor, GIL/stdin ile catismiyor, hizli ve engellemesiz.
    threading.Thread(
        target=_ask_incident_action_via_popup,
        args=(pid, pname, popup_message),
        daemon=True
    ).start()


MB_YESNOCANCEL = 0x03
IDYES = 6
IDNO = 7


def _ask_incident_action_via_popup(pid, pname, popup_message):
    RED = "\033[91m"
    RESET = "\033[0m"
    try:
        result = user32.MessageBoxW(
            None, popup_message, "🚨 KESİNLEŞMİŞ OLAY ŞÜPHESİ",
            MB_ICONWARNING | MB_TOPMOST | MB_YESNOCANCEL
        )
    except Exception:
        result = None

    if result == IDYES:
        auto_respond(pid, pname, "kullanıcı onayıyla KESİNLEŞMİŞ OLAY üzerine durduruldu", force=True)
    elif result == IDNO:
        print(f"{RED}  [i] İzlemeye devam ediliyor, süreç durdurulmadı.{RESET}", flush=True)
    else:
        print(f"{RED}  [i] Bildirim kapatıldı.{RESET}", flush=True)

class EVENT_TRACE_PROPERTIES(ctypes.Structure):
    _fields_ = [
        ("Wnode", wintypes.BYTE * 48),
        ("BufferSize", wintypes.ULONG),
        ("MinimumBuffers", wintypes.ULONG),
        ("MaximumBuffers", wintypes.ULONG),
        ("MaximumFileSize", wintypes.ULONG),
        ("LogFileMode", wintypes.ULONG),
        ("FlushTimer", wintypes.ULONG),
        ("EnableFlags", wintypes.ULONG),
        ("AgeLimit", wintypes.LONG),
        ("NumberOfBuffers", wintypes.ULONG),
        ("FreeBuffers", wintypes.ULONG),
        ("EventsLost", wintypes.ULONG),
        ("BuffersWritten", wintypes.ULONG),
        ("LogBuffersLost", wintypes.ULONG),
        ("RealTimeBuffersLost", wintypes.ULONG),
        ("LoggerThreadId", wintypes.HANDLE),
        ("LogFileNameOffset", wintypes.ULONG),
        ("LoggerNameOffset", wintypes.ULONG)
    ]

class EVENT_DESCRIPTOR(ctypes.Structure):
    _fields_ = [
        ("Id", wintypes.WORD),
        ("Version", wintypes.BYTE),
        ("Channel", wintypes.BYTE),
        ("Level", wintypes.BYTE),
        ("Opcode", wintypes.BYTE),
        ("Task", wintypes.WORD),
        ("Keyword", ctypes.c_uint64)
    ]

class EVENT_HEADER(ctypes.Structure):
    _fields_ = [
        ("Size", wintypes.WORD),
        ("HeaderType", wintypes.WORD),
        ("Flags", wintypes.WORD),
        ("EventProperty", wintypes.WORD),
        ("ThreadId", wintypes.DWORD),
        ("ProcessId", wintypes.DWORD),
        ("TimeStamp", ctypes.c_int64),
        ("ProviderId", GUID),
        ("EventDescriptor", EVENT_DESCRIPTOR),
        ("KernelTime", wintypes.DWORD),
        ("UserTime", wintypes.DWORD),
        ("ActivityId", GUID)
    ]

class EVENT_RECORD(ctypes.Structure):
    _fields_ = [
        ("EventHeader", EVENT_HEADER),
        ("BufferContext", wintypes.BYTE * 4),
        ("ExtendedDataCount", wintypes.WORD),
        ("UserDataLength", wintypes.WORD),
        ("ExtendedData", ctypes.c_void_p),
        ("UserData", ctypes.c_void_p),
        ("UserContext", ctypes.c_void_p)
    ]

PEVENT_RECORD_CALLBACK = ctypes.WINFUNCTYPE(None, ctypes.POINTER(EVENT_RECORD))

# EVENT_TRACE_LOGFILEW.CurrentEvent alaninin GERCEK tipi EVENT_TRACE'tir
# (fim_etw.py'de bulunan kritik bug - burada da ayni duzeltme uygulaniyor)
class EVENT_TRACE_HEADER(ctypes.Structure):
    _fields_ = [
        ("Size", wintypes.USHORT),
        ("FieldTypeFlags", wintypes.USHORT),
        ("VersionUnion", wintypes.ULONG),
        ("ThreadId", wintypes.ULONG),
        ("ProcessId", wintypes.ULONG),
        ("TimeStamp", ctypes.c_int64),
        ("Guid", GUID),
        ("ClientContextOrTime1", wintypes.ULONG),
        ("ClientContextOrTime2", wintypes.ULONG),
    ]

class EVENT_TRACE(ctypes.Structure):
    _fields_ = [
        ("Header", EVENT_TRACE_HEADER),
        ("InstanceId", wintypes.ULONG),
        ("ParentInstanceId", wintypes.ULONG),
        ("ParentGuid", GUID),
        ("MofData", ctypes.c_void_p),
        ("MofLength", wintypes.ULONG),
        ("ClientContextUnion", wintypes.ULONG),
    ]

class EVENT_TRACE_LOGFILEW(ctypes.Structure):
    _fields_ = [
        ("LogFileName", wintypes.LPWSTR),
        ("LoggerName", wintypes.LPWSTR),
        ("CurrentTime", ctypes.c_int64),
        ("BuffersRead", wintypes.ULONG),
        ("LogFileMode", wintypes.ULONG),
        ("CurrentEvent", EVENT_TRACE),
        ("LogfileHeader", wintypes.BYTE * 280),
        ("BufferCallback", ctypes.c_void_p),
        ("BufferSize", wintypes.ULONG),
        ("Filled", wintypes.ULONG),
        ("EventsLost", wintypes.ULONG),
        ("EventRecordCallback", PEVENT_RECORD_CALLBACK),
        ("IsKernelTrace", wintypes.ULONG),
        ("Context", ctypes.c_void_p)
    ]

TRACEHANDLE = ctypes.c_uint64

# ==============================================================================
# WIN32 DLL IMZALARI & SABITLER
# ==============================================================================
advapi32 = ctypes.windll.advapi32
kernel32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32


def enable_console_colors():
    """Windows konsolunun ANSI renk kodlarini (←[91m gibi) GERCEK renk olarak
    yorumlamasini saglar. Bu yapilmazsa bazi eski cmd.exe/PowerShell
    konfigurasyonlarinda kodlar duz metin olarak (cirkin sekilde) gorunur."""
    ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
    STD_OUTPUT_HANDLE = -11
    handle = kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
    mode = wintypes.DWORD()
    if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
        kernel32.SetConsoleMode(handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING)


# Native Windows pop-up (MessageBoxW) - ekstra kutuphane GEREKTIRMEZ, Windows'un
# kendi API'si. Gercek bir "sistem uyarisi" hissi verir (Windows Guvenlik
# Merkezi'nin kullandigi mekanizmalarla ayni aile).
MB_ICONWARNING = 0x30
MB_TOPMOST = 0x40000
MB_SYSTEMMODAL = 0x1000  # diger tum pencerelerin ONUNDE zorla gorunur


def show_windows_popup(title, message):
    """Ayri bir thread'de cagrilmali - MessageBoxW BLOKE EDICI'dir (kullanici
    'Tamam'a basana kadar bekler), ETW callback thread'ini bloke etmemesi icin."""
    try:
        user32.MessageBoxW(None, message, title, MB_ICONWARNING | MB_TOPMOST)
    except Exception:
        pass


advapi32.StartTraceW.restype = wintypes.ULONG
advapi32.StartTraceW.argtypes = [ctypes.POINTER(TRACEHANDLE), wintypes.LPCWSTR, ctypes.POINTER(EVENT_TRACE_PROPERTIES)]
advapi32.ControlTraceW.restype = wintypes.ULONG
advapi32.ControlTraceW.argtypes = [TRACEHANDLE, wintypes.LPCWSTR, ctypes.POINTER(EVENT_TRACE_PROPERTIES), wintypes.ULONG]
advapi32.OpenTraceW.restype = TRACEHANDLE
advapi32.OpenTraceW.argtypes = [ctypes.POINTER(EVENT_TRACE_LOGFILEW)]
advapi32.ProcessTrace.restype = wintypes.ULONG
advapi32.ProcessTrace.argtypes = [ctypes.POINTER(TRACEHANDLE), wintypes.ULONG, ctypes.c_void_p, ctypes.c_void_p]
advapi32.CloseTrace.restype = wintypes.ULONG
advapi32.CloseTrace.argtypes = [TRACEHANDLE]

EVENT_TRACE_REAL_TIME_MODE = 0x00000100
PROCESS_TRACE_MODE_REAL_TIME = 0x00000100
PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000
WNODE_FLAG_TRACED_GUID = 0x00020000
EVENT_TRACE_CONTROL_STOP = 1
ERROR_ALREADY_EXISTS = 183

# Klasik kernel logger EnableFlags degerleri (Microsoft dokumantasyonundan dogrulandi)
EVENT_TRACE_FLAG_PROCESS = 0x00000001        # yeni process baslatma olaylari (komut satiri icin)
EVENT_TRACE_FLAG_DISK_FILE_IO = 0x00000200
EVENT_TRACE_FLAG_FILE_IO = 0x02000000       # Read/Write detay seviyesi
EVENT_TRACE_FLAG_FILE_IO_INIT = 0x04000000  # Create/Delete/Rename isim eslemesi

# Klasik FileIo class icindeki event type (Opcode) degerleri
FILEIO_TYPE_MAP = {
    0: "NAME (rundown)",
    32: "OLUSTURULDU (Create/Name)",
    35: "SILINDI (Delete/Name)",
    36: "RUNDOWN",
    64: "OLUSTURULDU (Create)",
    65: "CLEANUP",
    66: "KAPANDI (Close)",
    67: "OKUNDU (Read)",
    68: "YAZILDI (Write)",
    69: "SETINFO",
    70: "SILINDI (Delete/Info)",
    71: "YENIDEN ADLANDIRILDI (Rename?)",  # dokumante degil, deneme amacli eklendi
    72: "DIRENUM",
    73: "FLUSH",
    77: "DIRNOTIFY",
    # Asagidakiler dokumante edilmemis ama gercek testte gozlemlendi - bu
    # Windows surumunde FileIo class'ina sonradan eklenmis ekstra tipler
    # gibi duruyor (muhtemelen INIT/OperationEnd/QueryInfo/FSControl varyantlari).
    # Isimsiz oldugu ve cok sik geldigi icin varsayilan olarak gosterilmiyor.
    # DOGRULANDI (gercek testle kanitlandi): bu Windows surumunde FileIo
    # class'ina eklenmis, PID ve TAM YOL bilgisini DOGRUDAN tasiyan iki kritik
    # opcode - correlation GEREKTIRMEZ, modern provider'dan cok daha iyi!
    79: "SILINDI (SetDelete)",
    80: "YENIDEN ADLANDIRILDI",
    # Asagidakiler hala tam netlesmedi, isimsiz oldugu ve cok sik geldigi
    # icin varsayilan olarak gosterilmiyor.
    74: "BILINMEYEN_74 (muhtemelen QueryInfo/Init)",
    75: "BILINMEYEN_75 (muhtemelen FSControl)",
    76: "BILINMEYEN_76 (muhtemelen OperationEnd - her islemden sonra geliyor)",
    84: "BILINMEYEN_84",
    86: "BILINMEYEN_86",
}

SESSION_NAME = KERNEL_LOGGER_NAME  # Klasik logger icin ISIM SABIT olmali

# Sadece bu klasordeki olaylari goster (fim_etw.py ile ayni mantik).
# Bos string birakirsan TUM sistem gosterilir (cok gurultulu).
WATCH_PATH_KEYWORD = "\\filemonitoring\\"
WATCH_DIR = r"C:\FileMonitoring"  # entropi olcumu icin gercek yol karsiligi (WATCH_PATH_KEYWORD ile tutarli olmali)

# Isim tasimayan (dosya yolu belirlenemeyen) event'leri gosterme.
# Sadece opcode'lari kesfetmek icin gecici olarak True yapabilirsin.
SHOW_UNNAMED_EVENTS = False


def guid_equal(g1, g2):
    return (g1.Data1 == g2.Data1 and g1.Data2 == g2.Data2 and g1.Data3 == g2.Data3
            and bytes(g1.Data4) == bytes(g2.Data4))


# ==============================================================================
# DEFENSE EVASION TESPITI - Shadow Copy / yedek silme komutlari
# ==============================================================================
# Mantik: Sifrelemeden ONCE, ransomware genelde kurtarmayi engellemek icin
# Windows'un yerlesik yedekleme/kurtarma mekanizmalarini (Volume Shadow Copy,
# Windows Backup, boot recovery) devre disi birakir/siler. Bu, MITRE ATT&CK'in
# "Defense Evasion" / "Inhibit System Recovery" (T1490) teknigi - sifreleme
# BASLAMADAN once yakalanabilecek en guclu erken uyarilardan biri.
#
# Process class event'lerinden (opcode=1, Start) gelen komut satirini,
# bilinen supheli anahtar kelimelerle tarayarak tespit ediyoruz. Tam alan
# offsetini cikarmaya calismiyoruz (SID degisken uzunlukta oldugu icin
# karmasik) - butun UserData'yi metne cevirip anahtar kelime arıyoruz,
# ayni dosya yolu regex'i gibi saglam/basit bir yaklasim.
SUSPICIOUS_COMMAND_KEYWORDS = (
    "vssadmin delete", "vssadmin resize",   # sadece YIKICI alt-komutlar - "list" artik tetiklemiyor
    "wmic shadowcopy delete", "shadowcopy delete",
    "bcdedit /set", "bcdedit  set",         # recoveryenabled/bootstatuspolicy degistirme
    "wbadmin delete", "diskshadow", "delete catalog",
)
_evasion_alerted_pids = {}  # pid -> son alarm zamani (kalici set DEGIL - PID yeniden kullanimi hatasi olustururdu)
_evasion_lock = threading.Lock()
EVASION_ALERT_COOLDOWN_SECONDS = 300.0  # ayni PID icin 5 dakikada bir tekrar kontrol edilebilir


def check_defense_evasion(pid, pname, decoded_userdata):
    lowered = decoded_userdata.lower()
    matched = next((kw for kw in SUSPICIOUS_COMMAND_KEYWORDS if kw in lowered), None)
    if not matched:
        return

    now = time.time()
    with _evasion_lock:
        last = _evasion_alerted_pids.get(pid, 0.0)
        if now - last < EVASION_ALERT_COOLDOWN_SECONDS:
            return
        _evasion_alerted_pids[pid] = now

    # Komut satirini okunabilir hale getirmeye calis: null byte'larla ayrilmis
    # parcalar arasinda anahtar kelimeyi iceren parcayi bul.
    fragments = [f for f in decoded_userdata.split('\x00') if f.strip()]
    command_guess = next((f for f in fragments if matched in f.lower()), matched)

    RED = "\033[91m"
    RESET = "\033[0m"
    message = (f"[🚨 DEFENSE EVASION] PID: {pid} ({pname}) YEDEK/KURTARMA SİLME KOMUTU "
               f"TESPİT EDİLDİ: '{command_guess.strip()}' - şifrelemeden ÖNCEKİ hazırlık aşaması olabilir!")
    message = escalate_with_discovery_context(pid, message)
    show_incident_alert(escalated_title(pid, "Defense Evasion (Yedek/Kurtarma Silme)"), pid, pname, command_guess.strip())
    log_alert_to_file("DEFENSE_EVASION", pid, pname, message)
    auto_respond(pid, pname, f"şüpheli komut: {command_guess.strip()}")


# ==============================================================================
# CANARY (TUZAK) DOSYA TESPITI - artik SAF ETW uzerinden, GERCEK PID ile
# ==============================================================================
# Opcode 79 (Delete) ve 80 (Rename), aksiyonu yapan GERCEK process'in PID'ini
# dogrudan tasidigi icin, canary alarmi artik hicbir correlation/polling
# fallback'ine ihtiyac duymadan, saf ETW akisindan geliyor.
CANARY_FILENAMES = {
    "onemli.xlsx",
}
CANARY_ALERT_ACTIONS = {"SILINDI (SetDelete)", "YENIDEN ADLANDIRILDI"}
# NOT: "YAZILDI (Write)" ve "SETINFO" BILEREK YOK - bu Windows surumunde
# klasik FileIo semasinda Write/SetInfo event'leri (opcode 68/69) HICBIR
# ZAMAN dosya adini metin olarak tasimiyor (isimsiz geliyor, bkz.
# event_callback'teki "if file_path:" filtresi). Bu action'lar
# CANARY_ALERT_ACTIONS'a eklense bile file_path hep None oldugu icin
# check_canary_alert asla cagrilmiyor - eskiden burada duran bu iki deger
# hicbir zaman eslesmeyen, yaniltici "olu kod"du.
CANARY_ALERT_COOLDOWN_SECONDS = 5.0
_canary_last_alert = {}
_canary_lock = threading.Lock()


def ensure_canary_files(directory):
    """
    CANARY_FILENAMES listesindeki dosyalar 'directory' icinde yoksa,
    onemsiz/sahte icerikle otomatik olusturur. fim_etw.py'de vardi ama
    fim_etw_classic.py'ye tasinmamisti - bu, canary'nin production'da
    (elle mudahale olmadan) hic calismamasina yol aciyordu, duzeltildi.
    """
    if not CANARY_FILENAMES:
        return
    os.makedirs(directory, exist_ok=True)
    for name in CANARY_FILENAMES:
        path = os.path.join(directory, name)
        if not os.path.exists(path):
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write("Bu bir CANARY (tuzak) dosyadir. Sahte icerik.\n")
                print(f"[+] Canary dosyasi olusturuldu: {path}")
            except OSError as e:
                print(f"[!] Canary dosyasi olusturulamadi: {path} -> {e}")


def check_canary_alert(pid, pname, action, file_path):
    if not CANARY_FILENAMES or action not in CANARY_ALERT_ACTIONS:
        return
    name = os.path.basename(file_path).lower() if file_path else None
    if not name:
        return
    # Tam eslesme (ör. dosya dogrudan silindi) YA DA rename sonrasi yeni isim
    # eski canary adiyla BASLIYORSA da eslestir - cunku YENIDEN ADLANDIRILDI
    # event'i sadece YENI ismi verir (eskiyi degil), ve ransomware genelde
    # orijinal isme bir uzanti EKLER (silmez/degistirmez).
    matched = any(
        name == c.lower() or name.startswith(c.lower())
        for c in CANARY_FILENAMES
    )
    if not matched:
        return

    now = time.time()
    key = (pid, action)
    with _canary_lock:
        last = _canary_last_alert.get(key, 0.0)
        if now - last < CANARY_ALERT_COOLDOWN_SECONDS:
            return
        _canary_last_alert[key] = now

    RED = "\033[91m"
    RESET = "\033[0m"
    reputation = process_reputation(pname)
    suspicious_parent, parent_name = check_parent_chain(pid, pname)
    parent_note = f" | Ebeveyn: {parent_name} {'⚠️ ŞÜPHELİ ZİNCİR' if suspicious_parent else ''}" if parent_name else ""
    message = (f"[🚨🐤 CANARY ALARM - SAF ETW] PID: {pid} ({pname}, itibar: {reputation}) TUZAK DOSYAYA DOKUNDU! "
               f"Aksiyon: {action} -> {file_path}{parent_note}")
    message = escalate_with_discovery_context(pid, message)
    show_incident_alert(escalated_title(pid, "Tuzak (Canary) Dosyaya Dokunma"), pid, pname, f"{action} -> {file_path}{parent_note}")
    log_alert_to_file("CANARY", pid, pname, message)
    # CANARY, sistemdeki EN YUKSEK guvenli sinyal - mesru hicbir surec bu
    # dosyaya dokunmaz, bu yuzden ONAY BEKLEMEDEN aninda surecistop durduruyoruz.
    # Amac: dosyayi kurtarmak degil (o zaten olmus bitmis), AYNI surecin
    # KALAN binlerce dosyaya dokunmasini - yani YAYILMAYI - durdurmak.
    auto_respond(pid, pname, "canary dosyaya dokundu (en yuksek guven sinyali)", force=True)


# ==============================================================================
# DAVRANISSAL (RANSOMWARE) TESPITI - saf ETW, gercek PID ile
# ==============================================================================
SUSPICIOUS_RENAME_EXTENSIONS = (".locked", ".encrypted", ".enc", ".crypt", ".locky")
RENAME_THRESHOLD = 30
TIME_WINDOW = 5.0
ALERT_COOLDOWN_SECONDS = 10.0
_rename_events = {}
_last_alert = {}
_anomaly_lock = threading.Lock()


def check_ransomware_anomaly(pid, pname, action, file_path):
    if action != "YENIDEN ADLANDIRILDI" or not file_path:
        return
    if not any(file_path.lower().endswith(ext) for ext in SUSPICIOUS_RENAME_EXTENSIONS):
        return

    # Itibar bazli DINAMIK esik: guvenilir bilinen uygulamalar icin esigi
    # yukselt (daha az yanlis pozitif), LOLBIN (powershell/cmd vb.) icin
    # esigi dusur (daha erken/hassas alarm) - cunku normal bir kullanici
    # PowerShell'den elle onlarca dosyayi yeniden adlandirmaz.
    reputation = process_reputation(pname)
    if reputation == "GUVENILIR":
        effective_threshold = RENAME_THRESHOLD * 2
    elif reputation == "SUPHELI_ARAC":
        effective_threshold = max(5, RENAME_THRESHOLD // 3)
    else:
        effective_threshold = RENAME_THRESHOLD

    now = time.time()
    with _anomaly_lock:
        events = _rename_events.setdefault(pid, [])
        events.append(now)
        cutoff = now - TIME_WINDOW
        while events and events[0] < cutoff:
            events.pop(0)
        count = len(events)
        if count < effective_threshold:
            return
        if now - _last_alert.get(pid, 0.0) < ALERT_COOLDOWN_SECONDS:
            return
        _last_alert[pid] = now

    RED = "\033[91m"
    RESET = "\033[0m"
    suspicious_parent, parent_name = check_parent_chain(pid, pname)
    parent_note = f" | Ebeveyn: {parent_name} {'⚠️ ŞÜPHELİ ZİNCİR' if suspicious_parent else ''}" if parent_name else ""
    message = (f"[🚨 ALARM - RANSOMWARE ŞÜPHESİ - SAF ETW] PID: {pid} ({pname}, itibar: {reputation}) "
               f"son {TIME_WINDOW:.0f} saniyede {count} dosyayı şüpheli biçimde yeniden adlandırdı! "
               f"(eşik: {effective_threshold}){parent_note}")
    message = escalate_with_discovery_context(pid, message)
    show_incident_alert(escalated_title(pid, "Davranışsal (Toplu Şüpheli Rename)"), pid, pname,
                         f"{count} dosya {TIME_WINDOW:.0f} saniyede yeniden adlandırıldı{parent_note}")
    log_alert_to_file("RANSOMWARE_BEHAVIOR", pid, pname, message)
    auto_respond(pid, pname, f"{count} dosyayı {TIME_WINDOW:.0f} saniyede şüpheli rename")


# ==============================================================================
# PROCESS ISIM COZUCU
# ==============================================================================
_proc_cache = {}

def get_pname(pid):
    if not pid:
        return "System"
    if pid in _proc_cache:
        return _proc_cache[pid]
    try:
        name = psutil.Process(pid).name()
        _proc_cache[pid] = name
        return name
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "Kapanmis/Bilinmeyen"


# ==============================================================================
# 1) PROCESS REPUTATION / ALLOWLIST
# ==============================================================================
# Mantik: Tek basina "PID X, Y dosyasini degistirdi" bilgisi yetersiz - "bu PID
# normalde boyle bir sey yapar mi?" sorusu asil ayirt edici olan. Bilinen,
# imzali, "dosya duzenleme" ile normalde iliskilendirdigimiz uygulamalar
# (Word, Excel, VS Code, git, Explorer) ile "living off the land" olarak
# bilinen, saldirganlarin sikca kotuye kullandigi ama kendisi zararsiz olan
# araclari (powershell, cmd, wscript, mshta, rundll32) ayirt ediyoruz.
TRUSTED_PROCESSES = {
    "explorer.exe", "winword.exe", "excel.exe", "powerpnt.exe",
    "code.exe", "git.exe", "notepad.exe", "acrobat.exe", "photoshop.exe",
    "msedgewebview2.exe", "msedge.exe",  # gercek testte yuksek DIRENUM gurultusu uretti
    "msmpeng.exe",  # Windows Defender gercek zamanli koruma - o da gurultu kaynagi cikti
}

LOLBIN_PROCESSES = {  # "Living off the land binaries" - kendisi zararsiz, cok kotuye kullanilir
    "powershell.exe", "powershell_ise.exe", "pwsh.exe", "cmd.exe",
    "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
    "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
}


def process_reputation(pname):
    lower = pname.lower() if pname else ""
    if lower in TRUSTED_PROCESSES:
        return "GUVENILIR"
    if lower in LOLBIN_PROCESSES:
        return "SUPHELI_ARAC"  # kendisi zararli degil ama dikkatli izlenmeli
    return "BILINMEYEN"


# ==============================================================================
# 2) PARENT PROCESS ZINCIRI (soy agaci) KONTROLU
# ==============================================================================
# Mantik: BIR process'in NE OLDUGUNDAN COK, KIM TARAFINDAN BASLATILDIGI cok
# guclu bir sinyaldir. Ornek: powershell.exe'nin explorer.exe tarafindan
# baslatilmasi normal (kullanici elle actı); WINWORD.EXE tarafindan
# baslatilmasi COK supheli (klasik "macro malware" deseni - bir Word
# dosyasi acilinca gizlice PowerShell calistiriyor).
SUSPICIOUS_PARENT_CHILD_PAIRS = {
    ("winword.exe", "powershell.exe"), ("winword.exe", "cmd.exe"),
    ("excel.exe", "powershell.exe"), ("excel.exe", "cmd.exe"),
    ("outlook.exe", "powershell.exe"), ("outlook.exe", "wscript.exe"),
    ("winword.exe", "wscript.exe"), ("excel.exe", "wscript.exe"),
}

_parent_cache = {}


def get_parent_name(pid):
    if pid in _parent_cache:
        return _parent_cache[pid]
    try:
        parent = psutil.Process(pid).parent()
        name = parent.name() if parent else None
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        name = None
    _parent_cache[pid] = name
    return name


def check_parent_chain(pid, pname):
    """Supheli bir ebeveyn-cocuk iliskisi varsa (ör. Word -> PowerShell) True doner."""
    parent_name = get_parent_name(pid)
    if not parent_name:
        return False, None
    pair = (parent_name.lower(), pname.lower())
    return pair in SUSPICIOUS_PARENT_CHILD_PAIRS, parent_name


# ==============================================================================
# 3) DIRENUM ILE ERKEN KESIF (DISCOVERY) TESPITI
# ==============================================================================
# Mantik: Sifrelemeden ONCE, ransomware genelde sistemde "neyi sifreleyecegini"
# bulmak icin cok sayida klasoru hizlica listeler (Discovery asamasi,
# MITRE ATT&CK). Bu, Impact (sifreleme) asamasindan ONCE gelen bir erken
# uyari sinyalidir - "olay olmadan once" mudahale sansi verir.
DIRENUM_THRESHOLD = 20
DIRENUM_TIME_WINDOW = 5.0
DIRENUM_COOLDOWN_SECONDS = 15.0
_direnum_events = {}
_direnum_last_alert = {}
_direnum_lock = threading.Lock()

# Discovery artik STANDALONE alarm degil, DESTEKLEYICI sinyal (asagida
# check_discovery_anomaly'nin ic yorumunda gerekce aciklanmis).
SHOW_DISCOVERY_OBSERVATIONS = False  # True yaparsan sessiz gozlem loglarini da gorursun
DISCOVERY_CORRELATION_WINDOW_SECONDS = 30.0  # bu sure icinde baska bir alarm gelirse "YUKSEK GUVEN" ekle
_discovery_burst_timestamp = {}


def check_discovery_anomaly(pid, pname, action):
    if action != "DIRENUM":
        return

    # Itibar bazli dinamik esik (yine de tutuyoruz - tamamen kaldirirsak
    # cok cesitli process'ler icin ayni havuzda birikir).
    reputation = process_reputation(pname)
    if reputation == "GUVENILIR":
        effective_threshold = DIRENUM_THRESHOLD * 5   # 20 -> 100
    else:
        effective_threshold = DIRENUM_THRESHOLD        # SUPHELI_ARAC ve BILINMEYEN ayni (20)

    now = time.time()
    with _direnum_lock:
        events = _direnum_events.setdefault(pid, [])
        events.append(now)
        cutoff = now - DIRENUM_TIME_WINDOW
        while events and events[0] < cutoff:
            events.pop(0)
        count = len(events)
        if count < effective_threshold:
            return
        if now - _direnum_last_alert.get(pid, 0.0) < DIRENUM_COOLDOWN_SECONDS:
            return
        _direnum_last_alert[pid] = now
        # ARTIK STANDALONE ALARM BASMIYORUZ - sadece "bu PID kisa sure once
        # yogun kesif yapti" bilgisini kaydediyoruz. Gercek testte (bkz.
        # yorum asagida) bu sinyal TEK BASINA cok gurultulu cikti: gercek
        # Windows bakim servisleri (TiWorker.exe, cleanmgr.exe, ngentask.exe,
        # svchost.exe), OneDrive senkronizasyonu, hatta VS Code'un kendisi
        # bile (itibar GUVENILIR, esik 100'e ragmen) bu esigi asti. Bu,
        # "kisa surede kac klasor listelendi" sayisinin, aktif kullanilan
        # gercek bir Windows makinesinde TEK BASINA guvenilir bir sinyal
        # OLMADIGINI kanitladi - endustride de bilinen bir gercek.
        #
        # Bunun yerine DESTEKLEYICI SINYAL olarak kullaniyoruz: baska bir
        # katman (canary/ransomware/defense evasion) AYNI PID icin kisa
        # sure icinde tetiklenirse, o alarmi "YUKSEK GUVEN" ile guclendiriyoruz
        # (bkz. escalate_with_discovery_context()). Boylece false-positive
        # uretmeden, gercek bir saldirinin erken kesif izini yine
        # degerlendirmis oluyoruz.
        _discovery_burst_timestamp[pid] = now

    # Sessiz, dusuk seviyeli gozlem logu (alarm degil - renk yok)
    if SHOW_DISCOVERY_OBSERVATIONS:
        print(f"    [ℹ️ gözlem] PID {pid} ({pname}, itibar: {reputation}) son "
              f"{DIRENUM_TIME_WINDOW:.0f} saniyede {count} klasör listeledi "
              f"(destekleyici sinyal, tek başına alarm değil)", flush=True)


def escalate_with_discovery_context(pid, base_message):
    """Bir alarm mesajina, o PID'in yakin zamanda discovery burst'u varsa
    'YUKSEK GUVEN' etiketi ekler. Iki bagimsiz sinyalin AYNI PID'de kisa
    sure icinde ust uste gelmesi, tek basina her ikisinden de daha guclu
    bir kanittir (defense-in-depth mantigi)."""
    burst_time = _discovery_burst_timestamp.get(pid)
    if burst_time and (time.time() - burst_time) <= DISCOVERY_CORRELATION_WINDOW_SECONDS:
        return f"🔥 YÜKSEK GÜVEN (yakın zamanda keşif/DIRENUM patlaması da tespit edildi) | {base_message}"
    return base_message


def escalated_title(pid, title):
    """show_incident_alert'in basligina da (sadece log dosyasina degil,
    kullanicinin GORDUGU ekrana/pop-up'a da) YUKSEK GUVEN etiketini ekler -
    eskiden bu bilgi sadece alerts_log.jsonl'e yaziliyordu, kullanici hic
    gormuyordu."""
    burst_time = _discovery_burst_timestamp.get(pid)
    if burst_time and (time.time() - burst_time) <= DISCOVERY_CORRELATION_WINDOW_SECONDS:
        return f"🔥 YÜKSEK GÜVEN — {title}"
    return title


# ==============================================================================
# YETKI YUKSELTME (PRIVILEGE ESCALATION) TESPITI
# ==============================================================================
# Mantik: Ransomware sisteme sizdiktan sonra, tam yetkiyle (SYSTEM/Administrator)
# calisabilmek icin genelde yetki yukseltmeye calisir - bu asamada dosya
# hareketi COK AZ olabilir (senin de belirttigin gibi), bu yuzden dosya
# tabanli katmanlarimizin HICBIRI bunu yakalayamaz. Bilinen yetki yukseltme/
# kesif komutlarini (whoami /priv, net localgroup administrators, runas,
# yeni servis/scheduled task olusturma - kalicilik icin de kullanilir)
# ayni Process class komut satiri taramasiyla yakaliyoruz.
PRIVESC_COMMAND_KEYWORDS = (
    "whoami /priv", "whoami /all",
    "net localgroup administrators", "net user administrator",
    "runas /user:administrator", "runas /savecred",
    "sc create", "sc.exe create",           # yeni servis olusturma (persistence/privesc)
    "schtasks /create",                      # zamanlanmis gorev (persistence/privesc)
    "reg add hklm", "icacls",                # registry/izin manipulasyonu
)
_privesc_alerted_pids = {}  # pid -> son alarm zamani (ayni sebeple set() yerine dict/cooldown)
_privesc_lock = threading.Lock()
PRIVESC_ALERT_COOLDOWN_SECONDS = 300.0


def check_privilege_escalation(pid, pname, decoded_userdata):
    lowered = decoded_userdata.lower()
    matched = next((kw for kw in PRIVESC_COMMAND_KEYWORDS if kw in lowered), None)
    if not matched:
        return

    now = time.time()
    with _privesc_lock:
        last = _privesc_alerted_pids.get(pid, 0.0)
        if now - last < PRIVESC_ALERT_COOLDOWN_SECONDS:
            return
        _privesc_alerted_pids[pid] = now

    fragments = [f for f in decoded_userdata.split('\x00') if f.strip()]
    command_guess = next((f for f in fragments if matched in f.lower()), matched)

    ORANGE = "\033[93m"
    RESET = "\033[0m"
    message = (f"[🔺 YETKİ YÜKSELTME ŞÜPHESİ] PID: {pid} ({pname}) SÜPHELİ KOMUT: "
               f"'{command_guess.strip()}' - dosya hareketi olmasa bile bu aşama tehlikelidir!")
    message = escalate_with_discovery_context(pid, message)
    show_incident_alert(escalated_title(pid, "Yetki Yükseltme Şüphesi"), pid, pname, command_guess.strip())
    log_alert_to_file("PRIVILEGE_ESCALATION", pid, pname, message)
    auto_respond(pid, pname, f"yetki yükseltme şüphesi: {command_guess.strip()}")


# ==============================================================================
# ENTROPI TABANLI TESPIT - fim_polling.py'den tasindi, artik SAF ETW akisinda
# ==============================================================================
# Mantik: sifrelenmis/rastgele veri, duz metin/ofis belgesi gibi yapilandirilmis
# veriden cok daha yuksek Shannon entropisine sahiptir. Tetikleme noktasi
# olarak Create/Rename olaylarini kullaniyoruz (bunlar guvenilir sekilde tam
# dosya yolu tasiyor) - dosyanin GUNCEL disk icerigini okuyup entropisini
# hesapliyoruz (Read/Write event'lerinin kendisini degil, o an diskteki
# veriyi kullaniyoruz - polling'deki mantikla ayni, tetikleyici farkli).
#
# "AKILLICA AYIRMA": tek basina yuksek entropi YETMEZ. ZIP/DOCX/JPG/MP4 gibi
# formatlar TASARIM GEREGI zaten yuksek entropili - bunlari her zaman
# supheli saymak yanlis pozitif uretir. Sadece (a) format dogal olarak
# yuksek entropili DEGILSE, YA DA (b) dosya adi supheli bir ransomware
# uzantisiyla BITIYORSA tam alarm basiyoruz; aksi halde sessiz gozlem.
ENTROPY_SAMPLE_BYTES = 4096
ENTROPY_HIGH_THRESHOLD = 7.5
ENTROPY_JUMP_THRESHOLD = 2.0
ENTROPY_TRIGGER_ACTIONS = {"OLUSTURULDU (Create)", "OLUSTURULDU (Create/Name)", "YENIDEN ADLANDIRILDI"}

KNOWN_HIGH_ENTROPY_EXTENSIONS = {
    ".zip", ".docx", ".xlsx", ".pptx", ".jpg", ".jpeg", ".png", ".gif",
    ".mp3", ".mp4", ".7z", ".rar", ".gz", ".pdf", ".pfx", ".jar", ".apk",
}
SUSPICIOUS_EXTENSIONS_FOR_ENTROPY = (
    ".locked", ".encrypted", ".enc", ".crypt", ".locky", ".wcry", ".wncry",
)

_entropy_cache = {}
_entropy_lock = threading.Lock()


def shannon_entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    length = len(data)
    entropy = 0.0
    for c in counts:
        if c == 0:
            continue
        p = c / length
        entropy -= p * math.log2(p)
    return entropy


def read_entropy_from_disk(windows_path):
    """ETW'nin verdigi \\Device\\HarddiskVolumeX\\... yolunu, Python'un
    okuyabilecegi bir yola cevirip dosyanin GUNCEL entropisini olcer."""
    local_path = ntpath_to_local_path(windows_path)
    if not local_path or not os.path.isfile(local_path):
        return None
    try:
        with open(local_path, "rb") as f:
            sample = f.read(ENTROPY_SAMPLE_BYTES)
        return shannon_entropy(sample)
    except OSError:
        return None


def ntpath_to_local_path(windows_path):
    """\\Device\\HarddiskVolumeX\\Klasor\\dosya.txt -> C:\\Klasor\\dosya.txt
    Basit yaklasim: bizim WATCH_DIR zaten C: uzerinde oldugu icin, path
    icinde WATCH_DIR'in son klasor adini arayip oradan itibaren C: ile
    birlestiriyoruz. Zaten \\Device\\... formati olmayan (dogrudan C:\\...
    ile baslayan) yollari oldugu gibi kullaniyoruz."""
    if windows_path.lower().startswith("c:\\") or windows_path[1:3] == ":\\":
        return windows_path
    marker = os.path.basename(WATCH_DIR.rstrip("\\")).lower()
    lower = windows_path.lower()
    idx = lower.find("\\" + marker + "\\")
    if idx == -1:
        idx = lower.find("\\" + marker)
        if idx == -1:
            return None
    return "C:" + windows_path[idx:]


def entropy_alarm_confidence(path):
    if any(path.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS_FOR_ENTROPY):
        return "YUKSEK"
    _, ext = os.path.splitext(path.lower())
    if ext not in KNOWN_HIGH_ENTROPY_EXTENSIONS:
        return "YUKSEK"
    return "GOZLEM"


def check_entropy_anomaly(pid, pname, action, file_path):
    if action not in ENTROPY_TRIGGER_ACTIONS or not file_path:
        return

    entropy_after = read_entropy_from_disk(file_path)
    if entropy_after is None:
        return

    with _entropy_lock:
        entropy_before = _entropy_cache.get(file_path)
        _entropy_cache[file_path] = entropy_after

    if entropy_after < ENTROPY_HIGH_THRESHOLD:
        return

    jump_ok = entropy_before is None or (entropy_after - entropy_before) >= ENTROPY_JUMP_THRESHOLD
    # Yeni dosyada (entropy_before yok) sadece mutlak esik yeterli; degisen
    # dosyada hem esik hem sicrama gerekli (polling'deki ayni mantik).
    if entropy_before is not None and not jump_ok:
        return

    confidence = entropy_alarm_confidence(file_path)
    jump_note = f"{entropy_before:.2f} → {entropy_after:.2f}" if entropy_before is not None else f"{entropy_after:.2f} (yeni dosya)"

    if confidence == "GOZLEM":
        if SHOW_DISCOVERY_OBSERVATIONS:  # ayni "sessiz gozlem" bayragini paylasiyoruz
            print(f"    [ℹ️ gözlem] PID {pid} ({pname}) {os.path.basename(file_path)} "
                  f"entropi: {jump_note} bit/byte (bilinen yüksek-entropili format, tek başına alarm değil)", flush=True)
        return

    RED = "\033[91m"
    RESET = "\033[0m"
    message = (f"[🚨 ENTROPİ ALARMI] PID: {pid} ({pname}) {os.path.basename(file_path)} "
               f"entropi: {jump_note} bit/byte — muhtemel şifreleme!")
    message = escalate_with_discovery_context(pid, message)
    show_incident_alert(escalated_title(pid, "Entropi (Muhtemel Şifreleme)"), pid, pname,
                         f"{os.path.basename(file_path)} — entropi: {jump_note} bit/byte")
    log_alert_to_file("ENTROPY", pid, pname, message)
    auto_respond(pid, pname, f"entropi anomalisi: {jump_note}")


# ==============================================================================
# 4) OTOMATIK TEPKI (RESPONSE) - VARSAYILAN KAPALI
# ==============================================================================
# Mantik: Gercek EDR urunleri sadece loglamaz, yuksek guvenli bir alarmda
# OTOMATIK AKSIYON da alir (surecı dondur/oldur). Bu, "circuit breaker"
# (devre kesici) deseni - zarar devam etmeden once kesmek.
#
# BILINCLI OLARAK VARSAYILAN KAPALI (AUTO_RESPONSE_ENABLED = False):
# otomatik process oldurme, yanlis pozitif durumunda meşru bir uygulamayi
# (ör. senin kendi test scriptini) durdurabilir - bu yuzden production'da
# dikkatli, kademeli acilmasi gereken bir ozellik. Simdilik SADECE
# "bunu yapardim" mesajini basiyor (dry-run), gercekten kill() cagirmiyor.
AUTO_RESPONSE_ENABLED = False
AUTO_RESPONSE_DRY_RUN = True  # True: sadece ne yapacagini yazar, gercekten oldurmez


def auto_respond(pid, pname, reason, force=False):
    """
    force=False (varsayilan): sadece AUTO_RESPONSE_ENABLED acıksa calisir -
    bu, sistemin KENDI KENDINE otomatik tepki vermesi icin.
    force=True: kullanicinin KESINLESMIS OLAY ekraninda "[1] Durdur" secimi
    gibi, ACIKCA ONAYLADIGI durumlar icin - AUTO_RESPONSE_ENABLED/DRY_RUN
    ayarlarindan bagimsiz olarak GERCEKTEN calisir (kullanicinin kendi
    kararidir, sistemin otomatik kararinin degil).
    """
    RED = "\033[91m"
    RESET = "\033[0m"

    if not force:
        if not AUTO_RESPONSE_ENABLED:
            return
        if AUTO_RESPONSE_DRY_RUN:
            print(f"{RED}[🛑 OTOMATIK TEPKİ - DRY RUN] PID {pid} ({pname}) DURDURULACAKTI "
                  f"(sebep: {reason}) - gerçekte durdurulmadı, AUTO_RESPONSE_DRY_RUN=True{RESET}", flush=True)
            return

    try:
        proc = psutil.Process(pid)
        proc.suspend()  # once dondur (kill() yerine suspend() daha az yikici - geri alinabilir)
        print(f"{RED}[🛑 TEPKİ UYGULANDI] PID {pid} ({pname}) DONDURULDU (sebep: {reason}){RESET}", flush=True)
        threading.Thread(
            target=show_windows_popup,
            args=("🛑 Süreç Durduruldu - Yayılma Engellendi",
                  f"PID {pid} ({pname}) donduruldu.\nSebep: {reason}\n\n"
                  "Bu süreç artık YENİ dosyalara dokunamıyor - olası zarar sınırlandı.\n"
                  "Süreci geri başlatmak (resume) isterseniz Görev Yöneticisi'nden "
                  "ya da IT ekibinizle birlikte kontrollü şekilde yapın."),
            daemon=True
        ).start()
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        print(f"[!] Tepki uygulanamadı: {e}", flush=True)


# ==============================================================================
# ETW OTURUM YONETIMI (KLASIK MOD)
# ==============================================================================
class ClassicKernelSession:
    def __init__(self):
        self.session_handle = TRACEHANDLE(0)
        self.props_buffer = None

    def start_session(self):
        name_bytes = (SESSION_NAME + '\0').encode('utf-16le')
        props_size = ctypes.sizeof(EVENT_TRACE_PROPERTIES) + len(name_bytes)

        self.props_buffer = ctypes.create_string_buffer(props_size)
        props = EVENT_TRACE_PROPERTIES.from_buffer(self.props_buffer)

        struct.pack_into('I', self.props_buffer, 0, props_size)
        # Wnode.Guid = SystemTraceControlGuid (offset 24, 16 byte) - KLASIK MOD ICIN ZORUNLU
        guid_bytes = struct.pack('<IHH', SYSTEM_TRACE_CONTROL_GUID.Data1, SYSTEM_TRACE_CONTROL_GUID.Data2, SYSTEM_TRACE_CONTROL_GUID.Data3) + bytes(SYSTEM_TRACE_CONTROL_GUID.Data4)
        struct.pack_into('16s', self.props_buffer, 24, guid_bytes)
        struct.pack_into('I', self.props_buffer, 44, WNODE_FLAG_TRACED_GUID)

        props.BufferSize = 64
        props.MinimumBuffers = 8
        props.MaximumBuffers = 32
        props.FlushTimer = 1
        props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE
        props.EnableFlags = (EVENT_TRACE_FLAG_DISK_FILE_IO | EVENT_TRACE_FLAG_FILE_IO
                              | EVENT_TRACE_FLAG_FILE_IO_INIT | EVENT_TRACE_FLAG_PROCESS)
        props.LoggerNameOffset = ctypes.sizeof(EVENT_TRACE_PROPERTIES)

        status = advapi32.StartTraceW(ctypes.byref(self.session_handle), SESSION_NAME, ctypes.byref(props))

        if status == ERROR_ALREADY_EXISTS:
            print(f"[i] '{SESSION_NAME}' zaten calisiyor (baska bir arac -Procmon/xperf- kullaniyor olabilir), kapatilip yeniden baslatiliyor...")
            self.stop_session()
            time.sleep(0.5)
            status = advapi32.StartTraceW(ctypes.byref(self.session_handle), SESSION_NAME, ctypes.byref(props))

        if status != 0:
            print(f"[!] StartTraceW basarisiz. Hata Kodu: {status}")
            if status == 5:
                print("    (ERROR_ACCESS_DENIED - Yonetici olarak calistirdigindan emin ol)")
            return False

        print(f"[+] Klasik NT Kernel Logger oturumu baslatildi (Handle: {self.session_handle.value})")
        print("[+] FileIo event class'i EnableFlags ile aktif edildi (EnableTraceEx2 KULLANILMADI).")
        return True

    def stop_session(self):
        if not self.props_buffer:
            return
        props = EVENT_TRACE_PROPERTIES.from_buffer(self.props_buffer)
        advapi32.ControlTraceW(self.session_handle, SESSION_NAME, ctypes.byref(props), EVENT_TRACE_CONTROL_STOP)
        print("[-] Oturum kapatildi.")


@PEVENT_RECORD_CALLBACK
def event_callback(event_record_ptr):
    record = event_record_ptr.contents
    header = record.EventHeader

    # PROCESS class'i: yeni process baslatildiginda komut satirini kontrol et
    # (Shadow Copy silme vb. Defense Evasion tespiti icin), sonra cik.
    if guid_equal(header.ProviderId, PROCESS_GUID):
        if header.EventDescriptor.Opcode == PROCESS_EVENT_TYPE_START and record.UserData and record.UserDataLength > 0:
            try:
                raw = ctypes.string_at(record.UserData, record.UserDataLength)
                pid = header.ProcessId
                pname = get_pname(pid)
                # Process_TypeGroup1 MOF payload'i KARISIK kodlama iceriyor:
                # SID (binary) + ImageFileName (ANSI) + CommandLine (genelde
                # Unicode). Tek bir kodlamayla cozmeye calismak yanlis
                # hizalanmaya yol acabilir - bu yuzden HEM UTF-16LE HEM
                # ASCII/Latin-1 olarak iki ayri deneme yapip ikisinde de
                # anahtar kelime ariyoruz (hangisi dogru hizalanirsa onu yakalar).
                decoded_utf16 = raw.decode('utf-16le', errors='ignore')
                decoded_latin1 = raw.decode('latin-1', errors='ignore')
                check_defense_evasion(pid, pname, decoded_utf16)
                check_defense_evasion(pid, pname, decoded_latin1)
                check_privilege_escalation(pid, pname, decoded_utf16)
                check_privilege_escalation(pid, pname, decoded_latin1)
            except Exception:
                pass
        return

    # Sadece FileIo class'ina ait event'lerle ilgileniyoruz - diger tum
    # kernel event'leri (Thread, DiskIo vb.) burada elenir.
    if not guid_equal(header.ProviderId, FILE_IO_GUID):
        return

    opcode = header.EventDescriptor.Opcode
    pid = header.ProcessId
    pname = get_pname(pid)
    action = FILEIO_TYPE_MAP.get(opcode, f"BILINMEYEN_TYPE_{opcode}")

    file_path = None
    if record.UserData and record.UserDataLength > 0:
        try:
            raw_bytes = ctypes.string_at(record.UserData, record.UserDataLength)
            decoded = raw_bytes.decode('utf-16le', errors='ignore')
            match = re.search(r'(\\Device\\[^\x00\r\n]+|[A-Za-z]:\\[^\x00\r\n]+)', decoded)
            if match:
                file_path = match.group(0).split('\x00')[0].strip()
        except Exception:
            pass

    time_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    # DIRENUM kontrolu isim tasisin tasimasin HER ZAMAN calismali - DIRENUM
    # olayi genelde dosya/dizin adini bizim regex'imizin bulabildigi formatta
    # tasimiyor (isimsiz geliyor), bu yuzden asagidaki "if file_path" bloguna
    # hapsedilirse hic tetiklenmez. Bagimsiz olarak burada kontrol ediyoruz.
    check_discovery_anomaly(pid, pname, action)

    if file_path:
        if WATCH_PATH_KEYWORD and WATCH_PATH_KEYWORD not in file_path.lower():
            return  # izlenen klasorun disinda, gosterme

        check_canary_alert(pid, pname, action, file_path)
        check_ransomware_anomaly(pid, pname, action, file_path)
        check_entropy_anomaly(pid, pname, action, file_path)

        if not is_duplicate_event(pid, action, file_path) and not QUIET_MODE:
            reputation = process_reputation(pname)
            rep_tag = f" [{reputation}]" if reputation != "BILINMEYEN" else ""
            print(f"[{time_str}] [{action:<28}] PName: {pname:<16}{rep_tag} (PID: {pid:<5}) -> {file_path}", flush=True)
    else:
        if not SHOW_UNNAMED_EVENTS:
            return
        # Isim tasimayan event (Read/Write/SetInfo/Close vb.) - yine de opcode'u
        # gorelim ki bu opcode'un GERCEKTEN tetiklendigini kanitlayabilelim.
        print(f"[{time_str}] [{action:<28}] PName: {pname:<16} (PID: {pid:<5}) -> (isim yok, opcode={opcode})", flush=True)


# ==============================================================================
# PERIYODIK BELLEK TEMIZLIGI - 7/24 arka plan calisma icin
# ==============================================================================
# Mantik: Her yeni process, PID bazli sozluklerde (_proc_cache, _rename_events,
# _direnum_events, _entropy_cache, _pid_alert_history vb.) bir kayit acar.
# Sistem SUREKLI acilan/kapanan process'lerle 7/24 calisirsa, bu sozlukler
# hic temizlenmezse zamanla sinirsiz buyur (memory leak). Periyodik olarak,
# artik CALISMAYAN process'lere ait PID kayitlarini siliyoruz - bu ayrica
# PID YENIDEN KULLANIMI sorununu da (bkz. defense evasion/privesc cooldown
# duzeltmesi) dolayli olarak azaltir.
CACHE_CLEANUP_INTERVAL_SECONDS = 300.0  # 5 dakikada bir


def cleanup_stale_pid_caches():
    pid_keyed_dicts = [
        _proc_cache, _parent_cache, _rename_events, _last_alert,
        _direnum_events, _direnum_last_alert, _discovery_burst_timestamp,
        _evasion_alerted_pids, _privesc_alerted_pids, _pid_alert_history,
        _pid_incident_prompted,
    ]
    removed = 0
    for d in pid_keyed_dicts:
        stale_pids = [pid for pid in list(d.keys()) if isinstance(pid, int) and not psutil.pid_exists(pid)]
        for pid in stale_pids:
            d.pop(pid, None)
            removed += 1
    # _canary_last_alert ve _entropy_cache PID degil (pid,action)/path anahtarli,
    # basit boyut sinirlamasiyla (en eski kayitlari atarak) buyumesini kisitla.
    for d, max_size in ((_canary_last_alert, 5000), (_entropy_cache, 5000), (_dedupe_cache, 5000)):
        if len(d) > max_size:
            for k in list(d.keys())[: len(d) - max_size]:
                d.pop(k, None)
    if removed:
        print(f"[i] Bellek temizligi: {removed} artik gecerli olmayan PID kaydi silindi.", flush=True)


def periodic_cleanup_loop(stop_event):
    while not stop_event.is_set():
        stop_event.wait(CACHE_CLEANUP_INTERVAL_SECONDS)
        if not stop_event.is_set():
            try:
                cleanup_stale_pid_caches()
            except Exception:
                pass


def start_trace_consumer():
    log_file = EVENT_TRACE_LOGFILEW()
    session_name_buf = ctypes.create_unicode_buffer(SESSION_NAME)
    log_file.LoggerName = ctypes.cast(session_name_buf, wintypes.LPWSTR)
    log_file.LogFileMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD
    log_file.EventRecordCallback = event_callback

    trace_handle = advapi32.OpenTraceW(ctypes.byref(log_file))
    if trace_handle == 0 or trace_handle == 0xFFFFFFFFFFFFFFFF:
        print(f"[!] OpenTraceW basarisiz. Hata Kodu: {ctypes.GetLastError()}")
        return

    handle_array = (TRACEHANDLE * 1)(trace_handle)
    try:
        advapi32.ProcessTrace(handle_array, 1, None, None)
    except KeyboardInterrupt:
        pass
    finally:
        advapi32.CloseTrace(trace_handle)


if __name__ == "__main__":
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("[!] HATA: Yonetici olarak calistirmalisin!")
        sys.exit(1)

    enable_console_colors()

    # WATCH_DIR yoksa olustur, canary dosyasi(lari) yoksa otomatik olustur -
    # eskiden fim_etw.py'de vardi, buraya tasinmayi unutmustuk (production'da
    # canary'nin hic calismamasina yol aciyordu).
    os.makedirs(WATCH_DIR, exist_ok=True)
    ensure_canary_files(WATCH_DIR)

    # Her calistirmada temiz bir alarm log dosyasiyla basla (test raporu icin)
    try:
        if os.path.exists(ALERT_LOG_PATH):
            os.remove(ALERT_LOG_PATH)
    except OSError:
        pass

    session = ClassicKernelSession()

    if session.start_session():
        try:
            consumer_thread = threading.Thread(target=start_trace_consumer, daemon=True)
            consumer_thread.start()

            cleanup_stop_event = threading.Event()
            cleanup_thread = threading.Thread(target=periodic_cleanup_loop, args=(cleanup_stop_event,), daemon=True)
            cleanup_thread.start()

            print("=" * 90)
            print("  Klasik NT Kernel Logger ile FileIo izleme + gelişmiş tespit (TEK SCRIPT)")
            print("  Katmanlar: Canary | Davranışsal (rename hızı) | Entropi (akıllı false-positive filtresi)")
            print("             Defense Evasion (Shadow Copy) | Yetki Yükseltme | Discovery (destekleyici sinyal)")
            print("             Process İtibarı | Ebeveyn Zinciri")
            print(f"  Çalışma modu: {'SESSİZ (sadece gerçek alarm gösterilir)' if QUIET_MODE else 'AYRINTILI (tüm dosya olayları görünür - debug modu)'}")
            print(f"  Alarm log: {ALERT_LOG_PATH} (test_detection_suite.py için)")
            print(f"  Otomatik tepki: {'AKTIF' if AUTO_RESPONSE_ENABLED else 'KAPALI'}"
                  f"{' (DRY RUN)' if AUTO_RESPONSE_ENABLED and AUTO_RESPONSE_DRY_RUN else ''}")
            print("  (Çıkış: CTRL+C)")
            print("=" * 90 + "\n")
            if QUIET_MODE:
                print("  [i] Sistem arka planda çalışıyor. Şüpheli bir durum olmadıkça hiçbir şey basılmayacak.\n", flush=True)

            while consumer_thread.is_alive():
                time.sleep(0.5)

        except KeyboardInterrupt:
            print("\n[-] Kapatiliyor...")
        finally:
            cleanup_stop_event.set()
            session.stop_session()