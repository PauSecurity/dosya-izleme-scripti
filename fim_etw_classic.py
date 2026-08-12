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
    "vssadmin", "wmic shadowcopy", "shadowcopy delete", "bcdedit",
    "wbadmin delete", "recoveryenabled", "diskshadow", "delete shadows",
    "delete catalog",
)
_evasion_alerted_pids = set()
_evasion_lock = threading.Lock()


def check_defense_evasion(pid, pname, decoded_userdata):
    lowered = decoded_userdata.lower()
    matched = next((kw for kw in SUSPICIOUS_COMMAND_KEYWORDS if kw in lowered), None)
    if not matched:
        return

    with _evasion_lock:
        if pid in _evasion_alerted_pids:
            return
        _evasion_alerted_pids.add(pid)

    # Komut satirini okunabilir hale getirmeye calis: null byte'larla ayrilmis
    # parcalar arasinda anahtar kelimeyi iceren parcayi bul.
    fragments = [f for f in decoded_userdata.split('\x00') if f.strip()]
    command_guess = next((f for f in fragments if matched in f.lower()), matched)

    RED = "\033[91m"
    RESET = "\033[0m"
    message = (f"[🚨 DEFENSE EVASION] PID: {pid} ({pname}) YEDEK/KURTARMA SİLME KOMUTU "
               f"TESPİT EDİLDİ: '{command_guess.strip()}' - şifrelemeden ÖNCEKİ hazırlık aşaması olabilir!")
    message = escalate_with_discovery_context(pid, message)
    print(f"{RED}{message}{RESET}", flush=True)
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
CANARY_ALERT_ACTIONS = {"SILINDI (SetDelete)", "YENIDEN ADLANDIRILDI", "YAZILDI (Write)", "SETINFO"}
CANARY_ALERT_COOLDOWN_SECONDS = 5.0
_canary_last_alert = {}
_canary_lock = threading.Lock()


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
    print(f"{RED}{message}{RESET}", flush=True)
    auto_respond(pid, pname, "canary dosyaya dokundu")


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
    print(f"{RED}{message}{RESET}", flush=True)
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


def auto_respond(pid, pname, reason):
    if not AUTO_RESPONSE_ENABLED:
        return

    RED = "\033[91m"
    RESET = "\033[0m"

    if AUTO_RESPONSE_DRY_RUN:
        print(f"{RED}[🛑 OTOMATIK TEPKİ - DRY RUN] PID {pid} ({pname}) DURDURULACAKTI "
              f"(sebep: {reason}) - gerçekte durdurulmadı, AUTO_RESPONSE_DRY_RUN=True{RESET}", flush=True)
        return

    try:
        proc = psutil.Process(pid)
        proc.suspend()  # once dondur (kill() yerine suspend() daha az yikici - geri alinabilir)
        print(f"{RED}[🛑 OTOMATIK TEPKİ] PID {pid} ({pname}) DONDURULDU (sebep: {reason}){RESET}", flush=True)
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        print(f"[!] Otomatik tepki başarısız: {e}", flush=True)


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

        reputation = process_reputation(pname)
        rep_tag = f" [{reputation}]" if reputation != "BILINMEYEN" else ""
        print(f"[{time_str}] [{action:<28}] PName: {pname:<16}{rep_tag} (PID: {pid:<5}) -> {file_path}", flush=True)
    else:
        if not SHOW_UNNAMED_EVENTS:
            return
        # Isim tasimayan event (Read/Write/SetInfo/Close vb.) - yine de opcode'u
        # gorelim ki bu opcode'un GERCEKTEN tetiklendigini kanitlayabilelim.
        print(f"[{time_str}] [{action:<28}] PName: {pname:<16} (PID: {pid:<5}) -> (isim yok, opcode={opcode})", flush=True)


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

    session = ClassicKernelSession()

    if session.start_session():
        try:
            consumer_thread = threading.Thread(target=start_trace_consumer, daemon=True)
            consumer_thread.start()

            print("=" * 90)
            print("  Klasik NT Kernel Logger ile FileIo izleme + gelişmiş tespit")
            print("  Katmanlar: Canary | Davranışsal (rename hızı) | Defense Evasion (Shadow Copy)")
            print("             Process İtibarı | Ebeveyn Zinciri | Discovery (destekleyici sinyal)")
            print(f"  Otomatik tepki: {'AKTIF' if AUTO_RESPONSE_ENABLED else 'KAPALI'}"
                  f"{' (DRY RUN)' if AUTO_RESPONSE_ENABLED and AUTO_RESPONSE_DRY_RUN else ''}")
            print("  (Çıkış: CTRL+C)")
            print("=" * 90 + "\n")

            while consumer_thread.is_alive():
                time.sleep(0.5)

        except KeyboardInterrupt:
            print("\n[-] Kapatiliyor...")
        finally:
            session.stop_session()