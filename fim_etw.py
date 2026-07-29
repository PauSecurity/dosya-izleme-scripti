import ctypes
from ctypes import wintypes
import sys
import os
import struct
import time
import uuid
from datetime import datetime
import threading
import psutil
import re
from collections import OrderedDict

# ==============================================================================
# KATMAN 0: KULLANICI OTURUMU (SESSION) TESPITI
# ==============================================================================
# Windows'ta SYSTEM/servis process'leri her zaman Session 0'da calisir.
# Sizin masaustunuzdeki/interaktif her sey (explorer, tarayici, vs.) ise
# aktif KONSOL session'inda calisir. Bu ikisini ayirt ederek "gercek
# kullanici aksiyonu" ile "arka plan/sistem aksiyonu"nu filtreleyebiliriz.
kernel32 = ctypes.windll.kernel32
kernel32.WTSGetActiveConsoleSessionId.restype = wintypes.DWORD
kernel32.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
kernel32.ProcessIdToSessionId.restype = wintypes.BOOL

ACTIVE_CONSOLE_SESSION_ID = kernel32.WTSGetActiveConsoleSessionId()

_session_cache = {}

# Ayni (process, dosya, aksiyon) ucluesi kisa bir sure icinde tekrar tekrar
# gelirse (Explorer/VSCode'un ayni dosyaya art arda handle acmasi gibi)
# sadece ilkini goster. Bu, gercek FIM anlaminda "gurultu"yu keser.
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

def is_from_active_user_session(pid):
    """PID, aktif interaktif kullanici session'inda mi calisiyor? (Session 0 = sistem/servis -> False)"""
    if not pid:
        return False
    if pid in _session_cache:
        return _session_cache[pid]
    session_id = wintypes.DWORD(0)
    ok = kernel32.ProcessIdToSessionId(wintypes.DWORD(pid), ctypes.byref(session_id))
    result = bool(ok) and session_id.value == ACTIVE_CONSOLE_SESSION_ID
    _session_cache[pid] = result
    return result

# ==============================================================================
# KATMAN 1: PROCESS RESOLVER & FİLTRE KURALLARI
# ==============================================================================
class ProcessNameResolver:
    def __init__(self):
        self.cache = {}

    def get_name(self, pid):
        if not pid:
            return "System"
        if pid in self.cache:
            return self.cache[pid]
        try:
            name = psutil.Process(pid).name()
            self.cache[pid] = name
            return name
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return "Kapanmis/Bilinmeyen"

process_resolver = ProcessNameResolver()

NOISE_KEYWORDS = [
    "$mft", "$logfile", "$bitmap", "\\appdata\\local\\temp",
    ".tmp", ".log", "ntuser.dat", "edb.log", "\\windows\\system32",
    "desktop.ini"
]

# Izlenecek klasor. \Device\HarddiskVolumeX\... seklindeki NT yollarinda
# eslesme yapabilmek icin sadece klasor adini (kucuk harf) kullaniyoruz.
WATCH_PATH_KEYWORD = "\\filemonitoring\\"

# True ise: sadece AKTIF KULLANICI OTURUMUNDAKI (Session 0 = sistem/servis DEGIL)
# process'lerin olaylari gosterilir. SYSTEM/servis kaynakli arka plan
# gurultusunu otomatik eler.
ONLY_ACTIVE_USER_SESSION = True

def is_watched_path(file_path):
    if not file_path:
        return False
    lower = file_path.lower()
    return WATCH_PATH_KEYWORD in lower or lower.endswith(WATCH_PATH_KEYWORD.rstrip("\\"))

def is_noise(file_path, pid=None):
    if not file_path or len(file_path) < 3:
        return True
    for noise in NOISE_KEYWORDS:
        if noise in file_path.lower():
            return True
    if not is_watched_path(file_path):
        return True
    if ONLY_ACTIVE_USER_SESSION and pid is not None and not is_from_active_user_session(pid):
        return True
    return False

# ==============================================================================
# KATMAN 2: WIN32 C-TYPES STRUCT TANIMLARI
# ==============================================================================
class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8)
    ]

KERNEL_FILE_PROVIDER_GUID = GUID(
    0xEDD08927, 0x9CC4, 0x4E65,
    (ctypes.c_ubyte * 8)(0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89)
)

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

# GERCEK EVENT_TRACE struct'i (EVENT_RECORD ile KARISTIRILMAMALI - farkli/kucuk boyut!)
# Bu, EVENT_TRACE_LOGFILEW.CurrentEvent alaninin GERCEK tipidir.
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

# EnableTraceEx2 icin gerekli struct - EnableParameters NULL olamaz!
class ENABLE_TRACE_PARAMETERS(ctypes.Structure):
    _fields_ = [
        ("Version", wintypes.ULONG),
        ("EnableProperty", wintypes.ULONG),
        ("ControlFlags", wintypes.ULONG),
        ("SourceId", GUID),
        ("EnableFilterDesc", ctypes.c_void_p),
        ("FilterDescCount", wintypes.ULONG),
    ]

ENABLE_TRACE_PARAMETERS_VERSION2 = 2

# ==============================================================================
# KATMAN 3: WIN32 DLL İMZALARI & SABİTLER
# ==============================================================================
advapi32 = ctypes.windll.advapi32

advapi32.StartTraceW.restype = wintypes.ULONG
advapi32.StartTraceW.argtypes = [ctypes.POINTER(TRACEHANDLE), wintypes.LPCWSTR, ctypes.POINTER(EVENT_TRACE_PROPERTIES)]
advapi32.ControlTraceW.restype = wintypes.ULONG
advapi32.ControlTraceW.argtypes = [TRACEHANDLE, wintypes.LPCWSTR, ctypes.POINTER(EVENT_TRACE_PROPERTIES), wintypes.ULONG]
advapi32.EnableTraceEx2.restype = wintypes.ULONG
advapi32.EnableTraceEx2.argtypes = [
    TRACEHANDLE, ctypes.POINTER(GUID), wintypes.ULONG, wintypes.BYTE,
    ctypes.c_uint64, ctypes.c_uint64, wintypes.ULONG,
    ctypes.POINTER(ENABLE_TRACE_PARAMETERS)
]
advapi32.OpenTraceW.restype = TRACEHANDLE
advapi32.OpenTraceW.argtypes = [ctypes.POINTER(EVENT_TRACE_LOGFILEW)]
advapi32.ProcessTrace.restype = wintypes.ULONG
advapi32.ProcessTrace.argtypes = [ctypes.POINTER(TRACEHANDLE), wintypes.ULONG, ctypes.c_void_p, ctypes.c_void_p]
advapi32.CloseTrace.restype = wintypes.ULONG
advapi32.CloseTrace.argtypes = [TRACEHANDLE]

EVENT_TRACE_REAL_TIME_MODE = 0x00000100
EVENT_TRACE_SYSTEM_LOGGER_MODE = 0x02000000  # Kernel-File gibi "system provider"lari enable etmek icin ZORUNLU
PROCESS_TRACE_MODE_REAL_TIME = 0x00000100
PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000
TRACE_LEVEL_INFORMATION = 4
WNODE_FLAG_TRACED_GUID = 0x00020000
SESSION_NAME = "PythonFIMKernelTrace"
EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1

# Gercek Microsoft-Windows-Kernel-File manifest ID'leri (repnz/etw-providers-docs kaynagi)
EVENT_MAP = {
    12: "OLUSTURULDU/ACILDI",
    14: "KAPANDI",
    15: "OKUNDU (READ)",
    16: "YAZILDI (WRITE)",
    17: "SETINFO",
    18: "SILINDI (SetDelete)",
    19: "YENIDEN ADLANDIRILDI",
    21: "DISKE YAZILDI (FLUSH)",
    30: "OLUSTURULDU (YENI DOSYA)",
}

# Sablonlarda "FileObject" pointer alaninin UserData icindeki bayt offseti.
# CreateArgs/CleanupArgs/SetInformationArgs -> Irp(8)+ThreadId(8) sonrasi -> offset 16
# ReadArgs (Read VE Write ayni sablonu kullanir) -> ByteOffset(8) once gelir -> offset 24
FILE_OBJECT_OFFSET = {
    12: 16,  # Create
    14: 16,  # Close (CleanupArgs)
    15: 24,  # Read  (ReadArgs)
    16: 24,  # Write (ReadArgs sablonu)
    17: 16,  # SetInformation
    18: 16,  # SetDelete
    19: 16,  # Rename
    21: 16,  # Flush (CleanupArgs)
    30: 16,  # CreateNewFile (Create ile ayni sablon)
}

# FileObject (pointer) -> dosya yolu eslemesi. SetDelete/Rename/Write/Read/Close
# gibi olaylar dosya adini metin olarak TASIMAZ, sadece bu pointer'i tasir.
# Create olayinda ogrendigimiz yolu burada saklayip diger olaylarda geri cagiriyoruz.
_MAX_FILE_OBJECT_MAP = 20000
_file_object_to_path = OrderedDict()

def remember_file_object(file_object, path):
    if file_object is None or not path:
        return
    _file_object_to_path[file_object] = path
    _file_object_to_path.move_to_end(file_object)
    if len(_file_object_to_path) > _MAX_FILE_OBJECT_MAP:
        _file_object_to_path.popitem(last=False)

def lookup_file_object(file_object):
    if file_object is None:
        return None
    return _file_object_to_path.get(file_object)

# ==============================================================================
# KATMAN 4: ETW KERNEL OTURUMU & CONSUMER
# ==============================================================================
# ==============================================================================
# KATMAN 3.5: POLLING TABANLI KLASOR IZLEYICI (CREATE/DELETE/RENAME icin)
# ==============================================================================
# ETW kernel event semasi Windows surumden surume degisebiliyor (bu sistemde
# beklenen SetDelete/Rename event'leri farkli davraniyor). CREATE/DELETE/RENAME
# icin, kernel semasina hic bagli olmayan, HER Windows surumunde ayni sekilde
# calisan basit ve saglam bir yontem: klasoru kisa araliklarla tarayip
# onceki anlik goruntu (snapshot) ile karsilastirmak.
WATCH_DIR = r"C:\FileMonitoring"
POLL_INTERVAL_SECONDS = 0.5

def _snapshot_dir(path):
    """path altindaki (alt klasorler dahil) tum dosyalarin {yol: (boyut, mtime)} halini dondurur."""
    snapshot = {}
    try:
        for root, dirs, files in os.walk(path):
            for name in files:
                full = os.path.join(root, name)
                try:
                    st = os.stat(full)
                    snapshot[full] = (st.st_size, st.st_mtime)
                except OSError:
                    pass
    except OSError:
        pass
    return snapshot

def poll_watch_dir(stop_event):
    if not os.path.isdir(WATCH_DIR):
        try:
            os.makedirs(WATCH_DIR, exist_ok=True)
        except OSError as e:
            print(f"[!] {WATCH_DIR} olusturulamadi: {e}")
            return

    previous = _snapshot_dir(WATCH_DIR)

    while not stop_event.is_set():
        time.sleep(POLL_INTERVAL_SECONDS)
        current = _snapshot_dir(WATCH_DIR)

        added = [p for p in current if p not in previous]
        removed = [p for p in previous if p not in current]
        modified = [p for p in current if p in previous and current[p] != previous[p]]

        # Basit rename tespiti: ayni anda 1 dosya kaybolup 1 dosya (ayni boyutla) belirdiyse rename say
        if len(added) == 1 and len(removed) == 1:
            old_path, new_path = removed[0], added[0]
            old_size = previous.get(old_path, (None, None))[0]
            new_size = current.get(new_path, (None, None))[0]
            if old_size == new_size:
                time_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                print(f"[{time_str}] [YENIDEN ADLANDIRILDI  ] {old_path} -> {new_path}", flush=True)
                previous = current
                continue

        time_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        for p in added:
            print(f"[{time_str}] [OLUSTURULDU (POLL)  ] -> {p}", flush=True)
        for p in removed:
            print(f"[{time_str}] [SILINDI (POLL)      ] -> {p}", flush=True)
        for p in modified:
            print(f"[{time_str}] [DEGISTIRILDI (POLL) ] -> {p}", flush=True)

        previous = current


class ETWKernelSession:
    def __init__(self, session_name=SESSION_NAME):
        self.session_name = session_name
        self.session_handle = TRACEHANDLE(0)
        self.props_buffer = None

    def start_session(self):
        name_bytes = (self.session_name + '\0').encode('utf-16le')
        props_size = ctypes.sizeof(EVENT_TRACE_PROPERTIES) + len(name_bytes)

        self.props_buffer = ctypes.create_string_buffer(props_size)
        props = EVENT_TRACE_PROPERTIES.from_buffer(self.props_buffer)

        struct.pack_into('I', self.props_buffer, 0, props_size)
        # ZORUNLU: SystemTraceProvider (EVENT_TRACE_SYSTEM_LOGGER_MODE) oturumlarinda
        # Wnode.Guid alanina benzersiz, sifir OLMAYAN bir GUID atanmalidir.
        # (Wnode layout: BufferSize(4)+ProviderId(4)+HistoricalContext(8)+TimeStamp(8) = offset 24 -> Guid[16])
        struct.pack_into('16s', self.props_buffer, 24, uuid.uuid4().bytes)
        struct.pack_into('I', self.props_buffer, 44, WNODE_FLAG_TRACED_GUID)

        props.BufferSize = 64
        props.MinimumBuffers = 8
        props.MaximumBuffers = 32
        props.FlushTimer = 1
        # SYSTEM_LOGGER_MODE olmadan Kernel-File gibi modern kernel provider'lar
        # etkinlestirilemez / event uretmez.
        props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE
        props.LoggerNameOffset = ctypes.sizeof(EVENT_TRACE_PROPERTIES)

        status = advapi32.StartTraceW(ctypes.byref(self.session_handle), self.session_name, ctypes.byref(props))

        if status == 183:  # ERROR_ALREADY_EXISTS
            self.stop_session()
            return self.start_session()

        if status != 0:
            print(f"[!] ETW Oturumu Açılamadı. Hata Kodu: {status}")
            return False

        print(f"[+] ETW Kernel Oturumu Başlatıldı: {self.session_name}")

        enable_params = ENABLE_TRACE_PARAMETERS()
        enable_params.Version = ENABLE_TRACE_PARAMETERS_VERSION2

        enable_status = advapi32.EnableTraceEx2(
            self.session_handle,
            ctypes.byref(KERNEL_FILE_PROVIDER_GUID),
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_INFORMATION,
            ctypes.c_uint64(0xFFFFFFFFFFFFFFFF),
            ctypes.c_uint64(0),
            0,
            ctypes.byref(enable_params)
        )

        if enable_status != 0:
            print(f"[!] EnableTraceEx2 başarısız oldu. Hata Kodu: {enable_status}")
            self.stop_session()
            return False

        print("[+] Microsoft-Windows-Kernel-File Dinleyicisi Aktif.")
        return True

    def stop_session(self):
        if not self.props_buffer:
            return
        props = EVENT_TRACE_PROPERTIES.from_buffer(self.props_buffer)
        advapi32.ControlTraceW(self.session_handle, self.session_name, ctypes.byref(props), 1)
        print("[-] ETW Oturumu Kapatıldı.")


@PEVENT_RECORD_CALLBACK
def event_callback(event_record_ptr):
    record = event_record_ptr.contents
    header = record.EventHeader

    event_id = header.EventDescriptor.Id
    pid = header.ProcessId
    pname = process_resolver.get_name(pid)
    action = EVENT_MAP.get(event_id, None)

    # İlgilenmediğimiz opcode veya event'leri atla
    if not action:
        return

    file_path = None
    file_object = None

    if record.UserData and record.UserDataLength > 0:
        try:
            raw_bytes = ctypes.string_at(record.UserData, record.UserDataLength)

            # FileObject pointer'ini ilgili sablon offsetinden cikar
            fo_offset = FILE_OBJECT_OFFSET.get(event_id, 16)
            if len(raw_bytes) >= fo_offset + 8:
                file_object = struct.unpack_from('<Q', raw_bytes, fo_offset)[0]

            decoded = raw_bytes.decode('utf-16le', errors='ignore')

            # Windows dosya yollarını yakala (\Device\HarddiskVolume... veya C:\...)
            match = re.search(r'(\\Device\\[^\x00\r\n]+|[A-Za-z]:\\[^\x00\r\n]+)', decoded)
            if match:
                file_path = match.group(0).split('\x00')[0].strip()
        except Exception:
            pass

    if event_id in (12, 30) and file_path:
        # Create/CreateNewFile olayi: FileObject -> yol eslemesini ogren/guncelle
        remember_file_object(file_object, file_path)
    elif not file_path:
        # Isim tasimayan olay (SetDelete/Rename/Write/Read/Close/Flush/SetInfo):
        # daha once ogrenilen yolu FileObject uzerinden geri cagir
        file_path = lookup_file_object(file_object)

    if event_id == 14:
        # Close: bu FileObject artik gecerli degil, haritadan temizle (adres yeniden kullanilabilir)
        _file_object_to_path.pop(file_object, None)

    if file_path and not is_noise(file_path, pid=pid) and not is_duplicate_event(pid, action, file_path):
        time_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        print(f"[{time_str}] [{action:<20}] PName: {pname:<16} (PID: {pid:<5}) -> {file_path}", flush=True)


def start_trace_consumer(session_name=SESSION_NAME):
    log_file = EVENT_TRACE_LOGFILEW()
    session_name_buf = ctypes.create_unicode_buffer(session_name)
    log_file.LoggerName = ctypes.cast(session_name_buf, wintypes.LPWSTR)
    log_file.LogFileMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD
    log_file.EventRecordCallback = event_callback

    trace_handle = advapi32.OpenTraceW(ctypes.byref(log_file))

    if trace_handle == 0 or trace_handle == 0xFFFFFFFFFFFFFFFF:
        print("[!] OpenTraceW Hatası!")
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
        print("[!] HATA: Terminali YÖNETİCİ OLARAK çalıştırmalısınız!")
        sys.exit(1)

    etw = ETWKernelSession()

    if etw.start_session():
        try:
            consumer_thread = threading.Thread(target=start_trace_consumer, daemon=True)
            consumer_thread.start()

            poll_stop_event = threading.Event()
            poll_thread = threading.Thread(target=poll_watch_dir, args=(poll_stop_event,), daemon=True)
            poll_thread.start()

            print("=" * 90)
            print("   [+] KERNEL-LEVEL FIM (STABIL WIN32 API) AKTİF")
            print(f"   [>>>] Izlenen yol: *\\FileMonitoring\\*  |  Sadece aktif kullanici oturumu (Session {ACTIVE_CONSOLE_SESSION_ID})")
            print(f"   [>>>] CREATE/DELETE/RENAME icin ek olarak {WATCH_DIR} polling ile de izleniyor ({POLL_INTERVAL_SECONDS}s)")
            print("   [>>>] C:\\FileMonitoring altinda dosya oluşturmayı/silmeyi deneyin (Çıkış: CTRL+C)")
            print("=" * 90 + "\n")

            while consumer_thread.is_alive():
                time.sleep(0.5)

        except KeyboardInterrupt:
            print("\n[-] Kapatılıyor...")
        finally:
            poll_stop_event.set()
            etw.stop_session()