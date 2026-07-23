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
# KATMAN 1: PROCESS NAME RESOLVER (ÖNBELLEKLİ PID ÇÖZÜCÜ)
# ==============================================================================
class ProcessNameResolver:
    def __init__(self):
        self.cache = {}

    def get_name(self, pid):
        if pid in self.cache:
            return self.cache[pid]
        try:
            name = psutil.Process(pid).name()
            self.cache[pid] = name
            return name
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return "Bilinmeyen / Kapanmis"


# ==============================================================================
# KATMAN 2: WIN32 C-TYPES & ETW STRUCT TANIMLARI
# ==============================================================================
class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", wintypes.BYTE * 8)
    ]

# Microsoft-Windows-Kernel-File GUID
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
        ("CurrentEvent", EVENT_RECORD),
        ("LogfileHeader", wintypes.BYTE * 280),
        ("BufferCallback", ctypes.c_void_p),
        ("BufferSize", wintypes.ULONG),
        ("Filled", wintypes.ULONG),
        ("EventsLost", wintypes.ULONG),
        ("EventRecordCallback", PEVENT_RECORD_CALLBACK),
        ("IsKernelTrace", wintypes.ULONG),
        ("Context", ctypes.c_void_p)
    ]

# TRACEHANDLE Windows'ta 64-bit'lik bir değerdir (ULONG64).
# x64 platformda wintypes.HANDLE de 8 byte olduğu için pratikte çalışır,
# ama en doğrusu ayrı bir tip tanımlamaktır.
TRACEHANDLE = ctypes.c_uint64

# ==============================================================================
# KATMAN 3: WIN32 DLL İMZALARI & SABİTLER
# ==============================================================================
advapi32 = ctypes.windll.advapi32

advapi32.StartTraceW.restype = wintypes.ULONG
advapi32.StartTraceW.argtypes = [
    ctypes.POINTER(TRACEHANDLE),
    wintypes.LPCWSTR,
    ctypes.POINTER(EVENT_TRACE_PROPERTIES)
]

advapi32.ControlTraceW.restype = wintypes.ULONG
advapi32.ControlTraceW.argtypes = [
    TRACEHANDLE,
    wintypes.LPCWSTR,
    ctypes.POINTER(EVENT_TRACE_PROPERTIES),
    wintypes.ULONG
]

advapi32.EnableTraceEx2.restype = wintypes.ULONG
advapi32.EnableTraceEx2.argtypes = [
    TRACEHANDLE,
    ctypes.POINTER(GUID),
    wintypes.ULONG,
    wintypes.BYTE,
    ctypes.c_uint64,
    ctypes.c_uint64,
    wintypes.ULONG,
    ctypes.c_void_p
]

advapi32.OpenTraceW.restype = TRACEHANDLE
advapi32.OpenTraceW.argtypes = [ctypes.POINTER(EVENT_TRACE_LOGFILEW)]

advapi32.ProcessTrace.restype = wintypes.ULONG
advapi32.ProcessTrace.argtypes = [ctypes.POINTER(TRACEHANDLE), wintypes.ULONG, ctypes.c_void_p, ctypes.c_void_p]

advapi32.CloseTrace.restype = wintypes.ULONG
advapi32.CloseTrace.argtypes = [TRACEHANDLE]

EVENT_TRACE_REAL_TIME_MODE = 0x00000100
PROCESS_TRACE_MODE_REAL_TIME = 0x00000100
PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000
TRACE_LEVEL_INFORMATION = 4
WNODE_FLAG_TRACED_GUID = 0x00020000
EVENT_TRACE_CONTROL_STOP = 1
EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1
ERROR_ALREADY_EXISTS = 183
INVALID_PROCESSTRACE_HANDLE = 0xFFFFFFFFFFFFFFFF

SESSION_NAME = "PythonFIMKernelTrace"

EVENT_MAP = {
    10: "OLUSTURULDU",
    11: "SILINDI",
    12: "ACILDI",
    14: "DEGISTIRILDI (WRITE)",
    15: "FLUSH (DISKE YAZILDI)",
    21: "YENIDEN ADLANDIRILDI"
}

# ==============================================================================
# KATMAN 4: OTURUM YÖNETİMİ & CONSUMER CALLBACK
# ==============================================================================
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

        # Wnode.BufferSize -> offset 0
        struct.pack_into('I', self.props_buffer, 0, props_size)
        # Wnode.Flags -> offset 44 (64-bit WNODE_HEADER layout: BufferSize(4)+ProviderId(4)+
        # HistoricalContext(8)+KernelHandle/TimeStamp(8)+Guid(16)+ClientContext(4)+Flags(4) = 48)
        struct.pack_into('I', self.props_buffer, 44, WNODE_FLAG_TRACED_GUID)

        props.BufferSize = 64
        props.MinimumBuffers = 8
        props.MaximumBuffers = 32
        props.FlushTimer = 1  # 1 Saniyede bir tamponu ekrana zorla boşalt
        props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE
        props.LoggerNameOffset = ctypes.sizeof(EVENT_TRACE_PROPERTIES)

        status = advapi32.StartTraceW(
            ctypes.byref(self.session_handle),
            self.session_name,
            ctypes.byref(props)
        )

        if status == ERROR_ALREADY_EXISTS:
            print(f"[i] '{self.session_name}' oturumu zaten mevcut, kapatılıp yeniden başlatılıyor...")
            self.stop_session()
            return self.start_session()

        if status != 0:
            print(f"ETW oturumu başlatılamadı. Hata Kodu: {status} -> {ctypes.WinError(status)}")
            return False

        print(f"ETW oturumu başlatıldı: {self.session_name} (Handle: {self.session_handle.value})")

        status_enable = advapi32.EnableTraceEx2(
            self.session_handle,
            ctypes.byref(KERNEL_FILE_PROVIDER_GUID),
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_INFORMATION,
            ctypes.c_uint64(0xFFFFFFFFFFFFFFFF),
            ctypes.c_uint64(0),
            0,
            None
        )

        if status_enable != 0:
            print(f"Provider Baglanamadi. Hata Kodu: {status_enable} -> {ctypes.WinError(status_enable)}")
            return False

        print("Microsoft-Windows-Kernel-File Sağlayıcısı (Tüm Keywords) Bağlandı.")
        return True

    def stop_session(self):
        if not self.props_buffer:
            return
        props = EVENT_TRACE_PROPERTIES.from_buffer(self.props_buffer)
        status = advapi32.ControlTraceW(
            self.session_handle,
            self.session_name,
            ctypes.byref(props),
            EVENT_TRACE_CONTROL_STOP
        )
        if status != 0 and status != 4871:  # ERROR_WMI_INSTANCE_NOT_FOUND (zaten kapalıysa)
            print(f"[!] ControlTraceW (STOP) uyarısı. Hata Kodu: {status}")
        else:
            print("ETW oturumu kapatildi.")


process_resolver = ProcessNameResolver()

@PEVENT_RECORD_CALLBACK
def event_callback(event_record_ptr):
    record = event_record_ptr.contents
    header = record.EventHeader

    event_id = header.EventDescriptor.Id
    # Debug: her gelen ham event'i göster. Sorun çözüldükten sonra bu satırı silebilirsin.
    print(f"[DEBUG] RAW EVENT geldi -> Id={event_id} PID={header.ProcessId} UserDataLen={record.UserDataLength}", flush=True)

    pid = header.ProcessId
    pname = process_resolver.get_name(pid)
    opcode = header.EventDescriptor.Opcode

    action = EVENT_MAP.get(event_id, f"EVENT_{event_id}_OP_{opcode}")

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

    if file_path:
        print(f"[{time_str}] [{action:<22}] PName: {pname:<18} (PID: {pid:<5}) -> Path: {file_path}", flush=True)


def start_trace_consumer(session_name=SESSION_NAME):
    log_file = EVENT_TRACE_LOGFILEW()

    session_name_buf = ctypes.create_unicode_buffer(session_name)
    log_file.LoggerName = ctypes.cast(session_name_buf, wintypes.LPWSTR)
    log_file.LogFileMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD
    log_file.EventRecordCallback = event_callback

    trace_handle = advapi32.OpenTraceW(ctypes.byref(log_file))

    if trace_handle == 0 or trace_handle == INVALID_PROCESSTRACE_HANDLE:
        err = ctypes.GetLastError()
        print(f"OpenTraceW Hatası! Hata Kodu: {err} -> {ctypes.WinError(err)}")
        return

    print("Event Consumer Hazır. Canlı izleme başlatılıyor...")
    print("=" * 90)

    handle_array = (TRACEHANDLE * 1)(trace_handle)

    try:
        status = advapi32.ProcessTrace(handle_array, 1, None, None)
        if status != 0:
            print(f"[!] ProcessTrace döndü. Hata Kodu: {status} -> {ctypes.WinError(status)}")
    except KeyboardInterrupt:
        print("\n[-] Kullanıcı tarafından durduruldu.")
    finally:
        advapi32.CloseTrace(trace_handle)


# ==============================================================================
# KATMAN 5: ANA ÇALIŞTIRMA BLOĞU
# ==============================================================================
if __name__ == "__main__":
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        is_admin = False

    if not is_admin:
        print("[!] HATA: ETW Kernel oturumu açmak için terminali YÖNETİCİ OLARAK çalıştırmalısınız!")
        sys.exit(1)

    etw = ETWKernelSession()

    if etw.start_session():
        try:
            consumer_thread = threading.Thread(target=start_trace_consumer, daemon=True)
            consumer_thread.start()

            print("\n[>>>] CANLI İZLEME BAŞLADI. Dosya işlemleri yapmayı deneyin! (Çıkış: CTRL+C)\n")

            while consumer_thread.is_alive():
                time.sleep(0.5)

        except KeyboardInterrupt:
            print("\n[-] Kapatılıyor...")
        finally:
            etw.stop_session()