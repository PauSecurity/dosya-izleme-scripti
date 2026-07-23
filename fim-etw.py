import ctypes
from ctypes import wintypes
import sys
import os

class GUID(ctypes.Structure): # GUID yapısını temsil eden bir sınıf
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", wintypes.BYTE * 8)
    ]


# Microsoft-Windows-Kernel-File GUID = edd08927-9cc4-4e65-b970-c2560fb5c289
KERNEL_FILE_PROVIDER_GUID = GUID(
    0xEDD08927, 0x9CC4, 0x4E65,
    (ctypes.c_byte * 8)(0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89)
)


class EVENT_TRACE_PROPERTIES(ctypes.Structure): # olaylarin izlenmesini saglayan yapi
    _fields_ = [
        ("Wnode", wintypes.WNODE_HEADER),
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

# Windows API DLL baglantisi
advapi32 = ctypes.windll.advapi32 # windows api fonk kullanmak icin advapi.dll yuklenmesi gerekir.

# Win32 sabitleri
EVENT_TRACE_REAL_TIME_MODE = 0x00000100
TRACE_LEVEL_INFORMATION = 4
SESSION_NAME = "PythonFIMKernelTrace"

class ETWKernelSession:
    def __init__(self,session_name = SESSION_NAME):
        self.session_name = session_name
        self.session_handle = wintypes.HANDLE(0)
        self.props_buffer = None

    def start_session(self):
        name_bytes = (self.session_name + '\0').encode('utf-16e')
        props_size = ctypes.sizeof(EVENT_TRACE_PROPERTIES) + len(name_bytes)

        self.props_buffer = ctypes.create_string_buffer(props_size)
        props = EVENT_TRACE_PROPERTIES.from_buffer(self.props_buffer)

        props.Wnode.c_buffer = ctypes.sizeof(EVENT_TRACE_PROPERTIES) # Wnode Size
        props.Wnode.Flags = 0x00020000 # WNODE_FLAG_TRACED_GUID
        props.BufferSize = 64          # 64 KB Tampon
        props.MinimumBuffers = 8
        props.MaximumBuffers = 32
        props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE # Canlı Bellek Akışı Modu
        props.LoggerNameOffset = ctypes.sizeof(EVENT_TRACE_PROPERTIES) # İsmin Bellekteki Adresi

        status = advapi32.StartTraceW( # win32 durum kodu
            ctypes.byref(self.session_handle),
            self.session_name,
            ctypes.byref(props)
        )

        if status == 183:
            self.stop_session() # onceki oturum durdurulur.
            return self.start_session() # oturum tekrar baslatilir.

        if status != 0:
            print(f"ETW oturumu başlatılamadı. Hata kodu: {status}")
            return False

        print(f"ETW oturumu başlatıldı: {self.session_name}")

        status_enable = advapi32.EnableTraceEx2(
            self.session_handle,
            ctypes.byref(KERNEL_FILE_PROVIDER_GUID),
            1,
            TRACE_LEVEL_INFORMATION,
            0 , 0 , 0 , None
        )

        if status_enable != 0:
            print(f"Provider Baglanamadi. {status_enable}")
            return False

        print("Microsoft-Windows-Kernel-File Sağlayıcısı Oturuma Baglandi")
        return True

    def stop_session(self):
        if self.props_buffer:
            props = EVENT_TRACE_PROPERTIES.from_buffer(self.props_buffer)
            advapi32.ControlTraceW(
                self.session_handle,
                self.session_name,
                ctypes.byref(props),
                1
            )         
            print("ETW oturumu kapatildi.")