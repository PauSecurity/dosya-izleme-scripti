import etw
import etw.evntrace as evntrace
import os
import sys
import psutil
from datetime import datetime

# ==============================================================================
# KATMAN 1: PROCESS RESOLVER & FİLTRE KURALLARI
# ==============================================================================
class ProcessResolver:
    def __init__(self):
        self.cache = {}

    def get_name(self, pid):
        if not pid:
            return "Sistem"
        if pid in self.cache:
            return self.cache[pid]
        try:
            name = psutil.Process(pid).name()
            self.cache[pid] = name
            return name
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return "Bilinmeyen/Kapanmış"

process_resolver = ProcessResolver()

NOISE_KEYWORDS = [
    "$Mft", "$LogFile", "$Bitmap", "\\AppData\\Local\\Temp",
    ".tmp", ".log", "NTUSER.DAT", "edb.log", "\\Windows\\System32"
]

def is_noise(file_path):
    """Sistem gürültüsü olan geçici dosya ve sistem yollarını filtreler."""
    if not file_path or len(file_path) < 3:
        return True
    for noise in NOISE_KEYWORDS:
        if noise.lower() in file_path.lower():
            return True
    return False

# ==============================================================================
# KATMAN 2: ETW CALLBACK
# ==============================================================================
def file_event_callback(event_tuple):
    """
    pywintrace geri çağırma verisini bir tuple/dict olarak teslim eder.
    """
    try:
        # Event verisini al (pywintrace veriyi tuple (msg, event_dict) olarak döner)
        event_data = event_tuple[1] if isinstance(event_tuple, tuple) else event_tuple

        header = event_data.get("EventHeader", {})
        payload = event_data.get("UserData", {}) or event_data.get("EventData", {})

        pid = header.get("ProcessId", 0)
        pname = process_resolver.get_name(pid)
        
        # Dosya yolu alanını yakala
        file_path = payload.get("FileName", payload.get("OpenPath", ""))

        if is_noise(file_path):
            return

        task_name = header.get("TaskName", "DOSYA_EYLEMI")
        time_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        print(f"[{time_str}] [{task_name:<18}] PName: {pname:<16} (PID: {pid:<5}) -> {file_path}")

    except Exception:
        pass

# ==============================================================================
# KATMAN 3: ETW OTURUM BAŞLATICI
# ==============================================================================
def start_fim():
    # Doğru ProviderInfo kullanımı
    try:
        provider = etw.ProviderInfo("Microsoft-Windows-Kernel-File", etw.GUID("{edd08927-9cc4-4e65-b970-c2560fb5c289}"))
    except AttributeError:
        # Alternatif erişim yolu
        provider = evntrace.ProviderInfo("Microsoft-Windows-Kernel-File", etw.GUID("{edd08927-9cc4-4e65-b970-c2560fb5c289}"))

    providers = [provider]

    print("=" * 80)
    print("   [+] KERNEL-LEVEL FIM (FILE INTEGRITY MONITOR) BAŞLATILDI")
    print("   [+] PyWinTrace Mimarisi Aktif (Bayt Yönetimi Kütüphanede)")
    print("   [+] Canlı Dosya İzlemesi Aktif. Çıkış için: CTRL+C")
    print("=" * 80 + "\n")

    # ETW İş parçacığını başlat
    job = etw.ETW(providers=providers, event_callback=file_event_callback)
    
    try:
        job.start()
        print("[>>>] Dinleme başladı. Bir klasörde dosya oluşturup silmeyi deneyin...\n")
        # Süreci canlı tut
        import time
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[-] FIM Durduruluyor...")
        job.stop()

if __name__ == "__main__":
    import ctypes
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("[!] HATA: ETW Kernel oturumu açmak için terminali YÖNETİCİ OLARAK çalıştırmalısınız!")
        sys.exit(1)

    start_fim()