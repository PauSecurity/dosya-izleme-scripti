import sys
import time
import os
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class KlasorIzleyici(FileSystemEventHandler):

    def _pid_bul(self, hedef_dosya_yolu):

        hedef_abs = os.path.abspath(hedef_dosya_yolu).lower()

        for process in psutil.process_iter(['pid','name']):
            try:
                open_files = process.open_files()
                for file_struct in open_files:
                    if file_struct.path.lower() == hedef_abs:
                        return process.info['pid'], process.info['name']
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return None, "Bilinmiyor/Kapatildi"

    def _dosya_gecerli_mi(self, dosya_yolu):
        dosya_adi = os.path.basename(dosya_yolu)
        if dosya_adi.startswith(".") or dosya_adi.startswith("~$"):
            return False
        yok_sayilanlar = {".tmp", ".temp", ".ini", ".db", ".crdownload"}
        _, uzanti = os.path.splitext(dosya_adi)
        return uzanti.lower() not in yok_sayilanlar

    def _log_yaz(self, eylem, dosya_yolu):
        pid,exe_name = self._pid_bul(dosya_yolu)
        dosya_adi= os.path.basename(dosya_yolu)

        pid_str = f"PID: {pid}" if pid else "PID: -"
        print(f"{eylem}: {dosya_adi} | {pid_str} | Process: {exe_name}")
    

    def on_created(self, event):
        if not event.is_directory and self._dosya_gecerli_mi(event.src_path):
            self._log_yaz("Yeni dosya olusturuldu", event.src_path)

    def on_deleted(self,event):
        if not event.is_directory and self._dosya_gecerli_mi(event.src_path):
            self._log_yaz("Dosya silindi", event.src_path)
        
    def on_modified(self,event):
        if not event.is_directory and self._dosya_gecerli_mi(event.src_path):
            self._log_yaz("Dosya degistirildi", event.src_path)   

    def on_moved(self,event):
        if not event.is_directory and self._dosya_gecerli_mi(event.src_path):
            eski_ad= os.path.basename(event.src_path)
            yeni_ad = os.path.basename(event.dest_path)
            self._log_yaz(f"Dosya tasindi: {eski_ad} -> {yeni_ad}", event.dest_path)

def monitoring(dizin_yolu="."):
    if not os.path.exists(dizin_yolu):
        print(f"{dizin_yolu} bulunamadi. ")
        return

    event_handler = KlasorIzleyici()
    observer = Observer()

    observer.schedule(event_handler,path=dizin_yolu, recursive=False)
    observer.start()

    print(f"Izlenen dizin {os.path.abspath(dizin_yolu)}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("Izleme sonlandirildi.")

    observer.join()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        IZLENECEK_KLASOR = sys.argv[1]
    else:
        IZLENECEK_KLASOR = "."

    monitoring(IZLENECEK_KLASOR)