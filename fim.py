import sys
import time
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class KlasorIzleyici(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            print(f" Yeni dosya olusturuldu. {os.path.basename(event.src_path)}")

    def on_deleted(self,event):
        if not event.is_directory:
            print(f" Dosya silindi. {os.path.basename(event.src_path)}")

    def on_modified(self,event):
        if not event.is_directory:
            print(f" Dosya degistirildi. {os.path.basename(event.src_path)}")

    def on_moved(self,event):
        if not event.is_directory:
            eski_ad= os.path.basename(event.src_path)
            yeni_ad = os.path.basename(event.dest_path)
            print(f" Dosya tasindi/yeniden adlandirildi. {eski_ad} => {yeni_ad}")

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