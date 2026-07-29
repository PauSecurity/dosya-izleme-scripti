import os
import time
import sys
from datetime import datetime

WATCH_DIR = r"C:\FileMonitoring"
POLL_INTERVAL_SECONDS = 0.5

EXCLUDE_KEYWORDS = [
    "\\.git\\",
    "\\__pycache__\\",
    ".tmp",
]


def is_excluded(path):
    lower = path.lower()
    return any(kw.lower() in lower for kw in EXCLUDE_KEYWORDS)


def human_size(num_bytes):
    for unit in ("B", "KB", "MB", "GB"):
        if num_bytes < 1024:
            return f"{num_bytes:.0f} {unit}" if unit == "B" else f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f} TB"


def relative(path):
    try:
        return os.path.relpath(path, WATCH_DIR)
    except ValueError:
        return path


def now_str():
    return datetime.now().strftime("%H:%M:%S")


def snapshot_dir(path):
    snap = {}
    try:
        for root, dirs, files in os.walk(path):
            for name in files:
                full = os.path.join(root, name)
                if is_excluded(full):
                    continue
                try:
                    st = os.stat(full)
                    snap[full] = (st.st_size, st.st_mtime)
                except OSError:
                    pass
    except OSError:
        pass
    return snap


def log(icon, label, text):
    print(f"[{now_str()}] {icon}  {label:<18} {text}", flush=True)


def run():
    if not os.path.isdir(WATCH_DIR):
        try:
            os.makedirs(WATCH_DIR, exist_ok=True)
        except OSError as e:
            print(f"[!] {WATCH_DIR} olusturulamadi: {e}")
            sys.exit(1)

    print("=" * 78)
    print("  DOSYA BÜTÜNLÜĞÜ İZLEME (FIM) — sade ve okunabilir mod")
    print(f"  İzlenen klasör : {WATCH_DIR}  (alt klasörler dahil)")
    print(f"  Tarama sıklığı : {POLL_INTERVAL_SECONDS} sn")
    if EXCLUDE_KEYWORDS:
        print(f"  Yok sayılanlar : {', '.join(EXCLUDE_KEYWORDS)}")
    print("  Çıkış: Ctrl+C")

    previous = snapshot_dir(WATCH_DIR)

    try:
        while True:
            time.sleep(POLL_INTERVAL_SECONDS)
            current = snapshot_dir(WATCH_DIR)

            added = [p for p in current if p not in previous]
            removed = [p for p in previous if p not in current]
            modified = [p for p in current if p in previous and current[p] != previous[p]]

            if len(added) == 1 and len(removed) == 1:
                old_path, new_path = removed[0], added[0]
                if previous[old_path][0] == current[new_path][0]:
                    log("↦", "YENİDEN ADLANDIRILDI", f"{relative(old_path)}  →  {relative(new_path)}")
                    previous = current
                    continue

            for p in added:
                size = current[p][0]
                log("✚", "OLUŞTURULDU", f"{relative(p)}  ({human_size(size)})")

            for p in removed:
                log("✖", "SİLİNDİ", relative(p))

            for p in modified:
                old_size = previous[p][0]
                new_size = current[p][0]
                size_note = f"{human_size(old_size)} → {human_size(new_size)}" if old_size != new_size else human_size(new_size)
                log("✎", "İÇERİK DEĞİŞTİ", f"{relative(p)}  ({size_note})")

            previous = current

    except KeyboardInterrupt:
        print("\n Durduruldu.")


if __name__ == "__main__":
    run()