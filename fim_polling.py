"""
Basit, saglam ve okunabilir Dosya Bütünlüğü İzleme (FIM) aracı.

Neden ETW yerine polling?
- Kernel ETW event semasi Windows build'den build'e degisiyor (bu sistemde
  beklenen SetDelete/Rename event'leri farkli/tutarsiz davraniyordu).
- Explorer, VSCode, Git extension'lari gibi arka plan surecleri surekli
  dosya "acma" (Open/Create) event'i uretiyor - bunlar gercek bir degisiklik
  degil, sadece "goz atma". ETW bu ikisini ayirt etmek icin cok gurultulu.
- Polling (klasoru periyodik tarayip onceki durumla kiyaslamak) ise SADECE
  gercekten degisen (olusturulan/silinen/yeniden adlandirilan/icerigi
  degisen) dosyalari yakalar. Yonetici (admin) hakki bile gerektirmez.

Kullanim: python fim_polling.py
Çıkış: Ctrl+C
"""

import os
import time
import sys
import math
from datetime import datetime

# ==============================================================================
# AYARLAR
# ==============================================================================
WATCH_DIR = r"C:\FileMonitoring"
POLL_INTERVAL_SECONDS = 0.5

# Bu klasor/dosya adi kaliplarini iceren yollari GORMEZDEN GEL.
# Ornegin bir git deposu iceriyorsa, .git klasorunun ic gurultusunu
# (indexler, objeler) disarida tutmak icin varsayilan olarak eklendi.
# Kendi degisikliklerinizi de gormek isterseniz bu listeyi bosaltabilirsiniz.
EXCLUDE_KEYWORDS = [
    "\\.git\\",
    "\\__pycache__\\",
    ".tmp",
]

# ------------------------------------------------------------------------
# ENTROPİ TABANLI ANOMALİ TESPİTİ
# ------------------------------------------------------------------------
# Mantık: sifrelenmis/rastgele veri, duz metin/ofis belgesi gibi yapilandirilmis
# veriden cok daha yuksek Shannon entropisine sahiptir (rastgele veri ~8.0
# bit/byte'a yaklasir, normal metin/belge tipik olarak 3-6 civarindadir).
# Bir dosyanin entropisi ANİDEN bu esigin uzerine sicrarsa (ozellikle onceki
# degerine gore buyuk bir sicrama varsa), icerigi sifrelenmis/rastgelestirilmis
# olabilecegini gosteren guclu bir sinyaldir.
ENTROPY_SAMPLE_BYTES = 4096      # Performans icin dosyanin sadece ilk N byte'ina bakilir
ENTROPY_HIGH_THRESHOLD = 7.5     # Bu degerin uzerindeki entropi "supheli yuksek" sayilir
ENTROPY_JUMP_THRESHOLD = 2.0     # Onceki olcume gore bu kadar (bit/byte) artis "ani sicrama" sayilir

# path -> son olculen entropi degeri (bir sonraki olcumle kiyaslamak icin)
_entropy_cache = {}


def shannon_entropy(data):
    """0.0 (tamamen tekduze) ile 8.0 (tamamen rastgele) arasinda Shannon entropisi."""
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


def read_entropy(path):
    try:
        with open(path, "rb") as f:
            sample = f.read(ENTROPY_SAMPLE_BYTES)
        return shannon_entropy(sample)
    except OSError:
        return None


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
    """path altindaki (alt klasorler dahil) tum dosyalarin {yol: (boyut, mtime)} halini dondurur."""
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
    print(f"  Entropi eşiği  : {ENTROPY_HIGH_THRESHOLD}/8.0 bit/byte (sıçrama eşiği: {ENTROPY_JUMP_THRESHOLD})")
    if EXCLUDE_KEYWORDS:
        print(f"  Yok sayılanlar : {', '.join(EXCLUDE_KEYWORDS)}")
    print("  Çıkış: Ctrl+C")
    print("=" * 78 + "\n")

    previous = snapshot_dir(WATCH_DIR)
    for p in previous:
        entropy = read_entropy(p)
        if entropy is not None:
            _entropy_cache[p] = entropy

    try:
        while True:
            time.sleep(POLL_INTERVAL_SECONDS)
            current = snapshot_dir(WATCH_DIR)

            added = [p for p in current if p not in previous]
            removed = [p for p in previous if p not in current]
            modified = [p for p in current if p in previous and current[p] != previous[p]]

            # Ayni anda 1 dosya kaybolup, ayni boyutta 1 yeni dosya belirdiyse -> rename
            if len(added) == 1 and len(removed) == 1:
                old_path, new_path = removed[0], added[0]
                if previous[old_path][0] == current[new_path][0]:
                    log("↦", "YENİDEN ADLANDIRILDI", f"{relative(old_path)}  →  {relative(new_path)}")
                    previous = current
                    continue

            for p in added:
                size = current[p][0]
                log("✚", "OLUŞTURULDU", f"{relative(p)}  ({human_size(size)})")
                entropy = read_entropy(p)
                if entropy is not None:
                    _entropy_cache[p] = entropy
                    if entropy >= ENTROPY_HIGH_THRESHOLD:
                        log("🚨", "YÜKSEK ENTROPİ", f"{relative(p)}  (entropi: {entropy:.2f}/8.0 — şifrelenmiş/rastgele veri olabilir!)")

            for p in removed:
                log("✖", "SİLİNDİ", relative(p))
                _entropy_cache.pop(p, None)

            for p in modified:
                old_size = previous[p][0]
                new_size = current[p][0]
                size_note = f"{human_size(old_size)} → {human_size(new_size)}" if old_size != new_size else human_size(new_size)
                log("✎", "İÇERİK DEĞİŞTİ", f"{relative(p)}  ({size_note})")

                entropy_after = read_entropy(p)
                if entropy_after is not None:
                    entropy_before = _entropy_cache.get(p)
                    _entropy_cache[p] = entropy_after
                    if entropy_before is not None:
                        jump = entropy_after - entropy_before
                        if entropy_after >= ENTROPY_HIGH_THRESHOLD and jump >= ENTROPY_JUMP_THRESHOLD:
                            log("🚨", "ENTROPİ ALARMI", f"{relative(p)}  ({entropy_before:.2f} → {entropy_after:.2f} bit/byte — muhtemel şifreleme!)")

            previous = current

    except KeyboardInterrupt:
        print("\n[-] Durduruldu.")


if __name__ == "__main__":
    run()