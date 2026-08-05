"""
Belirli bir dizinde N adet dosya oluşturup, içeriklerini topluca güncelleyen 
ve uzantılarını değiştirerek ETW/FIM tespit kurallarını test eden simülatör.

Kullanım:
    python ransomware_behavior_sim.py C:\TestLab --count 1000
"""

import argparse
import os
import sys
import time


def main():
    parser = argparse.ArgumentParser(description="FIM/ETW Anomali Tespit Test Script'i")
    parser.add_argument("directory", help="Dosyaların işleneceği dizin")
    parser.add_argument("--count", type=int, default=1000, help="Dosya sayısı (varsayılan: 1000)")
    parser.add_argument("--delay", type=float, default=0.0, help="İşlemler arası bekleme (varsayılan: 0)")
    args = parser.parse_args()

    os.makedirs(args.directory, exist_ok=True)

    print(f"============================================================")
    print(f"  ETW / FIM ANOMALİ DETEKTÖRÜ TEST SİMÜLASYONU")
    print(f"  Hedef Dizin: {args.directory}")
    print(f"  Dosya Sayısı: {args.count}")
    print(f"============================================================\n")

    # ------------------------------------------------------------------
    # AŞAMA 1: TOPLU DOSYA OLUŞTURMA (CREATE / WRITE)
    # ------------------------------------------------------------------
    print(f"[1/3] {args.count} adet test dosyası oluşturuluyor...")
    start_create = time.perf_counter()
    created_files = []

    for i in range(args.count):
        path = os.path.join(args.directory, f"dokuman_{i:05d}.docx")
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"Orijinal Belge İçeriği #{i}\n")
            created_files.append(path)
        except OSError as e:
            print(f"[!] Oluşturulamadı: {path} -> {e}")

        if args.delay > 0:
            time.sleep(args.delay)

    elapsed_create = time.perf_counter() - start_create
    print(f"[✔] Oluşturma Tamamlandı: {len(created_files)} dosya ({elapsed_create:.2f} sn)")

    print("\n[!] 2 saniye bekleniyor (ETW Buffer boşalması için)...")
    time.sleep(2)

    # ------------------------------------------------------------------
    # AŞAMA 2: HIZLI İÇERİK DEĞİŞTİRME VE UZANTI DEĞİŞTİRME (RENAME)
    # ------------------------------------------------------------------
    print(f"\n[2/3] Dosya içerikleri değiştiriliyor ve uzantılar dönüştürülüyor (.locked)...")
    start_rename = time.perf_counter()
    renamed_count = 0

    for path in created_files:
        try:
            # 1. İçeriği güncelle (WRITE)
            with open(path, "a", encoding="utf-8") as f:
                f.write("[BOZULMUŞ / ŞİFRELENMİŞ VERİ BLOKLARI]\n")

            # 2. Uzantıyı değiştir (RENAME) -> Anomali Tetikleyici
            new_path = path + ".locked"
            os.rename(path, new_path)
            renamed_count += 1

        except OSError as e:
            print(f"[!] Dönüştürülemedi: {path} -> {e}")

        if args.delay > 0:
            time.sleep(args.delay)

    elapsed_rename = time.perf_counter() - start_rename
    print(f"[✔] Dönüştürme Tamamlandı: {renamed_count} dosya ({elapsed_rename:.2f} sn)")

    # ------------------------------------------------------------------
    # AŞAMA 3: FİDYE NOTU BIRAKMA (DROP NOTE)
    # ------------------------------------------------------------------
    print(f"\n[3/3] Dizin içerisine sahte fidye notu bırakılıyor...")
    note_path = os.path.join(args.directory, "BENI_OKU_RECOVER.txt")
    with open(note_path, "w", encoding="utf-8") as f:
        f.write("TÜM DOSYALARINIZ TEST AMACIYLA DEĞİŞTİRİLMİŞTİR.\nETW ALARMI TETİKLENMELİDİR.")

    print("\n" + "=" * 60)
    print(f"  İşlem Hızı      : {renamed_count / elapsed_rename:.1f} dosya/sn (RENAME)")
    print(f"  Toplam Süre     : {elapsed_create + elapsed_rename:.2f} sn")
    print("=" * 60)
    print(" [✔] Test bitti! ETW İzleyicindeki log ve alarm durumunu kontrol et.")


if __name__ == "__main__":
    main()