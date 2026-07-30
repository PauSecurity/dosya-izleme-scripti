"""
Belirli bir dizinde N adet test dosyasi olusturan basit script.

Kullanim:
    python create_files.py C:\FileMonitoring
    python create_files.py C:\FileMonitoring --count 1000
    python create_files.py C:\FileMonitoring --count 1000 --delay 0.01
"""

import argparse
import os
import sys
import time


def main():
    parser = argparse.ArgumentParser(description="Belirli bir dizinde N adet test dosyasi olusturur.")
    parser.add_argument("directory", help="Dosyalarin olusturulacagi dizin")
    parser.add_argument("--count", type=int, default=1000, help="Olusturulacak dosya sayisi (varsayilan: 1000)")
    parser.add_argument("--delay", type=float, default=0.0, help="Her dosya arasinda bekleme suresi (saniye, varsayilan: 0)")
    args = parser.parse_args()

    os.makedirs(args.directory, exist_ok=True)

    print(f"[+] {args.count} dosya olusturuluyor: {args.directory}")
    start = time.perf_counter()

    created = 0
    errors = 0
    for i in range(args.count):
        path = os.path.join(args.directory, f"test_dosya_{i:05d}.txt")
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"Test dosyasi #{i}\n")
            created += 1
        except OSError as e:
            errors += 1
            print(f"[!] Olusturulamadi: {path} -> {e}")

        if args.delay > 0:
            time.sleep(args.delay)

    elapsed = time.perf_counter() - start

    print("=" * 60)
    print(f"  Olusturulan dosya sayisi : {created}")
    print(f"  Hata sayisi              : {errors}")
    print(f"  Toplam sure              : {elapsed:.3f} sn")
    if elapsed > 0:
        print(f"  Ortalama hiz             : {created / elapsed:.1f} dosya/sn")
    print("=" * 60)


if __name__ == "__main__":
    main()