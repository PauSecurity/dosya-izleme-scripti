"""
Herhangi bir dosyanin (veya bir klasordeki tum dosyalarin) Shannon entropisini
olcen, BAGIMSIZ bir yardimci arac. Sifreleme YAPMAZ, sadece OLCER.

Amac: fim_polling.py'deki entropi tabanli tespit katmaninin (ENTROPY_HIGH_THRESHOLD)
gercek dunya dosyalariyla (docx, zip, jpg, mp4 vb.) YANLIS POZITIF uretip
uretmedigini olcmek. Bu formatlarin cogu zaten dogal olarak yuksek entropili
oldugu icin (ZIP/JPEG/MP4 sikistirma algoritmasi nedeniyle), tespit katmanimizin
"her yuksek entropi = ransomware" diye yanilip yanilmadigini gormemiz lazim.

Kullanim:
    python measure_entropy.py "C:\\yol\\dosya.docx"
    python measure_entropy.py "C:\\bir\\klasor" --recursive
"""

import argparse
import math
import os

ENTROPY_SAMPLE_BYTES = 4096
ENTROPY_HIGH_THRESHOLD = 7.5  # fim_polling.py ile ayni esik


def shannon_entropy(data):
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


def measure(path):
    try:
        with open(path, "rb") as f:
            sample = f.read(ENTROPY_SAMPLE_BYTES)
        return shannon_entropy(sample)
    except OSError as e:
        print(f"[!] Okunamadi: {path} -> {e}")
        return None


def main():
    parser = argparse.ArgumentParser(description="Dosya(lar)in entropisini olcer, sifreleme yapmaz.")
    parser.add_argument("path", help="Tek dosya ya da klasor yolu")
    parser.add_argument("--recursive", action="store_true", help="Klasor icin alt klasorleri de tara")
    args = parser.parse_args()

    targets = []
    if os.path.isfile(args.path):
        targets = [args.path]
    elif os.path.isdir(args.path):
        if args.recursive:
            for root, dirs, files in os.walk(args.path):
                for name in files:
                    targets.append(os.path.join(root, name))
        else:
            targets = [os.path.join(args.path, n) for n in os.listdir(args.path)
                       if os.path.isfile(os.path.join(args.path, n))]
    else:
        print(f"[!] Bulunamadi: {args.path}")
        return

    print("=" * 78)
    print(f"{'Dosya':<45} {'Entropi':>10}  {'Eşik Üstü mü?':>15}")
    print("-" * 78)

    false_positive_count = 0
    for path in targets:
        entropy = measure(path)
        if entropy is None:
            continue
        flag = "🚨 EVET (F.P.?)" if entropy >= ENTROPY_HIGH_THRESHOLD else "hayır"
        if entropy >= ENTROPY_HIGH_THRESHOLD:
            false_positive_count += 1
        name = os.path.basename(path)
        print(f"{name:<45} {entropy:>9.2f}  {flag:>15}")

    print("=" * 78)
    print(f"Toplam dosya: {len(targets)}  |  Eşik üstü (potansiyel yanlış pozitif): {false_positive_count}")
    print(f"Eşik: {ENTROPY_HIGH_THRESHOLD}/8.0 bit/byte")
    print("=" * 78)
    print("[i] Not: Bu araç sadece 'anlık yüksek entropi' katmanını izole test eder.")
    print("    fim_polling.py'de gerçek tespit hem yüksek entropi HEM ani sıçrama")
    print("    (ENTROPY_JUMP_THRESHOLD) gerektirir - bu yüzden zaten yüksek entropili")
    print("    olarak OLUŞTURULAN bir dosya (ör. bir .zip kopyalanması) için bile")
    print("    'sıçrama' şartı sağlanamayabilir. Ama YENİ oluşan dosyalarda sadece")
    print("    mutlak eşik kontrolü var (bkz. fim_polling.py 'added' bloğu) - o yüzden")
    print("    bu tablo, o spesifik durumun yanlış pozitif riskini gösteriyor.")


if __name__ == "__main__":
    main()