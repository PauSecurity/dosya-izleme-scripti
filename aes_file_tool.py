"""
Tek dosya AES-256-GCM sifreleme/desifreleme egitim araci.

Amac: AES'in mekanigini (anahtar, nonce/IV, authentication tag) ve
sifreleme sirasinda dosyada NELERIN DEGISTIGINI (boyut, entropi, header/magic
byte kaybi) gozlemlemek. Anahtar SENDE kalir, dosya sadece SENIN elinle,
SENIN belirledigin tek bir hedefte islenir - otomatik/topluca degil.

AES-GCM kullanimimizin sebebi: hem gizlilik (encryption) hem de butunluk/
kimlik dogrulama (authentication tag) sagliyor - dosya bozulursa ya da
yanlis anahtarla acilmaya calisilirsa desifreleme SESSIZCE degil, HATA
vererek basarisiz olur. Bu "authenticated encryption" kavramini gormek icin
iyi bir ornek.

Kurulum:
    pip install cryptography

Kullanim:
    # Sifrele (yeni bir anahtar uretir ve ekrana yazdirir - SAKLA!)
    python aes_file_tool.py encrypt onemli.xlsx

    # Var olan bir anahtarla sifrele
    python aes_file_tool.py encrypt onemli.xlsx --key <base64-anahtar>

    # Desifrele
    python aes_file_tool.py decrypt onemli.xlsx.enc --key <base64-anahtar>
"""

import argparse
import base64
import os
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


MAGIC = b"AESFILE1"  # basit bir format isareti: [MAGIC][12 byte nonce][ciphertext+tag]


def generate_key():
    return AESGCM.generate_key(bit_length=256)


def encrypt_file(path, key):
    with open(path, "rb") as f:
        plaintext = f.read()

    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # AES-GCM icin standart nonce boyutu
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    out_path = path + ".enc"
    with open(out_path, "wb") as f:
        f.write(MAGIC)
        f.write(nonce)
        f.write(ciphertext)

    return out_path, len(plaintext), len(ciphertext)


def decrypt_file(path, key):
    with open(path, "rb") as f:
        data = f.read()

    if not data.startswith(MAGIC):
        raise ValueError("Bu dosya bu araçla şifrelenmemiş (magic byte uyuşmuyor).")

    nonce = data[len(MAGIC):len(MAGIC) + 12]
    ciphertext = data[len(MAGIC) + 12:]

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)  # yanlis anahtar/bozuk veri -> InvalidTag hatasi

    if path.endswith(".enc"):
        out_path = path[: -len(".enc")]
    else:
        out_path = path + ".dec"

    with open(out_path, "wb") as f:
        f.write(plaintext)

    return out_path, len(plaintext)


def shannon_entropy(data, sample_size=4096):
    """Verinin ilk N byte'i uzerinden basit Shannon entropi hesabi (0-8 bit/byte arasi)."""
    import math
    sample = data[:sample_size]
    if not sample:
        return 0.0
    counts = [0] * 256
    for b in sample:
        counts[b] += 1
    entropy = 0.0
    length = len(sample)
    for c in counts:
        if c == 0:
            continue
        p = c / length
        entropy -= p * math.log2(p)
    return entropy


def main():
    parser = argparse.ArgumentParser(description="Tek dosya AES-256-GCM sifreleme/desifreleme egitim araci.")
    parser.add_argument("mode", choices=["encrypt", "decrypt"])
    parser.add_argument("path", help="Islenecek dosyanin yolu")
    parser.add_argument("--key", help="Base64 AES anahtari (verilmezse 'encrypt' modunda yeni anahtar uretilir)")
    args = parser.parse_args()

    if not os.path.isfile(args.path):
        print(f"[!] Dosya bulunamadi: {args.path}")
        sys.exit(1)

    with open(args.path, "rb") as f:
        original_bytes = f.read()
    entropy_before = shannon_entropy(original_bytes)

    if args.mode == "encrypt":
        key = base64.b64decode(args.key) if args.key else generate_key()

        out_path, plain_len, cipher_len = encrypt_file(args.path, key)

        with open(out_path, "rb") as f:
            encrypted_bytes = f.read()
        entropy_after = shannon_entropy(encrypted_bytes)

        print("=" * 60)
        print(f"  Girdi dosyasi     : {args.path}  ({plain_len} byte)")
        print(f"  Cikti dosyasi     : {out_path}  ({len(encrypted_bytes)} byte)")
        print(f"  Entropi ONCESI    : {entropy_before:.2f} bit/byte  (max 8.0)")
        print(f"  Entropi SONRASI   : {entropy_after:.2f} bit/byte  (max 8.0)")
        print(f"  AES Anahtari (SAKLA, deşifrelemek icin lazim):")
        print(f"  {base64.b64encode(key).decode()}")
        print("=" * 60)
        print("[GÜVENLİK NOTU] Bu araç EĞİTİM amaçlı olduğu için anahtarı bilerek")
        print("  ekrana/konsola yazdırıyor. GERÇEK sistemlerde şifreleme anahtarlarının")
        print("  loglara, konsola veya düz metin olarak herhangi bir yere yazılması")
        print("  ciddi bir güvenlik zafiyetidir (anahtar, HSM/KMS gibi ayrı bir")
        print("  güvenli depoda tutulmalı, asla log/stdout'a çıkmamalıdır).")
        print("=" * 60)
        print("[i] Orijinal dosya SILINMEDI, iki kopya da diskte duruyor.")
        print("[i] FIM/ETW aracin, .enc dosyasinin OLUSTURULDUGUNU/YAZILDIGINI ve")
        print("    entropisinin nasil sicradigini yakalamali.")

    else:  # decrypt
        if not args.key:
            print("[!] decrypt modu icin --key zorunlu.")
            sys.exit(1)
        key = base64.b64decode(args.key)

        try:
            out_path, plain_len = decrypt_file(args.path, key)
        except Exception as e:
            print(f"[!] Desifreleme basarisiz (yanlis anahtar ya da bozuk dosya): {e}")
            sys.exit(1)

        print("=" * 60)
        print(f"  Şifreli dosya : {args.path}")
        print(f"  Çözülen dosya : {out_path}  ({plain_len} byte)")
        print("  [✔] Doğrulama başarılı (AES-GCM authentication tag geçerli).")
        print("=" * 60)


if __name__ == "__main__":
    main()