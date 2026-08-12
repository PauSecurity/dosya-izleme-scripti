"""
FIM Tespit Sistemi - Sistematik Test Paketi

Amac: fim_etw_classic.py'nin bes katmaninin (canary, davranissal, discovery,
defense evasion, entropi) hem YANLIS POZITIF URETMEDIGINI (normal kullanici
davranisinda) hem DE GERCEKTEN ALGILADIGINI (supheli davranis simulasyonunda)
tek bir kosuda, etiketli senaryolarla dogrulamak.

Kullanim:
    1) Bir terminalde fim_etw_classic.py'yi (Yonetici olarak) baslat.
    2) Ayri bir terminalde bu scripti calistir:  python test_detection_suite.py
    3) Her senaryo basladiginda ne BEKLEDIGIMIZI ekrana yazar, birkaç saniye
       bekler (islemi yapar), sonra bir sonrakine gecer.
    4) fim_etw_classic.py'nin terminaline bakip her senaryo icin GERCEKTE ne
       oldugunu (alarm cikti mi, cikmadi mi) senaryonun BEKLENTI'siyle
       karsilastir. Sonunda ekrana basilan kontrol listesini doldur.

NOT: Butun senaryolar KASITLI OLARAK ZARARSIZDIR - gercek sifreleme,
gercek shadow copy silme, gercek zarar YOKTUR. Sadece davranis desenleri
taklit edilir (bkz. her senaryonun aciklamasi).
"""

import os
import subprocess
import sys
import time

WATCH_DIR = r"C:\FileMonitoring"
CANARY_FILENAME = "onemli.xlsx"  # fim_etw_classic.py'deki CANARY_FILENAMES ile ayni olmali


def banner(title):
    print("\n" + "=" * 78)
    print(f"  {title}")
    print("=" * 78)


def wait(seconds, reason):
    print(f"  [i] {reason} ({seconds} sn bekleniyor)...")
    time.sleep(seconds)


def cleanup():
    if os.path.isdir(WATCH_DIR):
        for name in os.listdir(WATCH_DIR):
            path = os.path.join(WATCH_DIR, name)
            try:
                if os.path.isdir(path):
                    for root, dirs, files in os.walk(path, topdown=False):
                        for f in files:
                            os.remove(os.path.join(root, f))
                        for d in dirs:
                            os.rmdir(os.path.join(root, d))
                    os.rmdir(path)
                else:
                    os.remove(path)
            except OSError:
                pass
    os.makedirs(WATCH_DIR, exist_ok=True)


# ==============================================================================
# BENIGN (ZARARSIZ / NORMAL KULLANICI) SENARYOLARI - ALARM BEKLENMIYOR
# ==============================================================================

def benign_normal_editing():
    """Normal bir kullanicinin dosya duzenleme hizini taklit eder: birkac
    dosyayi, ARALIKLI (insan hizinda) olarak olusturur/degistirir."""
    for i in range(3):
        path = os.path.join(WATCH_DIR, f"belge_{i}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"Normal kullanici notu #{i}\n")
        print(f"  [+] {os.path.basename(path)} olusturuldu (insan hizinda)")
        time.sleep(1.5)  # gercek bir kullanicinin dosyalar arasi gecis hizi


def benign_slow_browsing():
    """Kullanicinin birkac klasoru YAVASCA (esigin cok altinda) gezmesini
    taklit eder - DIRENUM esigi 5 saniyede 20 (guvenilmeyen process icin);
    burada 5 klasoru 5 saniyeye yayarak esigin cok altinda kaliyoruz."""
    for i in range(5):
        folder = os.path.join(WATCH_DIR, f"proje_{i}")
        os.makedirs(folder, exist_ok=True)
        list(os.scandir(folder))
        print(f"  [+] proje_{i} klasoru gezildi (yavas tempo)")
        time.sleep(1.0)


def benign_harmless_command():
    """Shadow Copy/yedek silme ile HICBIR ilgisi olmayan, tamamen zararsiz
    bir PowerShell komutu calistirir - Defense Evasion katmani icin
    yanlis pozitif kontrolu."""
    print("  [+] Zararsiz komut calistiriliyor: Get-Date")
    subprocess.run(["powershell", "-Command", "Get-Date"], capture_output=True)


def benign_normal_rename():
    """SUPHELI OLMAYAN bir uzantiya (SUSPICIOUS_RENAME_EXTENSIONS listesinde
    olmayan) normal bir yeniden adlandirma yapar."""
    src = os.path.join(WATCH_DIR, "taslak.txt")
    dst = os.path.join(WATCH_DIR, "taslak_final.txt")
    with open(src, "w", encoding="utf-8") as f:
        f.write("taslak icerik\n")
    time.sleep(0.5)
    os.rename(src, dst)
    print(f"  [+] taslak.txt -> taslak_final.txt (supheli olmayan uzanti)")


# ==============================================================================
# MALICIOUS-PATTERN (SUPHELI DAVRANIS DESENI) SENARYOLARI - ALARM BEKLENIYOR
# ==============================================================================
# Hepsi ZARARSIZDIR: gercek sifreleme/gercek silme YOKTUR, sadece davranis
# HIZI ve DESENI taklit edilir.

def malicious_canary_touch():
    """Canary (tuzak) dosyaya, ransomware'in yapacagi gibi rename ile dokunur."""
    path = os.path.join(WATCH_DIR, CANARY_FILENAME)
    with open(path, "w", encoding="utf-8") as f:
        f.write("tuzak dosya icerigi\n")
    time.sleep(0.5)
    os.rename(path, path + ".locked")
    print(f"  [+] {CANARY_FILENAME} -> {CANARY_FILENAME}.locked (canary dokunuldu)")


def malicious_rapid_rename():
    """DEFAULT (BILINMEYEN itibar) esigi (30) UZERINDE, KISA surede coktan-
    COGA rename - gercek sifreleme YOK, sadece hiz/desen taklit ediliyor.
    NOT: Bu test scripti python.exe'den calistigi icin itibar BILINMEYEN'dir
    (LOLBIN degil), bu yuzden dusurulmus esik (10) degil VARSAYILAN esik (30)
    gecerlidir - sayimizi buna gore ayarliyoruz."""
    files = []
    for i in range(35):
        path = os.path.join(WATCH_DIR, f"hizli_{i}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write("icerik\n")
        files.append(path)
    for path in files:
        os.rename(path, path + ".locked")
    print(f"  [+] {len(files)} dosya kisa surede '.locked' uzantisina cevrildi")


def malicious_rapid_direnum():
    """Discovery esigi (20, artik itibar farki yok) UZERINDE, KISA surede
    cok sayida klasor listeleme."""
    for i in range(25):
        folder = os.path.join(WATCH_DIR, f"kesif_{i}")
        os.makedirs(folder, exist_ok=True)
        list(os.scandir(folder))
    print("  [+] 25 klasor hizlica listelendi")


def malicious_vssadmin():
    """vssadmin'i cagirir - SADECE 'list' (hicbir sey SILMEZ), ama komut
    satirinda 'vssadmin' gectigi icin Defense Evasion anahtar kelime
    taramasini tetiklemesi beklenir."""
    print("  [+] 'vssadmin list shadows' calistiriliyor (SADECE listeler, SILMEZ)")
    subprocess.run(["vssadmin", "list", "shadows"], capture_output=True)


# ==============================================================================
# ANA KOSU
# ==============================================================================

SCENARIOS = [
    ("BENIGN-1", "Normal dosya oluşturma/düzenleme (insan hızında)", "ALARM YOK", benign_normal_editing),
    ("BENIGN-2", "Yavaş klasör gezinme (eşiğin altında)", "ALARM YOK", benign_slow_browsing),
    ("BENIGN-3", "Zararsız PowerShell komutu (Get-Date)", "ALARM YOK", benign_harmless_command),
    ("BENIGN-4", "Normal dosya yeniden adlandırma (şüpheli olmayan uzantı)", "ALARM YOK", benign_normal_rename),
    ("MALICIOUS-1", "Canary dosyaya dokunma", "🚨 CANARY ALARM", malicious_canary_touch),
    ("MALICIOUS-2", "Hızlı toplu rename (.locked, 35 dosya)", "🚨 RANSOMWARE ŞÜPHESİ ALARM", malicious_rapid_rename),
    ("MALICIOUS-3", "Hızlı klasör keşfi (25 klasör)", "⚠️ ERKEN UYARI - KEŞİF", malicious_rapid_direnum),
    ("MALICIOUS-4", "vssadmin list shadows (sadece listeler)", "🚨 DEFENSE EVASION ALARM", malicious_vssadmin),
]


def main():
    print("=" * 78)
    print("  FIM TESPİT SİSTEMİ - SİSTEMATİK TEST PAKETİ")
    print(f"  İzlenen klasör: {WATCH_DIR}")
    print("  fim_etw_classic.py'nin AYRI bir terminalde ÇALIŞIYOR olduğundan emin ol!")
    print("=" * 78)
    input("\n  Hazır olduğunda ENTER'a bas...")

    cleanup()
    wait(6, "cleanup() sonrası tespit pencerelerinin (5 sn) tamamen boşalması için ekstra bekleniyor")

    for code, description, expectation, func in SCENARIOS:
        banner(f"{code}: {description}\n  BEKLENTİ: {expectation}")
        func()
        wait(6, "sonuçları gözlemle + bir sonraki senaryo öncesi pencerenin boşalması")

    banner("TEST PAKETİ TAMAMLANDI")
    print("  Aşağıdaki kontrol listesini fim_etw_classic.py çıktısına bakarak doldur:\n")
    for code, description, expectation, _ in SCENARIOS:
        print(f"  [ ] {code:<12} {description:<55} Beklenti: {expectation}")
    print("\n  Her BENIGN senaryoda alarm ÇIKMAMALI, her MALICIOUS senaryoda ÇIKMALI.")
    print("  Uyuşmayan bir senaryo varsa (yanlış pozitif ya da kaçırılan tespit),")
    print("  ilgili eşiği/mantığı ayarlamamız gerekiyor demektir.")


if __name__ == "__main__":
    main()