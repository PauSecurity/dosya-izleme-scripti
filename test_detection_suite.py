"""
FIM Tespit Sistemi - Sistematik Test Paketi + OTOMATIK RAPOR

Amac: fim_etw_classic.py'nin tespit katmanlarinin (canary, davranissal,
discovery/korelasyon, defense evasion, privilege escalation) hem YANLIS
POZITIF URETMEDIGINI (normal kullanici davranisinda) hem DE GERCEKTEN
ALGILADIGINI (supheli davranis simulasyonunda) OTOMATIK olarak dogrulamak.

Nasil calisir:
    1) Bir terminalde fim_etw_classic.py'yi (Yonetici olarak) baslat.
       (Bu, ayni klasorde 'alerts_log.jsonl' dosyasini olusturup her
       alarmi oraya da kaydeder.)
    2) Ayri bir terminalde bu scripti calistir: python test_detection_suite.py
    3) Her senaryonun BASLANGIC ve BITIS zaman damgasini kaydeder.
    4) Test paketi bitince 'alerts_log.jsonl' dosyasini okur, her senaryonun
       zaman penceresine hangi alarmlarin dustugunu bulur, BEKLENTI ile
       GERCEKLESEN'i karsilastirip OTOMATIK bir PASS/FAIL raporu (hem
       konsola hem 'test_report.md' dosyasina) yazar.

NOT: Butun senaryolar KASITLI OLARAK ZARARSIZDIR - gercek sifreleme,
gercek shadow copy silme, gercek yetki yukseltme YOKTUR. Sadece davranis
DESENLERI/komut satirlari taklit edilir (bkz. her senaryonun aciklamasi).
"""

import json
import os
import subprocess
import sys
import time

WATCH_DIR = r"C:\FileMonitoring"
CANARY_FILENAME = "onemli.xlsx"       # fim_etw_classic.py'deki CANARY_FILENAMES ile ayni olmali
ALERT_LOG_PATH = "alerts_log.jsonl"   # fim_etw_classic.py ile AYNI klasorde calistirilmali
REPORT_PATH = "test_report.md"
CORRELATION_END_BUFFER_SECONDS = 3.0  # senaryo bitince alarmin gelmesi icin ekstra pay


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
    """Normal bir kullanicinin dosya duzenleme hizini taklit eder."""
    for i in range(3):
        path = os.path.join(WATCH_DIR, f"belge_{i}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"Normal kullanici notu #{i}\n")
        print(f"  [+] {os.path.basename(path)} olusturuldu (insan hizinda)")
        time.sleep(1.5)


def benign_slow_browsing():
    """Kullanicinin birkac klasoru YAVASCA gezmesini taklit eder."""
    for i in range(5):
        folder = os.path.join(WATCH_DIR, f"proje_{i}")
        os.makedirs(folder, exist_ok=True)
        list(os.scandir(folder))
        print(f"  [+] proje_{i} klasoru gezildi (yavas tempo)")
        time.sleep(1.0)


def benign_harmless_command():
    """Defense Evasion/Privilege Escalation ile HICBIR ilgisi olmayan,
    tamamen zararsiz bir komut - false positive kontrolu icin."""
    print("  [+] Zararsiz komut calistiriliyor: whoami (parametresiz)")
    subprocess.run(["whoami"], capture_output=True)
    print("  [+] Zararsiz komut calistiriliyor: Get-Date")
    subprocess.run(["powershell", "-Command", "Get-Date"], capture_output=True)


def benign_normal_rename():
    """SUPHELI OLMAYAN bir uzantiya normal bir yeniden adlandirma yapar."""
    src = os.path.join(WATCH_DIR, "taslak.txt")
    dst = os.path.join(WATCH_DIR, "taslak_final.txt")
    with open(src, "w", encoding="utf-8") as f:
        f.write("taslak icerik\n")
    time.sleep(0.5)
    os.rename(src, dst)
    print("  [+] taslak.txt -> taslak_final.txt (supheli olmayan uzanti)")


# ==============================================================================
# MALICIOUS-PATTERN (SUPHELI DAVRANIS DESENI) SENARYOLARI - ALARM BEKLENIYOR
# ==============================================================================
# Hepsi ZARARSIZDIR: gercek sifreleme/gercek silme/gercek yetki yukseltme
# YOKTUR, sadece davranis HIZI ve KOMUT SATIRI deseni taklit edilir.

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
    COGA rename - gercek sifreleme YOK, sadece hiz/desen taklit ediliyor."""
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
    """Discovery esigi UZERINDE, KISA surede cok sayida klasor listeleme.
    NOT: Discovery artik STANDALONE alarm URETMEZ (bkz. fim_etw_classic.py) -
    bu senaryo sadece bir SONRAKI senaryoyu (Defense Evasion) 'YUKSEK GUVEN'
    ile guclendirmek icin baglam hazirlar. Bu yuzden otomatik raporda
    'ALARM YOK (beklenen)' olarak degerlendirilir, ayri bir basarisizlik
    sayilmaz."""
    for i in range(25):
        folder = os.path.join(WATCH_DIR, f"kesif_{i}")
        os.makedirs(folder, exist_ok=True)
        list(os.scandir(folder))
    print("  [+] 25 klasor hizlica listelendi (Defense Evasion'u guclendirmek icin baglam)")


def malicious_vssadmin_delete():
    """vssadmin delete shadows /all /quiet calistirir. Sistemde HICBIR
    shadow copy yoksa (cogu temiz VM'de boyle) bu komut TAMAMEN ZARARSIZDIR
    (silecek bir sey bulamaz) - ama komut satirinda 'vssadmin delete' aynen
    gectigi icin Defense Evasion tespitini test etmek icin yeterlidir."""
    print("  [+] 'vssadmin delete shadows /all /quiet' calistiriliyor")
    print("      (Sistemde shadow copy yoksa TAMAMEN ZARARSIZ - silecek bir sey yok)")
    subprocess.run(["vssadmin", "delete", "shadows", "/all", "/quiet"], capture_output=True)


def malicious_privesc_command():
    """Yetki yukseltme kesfinde kullanilan, KENDISI ZARARSIZ (hicbir sey
    degistirmez, sadece BILGI gosterir) bir komut calistirir."""
    print("  [+] 'whoami /priv' calistiriliyor (SADECE mevcut yetkileri LISTELER, degistirmez)")
    subprocess.run(["whoami", "/priv"], capture_output=True)


def benign_high_entropy_but_known_format():
    """Gercek bir ZIP dosyasi olusturur - ZIP dogal olarak yuksek entropili
    olsa da, BILINEN bir format oldugu icin 'akillica ayirma' mantigi
    (KNOWN_HIGH_ENTROPY_EXTENSIONS) bunu TAM ALARM degil, sessiz gozlem
    olarak degerlendirmeli - false positive testi."""
    import zipfile
    path = os.path.join(WATCH_DIR, "gercek_arsiv.zip")
    src = os.path.join(WATCH_DIR, "belge_0.txt")
    if not os.path.exists(src):
        with open(src, "w", encoding="utf-8") as f:
            f.write("icerik\n")
    with zipfile.ZipFile(path, "w") as zf:
        zf.write(src, arcname="belge.txt")
    print("  [+] gercek_arsiv.zip olusturuldu (dogal olarak yuksek entropili ama BILINEN format)")


def malicious_unknown_extension_high_entropy():
    """Bilinmeyen bir uzantiyla (.dat), rastgele/yuksek entropili bir dosya
    olusturur - ransomware'in yeni sifrelenmis dosya yaratmasini taklit
    eder (ama gercek AES sifreleme DEGIL, sadece os.urandom ile rastgele
    bayt - entropi katmanini test etmek icin yeterli, sifreleme degil)."""
    path = os.path.join(WATCH_DIR, "bilinmeyen_dosya.dat")
    with open(path, "wb") as f:
        f.write(os.urandom(8192))
    print("  [+] bilinmeyen_dosya.dat rastgele veriyle olusturuldu (bilinmeyen uzanti + yuksek entropi)")


# ==============================================================================
# SENARYO TANIMLARI: (kod, aciklama, beklenen_alert_type_listesi, fonksiyon)
# beklenen_alert_type_listesi bos ([]) ise "hicbir alarm gelmemeli" demektir.
# ==============================================================================

SCENARIOS = [
    ("BENIGN-1", "Normal dosya oluşturma/düzenleme (insan hızında)", [], benign_normal_editing),
    ("BENIGN-2", "Yavaş klasör gezinme (eşiğin altında)", [], benign_slow_browsing),
    ("BENIGN-3", "Zararsız komutlar (whoami, Get-Date)", [], benign_harmless_command),
    ("BENIGN-4", "Normal dosya yeniden adlandırma (şüpheli olmayan uzantı)", [], benign_normal_rename),
    ("BENIGN-5", "Gerçek ZIP oluşturma (doğal yüksek entropi, bilinen format)", [], benign_high_entropy_but_known_format),
    ("MALICIOUS-1", "Canary dosyaya dokunma", ["CANARY"], malicious_canary_touch),
    ("MALICIOUS-2", "Hızlı toplu rename (.locked, 35 dosya)", ["RANSOMWARE_BEHAVIOR"], malicious_rapid_rename),
    ("MALICIOUS-3", "Hızlı klasör keşfi (25 klasör, korelasyon bağlamı)", [], malicious_rapid_direnum),
    ("MALICIOUS-4", "vssadmin delete shadows (shadow copy yoksa zararsız)", ["DEFENSE_EVASION"], malicious_vssadmin_delete),
    ("MALICIOUS-5", "whoami /priv (sadece listeler, değiştirmez)", ["PRIVILEGE_ESCALATION"], malicious_privesc_command),
    ("MALICIOUS-6", "Bilinmeyen uzantı + yüksek entropi (.dat, rastgele veri)", ["ENTROPY"], malicious_unknown_extension_high_entropy),
]


WAIT_FOR_ALERT_TIMEOUT_SECONDS = 20.0   # MALICIOUS senaryo sonrasi beklenen alarmi bu kadar bekle
WAIT_FOR_ALERT_POLL_INTERVAL = 0.5
BENIGN_SETTLE_SECONDS = 5.0             # BENIGN senaryo sonrasi "hicbir alarm gelmedi" onayi icin bekleme


def read_alerts():
    if not os.path.exists(ALERT_LOG_PATH):
        return []
    alerts = []
    with open(ALERT_LOG_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return alerts


def wait_for_expected_alerts(start_ts, expected_types, timeout_seconds):
    """expected_types bos ise (BENIGN), sadece kisa bir 'sessizlik onayi'
    suresi bekler. Dolu ise (MALICIOUS), beklenen turlerin HEPSI gorulene
    KADAR ya da timeout'a kadar aktif olarak polling yapar - sabit bir
    zaman penceresine guvenmek yerine, gecikme ne olursa olsun dogru sonucu
    yakalar."""
    if not expected_types:
        time.sleep(BENIGN_SETTLE_SECONDS)
        end_ts = time.time()
        found = [a for a in read_alerts() if a["timestamp"] >= start_ts]
        return end_ts, sorted(set(a["alert_type"] for a in found))

    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        found = [a for a in read_alerts() if a["timestamp"] >= start_ts]
        found_types = set(a["alert_type"] for a in found)
        if all(t in found_types for t in expected_types):
            return time.time(), sorted(found_types)
        time.sleep(WAIT_FOR_ALERT_POLL_INTERVAL)

    # timeout - ne bulunduysa onu dondur (basarisiz sayilacak ama ne geldigini gorebiliriz)
    found = [a for a in read_alerts() if a["timestamp"] >= start_ts]
    return time.time(), sorted(set(a["alert_type"] for a in found))


def build_report(scenario_windows, all_alerts):
    """Her senaryonun zaman penceresine dusen alarmlari bulup PASS/FAIL belirler."""
    results = []
    for code, description, expected_types, start_ts, end_ts in scenario_windows:
        window_alerts = [
            a for a in all_alerts
            if start_ts <= a["timestamp"] <= end_ts + CORRELATION_END_BUFFER_SECONDS
        ]
        found_types = sorted(set(a["alert_type"] for a in window_alerts))

        if not expected_types:
            passed = len(found_types) == 0
            expectation_str = "ALARM YOK"
        else:
            passed = all(t in found_types for t in expected_types)
            expectation_str = " + ".join(expected_types)

        results.append({
            "code": code,
            "description": description,
            "expected": expectation_str,
            "found": ", ".join(found_types) if found_types else "(hiçbiri)",
            "passed": passed,
            "alert_count": len(window_alerts),
        })
    return results


def write_markdown_report(results):
    lines = []
    lines.append("# FIM Tespit Sistemi - Otomatik Test Raporu\n")
    lines.append(f"Oluşturulma zamanı: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    total = len(results)
    passed_count = sum(1 for r in results if r["passed"])
    lines.append(f"**Sonuç: {passed_count}/{total} senaryo beklendiği gibi çalıştı.**\n")
    lines.append("| Senaryo | Açıklama | Beklenen | Gerçekleşen | Durum |")
    lines.append("|---|---|---|---|---|")
    for r in results:
        status = "✅ PASS" if r["passed"] else "❌ FAIL"
        lines.append(f"| {r['code']} | {r['description']} | {r['expected']} | {r['found']} | {status} |")

    failed = [r for r in results if not r["passed"]]
    if failed:
        lines.append("\n## Başarısız Senaryolar - Analiz Gerekli\n")
        for r in failed:
            if r["expected"] == "ALARM YOK":
                lines.append(f"- **{r['code']}**: Beklenmedik alarm geldi ({r['found']}) -> muhtemel YANLIŞ POZİTİF, eşik/mantık gözden geçirilmeli.")
            else:
                lines.append(f"- **{r['code']}**: Beklenen alarm ({r['expected']}) gelmedi -> muhtemel KAÇIRILAN TESPİT, eşik/anahtar kelime gözden geçirilmeli.")
    else:
        lines.append("\n## Tüm senaryolar beklendiği gibi sonuçlandı.\n")

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def main():
    print("=" * 78)
    print("  FIM TESPİT SİSTEMİ - SİSTEMATİK TEST PAKETİ (OTOMATİK RAPORLU)")
    print(f"  İzlenen klasör : {WATCH_DIR}")
    print(f"  Alarm log      : {ALERT_LOG_PATH}  (fim_etw_classic.py ile AYNI klasörde olmalı)")
    print("  fim_etw_classic.py'nin AYRI bir terminalde ÇALIŞIYOR olduğundan emin ol!")
    print("=" * 78)
    input("\n  Hazır olduğunda ENTER'a bas...")

    cleanup()
    wait(6, "cleanup() sonrası tespit pencerelerinin tamamen boşalması için ekstra bekleniyor")

    scenario_windows = []
    for code, description, expected_types, func in SCENARIOS:
        banner(f"{code}: {description}\n  BEKLENTİ: {' + '.join(expected_types) if expected_types else 'ALARM YOK'}")
        start_ts = time.time()
        func()
        if expected_types:
            print(f"  [i] Beklenen alarm(lar) için en fazla {WAIT_FOR_ALERT_TIMEOUT_SECONDS:.0f} sn bekleniyor "
                  f"(gecikme olursa bile yakalanır)...")
        end_ts, found_types_preview = wait_for_expected_alerts(start_ts, expected_types, WAIT_FOR_ALERT_TIMEOUT_SECONDS)
        if expected_types:
            ok = all(t in found_types_preview for t in expected_types)
            print(f"  [{'✔' if ok else '✖'}] Bulunan: {found_types_preview if found_types_preview else '(hiçbiri)'}")
        scenario_windows.append((code, description, expected_types, start_ts, end_ts))

    banner("TEST PAKETİ TAMAMLANDI - RAPOR OLUŞTURULUYOR")

    all_alerts = read_alerts()
    print(f"  [i] '{ALERT_LOG_PATH}' dosyasından {len(all_alerts)} alarm kaydı okundu.")

    results = build_report(scenario_windows, all_alerts)
    write_markdown_report(results)

    print("\n  SONUÇ TABLOSU:\n")
    print(f"  {'Senaryo':<14}{'Beklenen':<24}{'Gerçekleşen':<24}{'Durum'}")
    print("  " + "-" * 74)
    for r in results:
        status = "✅ PASS" if r["passed"] else "❌ FAIL"
        print(f"  {r['code']:<14}{r['expected']:<24}{r['found']:<24}{status}")

    passed_count = sum(1 for r in results if r["passed"])
    print(f"\n  Toplam: {passed_count}/{len(results)} senaryo doğru sonuçlandı.")
    print(f"  Detaylı rapor: {os.path.abspath(REPORT_PATH)}")

    if all_alerts and not os.path.exists(ALERT_LOG_PATH):
        print("\n  [!] UYARI: alerts_log.jsonl bulunamadı - fim_etw_classic.py'yi bu script")
        print("      ile AYNI klasörden çalıştırdığından emin ol.")


if __name__ == "__main__":
    main()