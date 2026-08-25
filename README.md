# 🛡️ Python FIM — Fidye Yazılımı Tespit Sistemi

Windows üzerinde çalışan, kernel seviyesinde dosya olaylarını izleyerek fidye yazılımı (ransomware) davranışını tespit eden, çok katmanlı bir **File Integrity Monitoring (FIM)** / davranışsal tespit sistemi.

## 📌 Ana Proje: `fim_etw_classic.py`

Bu, projenin **son ve tek** çalışan sistemidir — tüm tespit katmanlarını, kullanıcıya yönelik uyarı mekanizmasını ve otomatik tepki özelliğini tek bir script'te birleştirir. Windows'un **klasik NT Kernel Logger** mekanizması (`SystemTraceControlGuid` + `FileIo`/`Process` event class'ları) üzerinden çalışır — `ctypes` ile doğrudan Win32 API'lerine bağlanır, hiçbir üçüncü parti izleme kütüphanesi kullanmaz.

### Yedi Bağımsız Tespit Katmanı

| Katman | Ne yakalar | MITRE ATT&CK aşaması |
|---|---|---|
| **Canary (honeyfile)** | Dokunulmaması gereken bir tuzak dosyaya yapılan herhangi bir işlem — eşiksiz, anında | Impact |
| **Davranışsal** | Kısa sürede eşik üzerinde sayıda dosyanın şüpheli bir uzantıya yeniden adlandırılması | Impact |
| **Entropi** | Dosya içeriğinin aniden yüksek entropili/rastgele veriye dönüşmesi (şifreleme belirtisi) | Impact |
| **Defense Evasion** | Komut satırından Shadow Copy/yedek silme girişimleri (`vssadmin`, `wmic` vb.) | Defense Evasion |
| **Yetki Yükseltme** | `whoami /priv`, `runas`, yeni servis/görev oluşturma gibi komutlar | Privilege Escalation |
| **Discovery (korelasyon)** | Hızlı klasör keşfi — tek başına alarm üretmez, diğer sinyalleri güçlendirir | Discovery |
| **Process İtibarı / Ebeveyn Zinciri** | Güvenilir uygulamalar ile "living off the land" araçlarının ayrımı, şüpheli süreç soyağacı | — |

### Kullanıcıya Yönelik Uyarı Sistemi

- **Sessiz çalışma modu** — normal zamanlarda hiçbir şey yazdırmaz, sadece gerçek bir tehdit olduğunda konuşur.
- Her alarmda **"YAPMANIZ GEREKENLER"** listesiyle birlikte net bir uyarı ekranı + **gerçek bir Windows bildirim penceresi** (`MessageBoxW`).
- **"Kesinleşmiş Olay"** — aynı süreç için kısa sürede birden fazla bağımsız sinyal birikirse, tüm kanıtı tek ekranda gösterip kullanıcıdan aksiyon onayı ister (Evet/Hayır/İptal pop-up'ı).
- **Otomatik tepki (yayılmayı durdurma)** — canary tetiklenince (en yüksek güvenilirlikli sinyal olduğu için) onay beklemeden ilgili süreç `suspend()` ile anında durdurulur; diğer sinyallerde kullanıcı onayına bırakılır.

### Neden ETW'nin Klasik Yöntemi?

Projenin geliştirme sürecinde önce ETW'nin modern API'si (`EnableTraceEx2`) denendi, ama bu Windows sürümünde `Rename`/`Delete` olaylarının güvenilir tetiklenmediği tespit edildi. Araştırma sonucunda çok daha eski bir mekanizma olan **NT Kernel Logger**'a geçildi; bu Windows sürümünde dokümante edilmemiş ama güvenilir çalışan iki opcode (silme ve yeniden adlandırma) keşfedildi — bunlar işlemi yapan sürecin gerçek PID'ini ve tam dosya yolunu **doğrudan, hiçbir ek eşleştirmeye gerek kalmadan** taşıyor.

---

## 🧪 Test Altyapısı: `test_detection_suite.py`

Hem zararsız (normal kullanıcı) hem şüpheli davranış desenlerini otomatik simüle eden, sonuçları `alerts_log.jsonl` üzerinden doğrulayıp otomatik bir `test_report.md` raporu üreten sistematik bir test paketi. Gerçek testte bulunan yanlış pozitifler (Windows Defender, PowerShell başlangıç rutini, VS Code'un arka plan taraması) bu paket sayesinde tespit edilip düzeltildi.

```powershell
python fim_etw_classic.py        # Terminal 1 (Yönetici olarak)
python test_detection_suite.py   # Terminal 2
```

---

## 🧩 Yardımcı ve Karşılaştırma Amaçlı Dosyalar

Proje sürecinde aynı problemi farklı seviyelerde çözmek için üç alternatif yaklaşım da denendi (artık kullanılmıyor, sadece karşılaştırma/öğrenme amaçlı repoda tutuluyor):

| Dosya | Yaklaşım |
|---|---|
| `fim.py` | `watchdog` kütüphanesi (yüksek seviye, hazır çözüm) |
| `fim_polling.py` | Kütüphanesiz, klasör anlık görüntüsü karşılaştırma |
| `fim_etw.py` | ETW'nin modern API'si (`EnableTraceEx2`) — `fim_etw_classic.py`'ye evrilmeden önceki ara adım |

**Diğer yardımcı araçlar:**
- `aes_file_tool.py` — AES-256-GCM ile tek dosya şifreleme/deşifreleme eğitim aracı (entropi testleri için gerçek şifreli veri üretir)
- `measure_entropy.py` — Gerçek dosyalarda (zip/docx/jpg vb.) entropi false-positive oranını ölçen bağımsız araç

---

## 🚀 Kurulum

```bash
pip install -r requirements.txt
python fim_etw_classic.py   # Yönetici olarak çalıştırılmalı
```

---

## 🎓 Öğrenilen Kavramlar

- **Event Tracing for Windows (ETW)**: session/provider/consumer mimarisi, klasik vs. modern API farkları
- **Win32 API'leri Python `ctypes` ile çağırma**, C struct'larını bayt-hizası uyumlu şekilde yeniden tanımlama
- **MITRE ATT&CK** çerçevesinde çok aşamalı tespit (Discovery → Defense Evasion → Privilege Escalation → Impact)
- **Detection engineering**: sinyal korelasyonu, itibar bazlı dinamik eşikler, false-positive ölçümü ve azaltma
- **Kriptografi**: AES-GCM, authenticated encryption, Shannon entropi
- **Güvenli yazılım mühendisliği**: geri alınabilir aksiyonlar (kill yerine suspend), GIL-güvenli thread tasarımı, bellek sızıntısı önleme

---

## ⚠️ Sınırlamalar

- `ctypes.windll` kullanıldığı için sadece **Windows**'ta çalışır.
- Tek bir dosyayı **önlemez** (ETW olay zaten gerçekleştikten sonra bildirir) — amacı saldırının **devamını** (yayılmasını) durdurmaktır.
- Ağ trafiğini izlemez; veri hırsızlığı (exfiltration) tespiti kapsam dışıdır.
- Discovery katmanı, dosya yolu bilgisi taşımadığı için klasöre değil PID'in genel davranış hızına göre kapsamlandırılmıştır.

---

## 📄 Lisans

Bu proje eğitim amaçlıdır (Pamukkale Üniversitesi Bilgisayar Mühendisliği stajı kapsamında geliştirilmiştir).