# 🛡️ Python FIM — Dosya Bütünlüğü İzleme Aracı

Windows üzerinde belirli bir klasördeki dosya değişikliklerini (oluşturma, silme, yeniden adlandırma, içerik değişikliği) izleyen, Python ile yazılmış bir **File Integrity Monitoring (FIM)** aracı.

Bu depo, aynı problemi **üç farklı teknik seviyede** çözen üç ayrı script içerir — biri hazır bir kütüphaneyle, biri sıfırdan yazılmış basit bir algoritmayla, biri de doğrudan Windows kernel'inden okuyarak:

| Dosya | Yaklaşım | Seviye | Durum |
|---|---|---|---|
| [`fim.py`](./fim.py) | `watchdog` kütüphanesi (OS-native dosya sistemi bildirimleri) | Yüksek seviye | ✅ Çalışır |
| [`fim_polling.py`](./fim_polling.py) | Klasör anlık görüntüsü karşılaştırma (polling) | Orta seviye, sıfırdan yazıldı | ✅ Ana çözüm — sağlam, sade |
| [`fim_etw.py`](./fim_etw.py) | ETW (Windows Kernel Event Tracing), doğrudan Win32 API | Düşük seviye (kernel) | 🧪 İleri seviye / deneysel |

---

## 📌 Proje Amacı

Bir klasörü (varsayılan: `C:\FileMonitoring`) izleyip şu olayları raporlamak:

- ✚ **Dosya oluşturuldu**
- ✖ **Dosya silindi**
- ✎ **Dosya içeriği değişti**
- ↦ **Dosya yeniden adlandırıldı**

Bu tür araçlar gerçek dünyada **EDR (Endpoint Detection & Response)**, **ransomware tespiti**, **denetim/log** ve **adli bilişim (forensics)** sistemlerinin temel yapı taşlarından biridir. Aynı problemi üç farklı soyutlama seviyesinde çözmek, "kütüphane kullanmak" ile "işletim sisteminin bunu perde arkasında nasıl yaptığını anlamak" arasındaki farkı görmek için bilinçli bir tercihtir.

---

## 🧩 Üç Farklı Teknik Yaklaşım

### 1) `fim.py` — `watchdog` Kütüphanesi ile

**Nasıl çalışır:**
Python'un popüler `watchdog` kütüphanesini kullanır. Bu kütüphane arka planda Windows'un **`ReadDirectoryChangesW`** API'sini sarmalar (wrap eder) ve `on_created` / `on_deleted` / `on_modified` / `on_moved` gibi olay bazlı (event-driven) callback'ler sağlar.

**Kullanılan teknolojiler:**
- **`watchdog`** — çapraz platform (cross-platform) dosya sistemi izleme kütüphanesi
- **`psutil`** — bir dosyayı hangi process'in açık tuttuğunu (`process.open_files()`) bulmak için

**Avantajı:** En az kod ile en hızlı sonuç; kütüphane işletim sistemi farklarını (Windows/Linux/macOS) soyutlar.
**Dezavantajı:** Perde arkasında ne olduğu gizlenir; ince ayar (fine-tuning) imkânı kısıtlıdır.

### 2) `fim_polling.py` — Sıfırdan Yazılmış Polling Algoritması

**Nasıl çalışır:**
Dış kütüphane kullanmadan, izlenen klasörü kısa aralıklarla (varsayılan 0.5 saniye) `os.walk` ile tarar, her dosyanın `(boyut, değiştirilme zamanı)` bilgisini bir önceki taramayla karşılaştırır. Farkı create/delete/modify/rename olarak sınıflandırır.

**Kullanılan teknolojiler:**
- Sadece Python standart kütüphanesi: `os`, `time`, `datetime` — **hiçbir ekstra bağımlılık yok**

**Avantajları:**
- Yönetici (admin) yetkisi **gerektirmez**
- Windows sürümünden tamamen bağımsız, her yerde aynı şekilde çalışır
- Gürültüsüz: bir programın dosyayı sadece "açması" event üretmez, sadece *gerçek* değişiklik raporlanır

**Dezavantajı:** Gerçek zamanlı değil (tarama aralığı kadar gecikme olabilir), hangi process'in yaptığını göstermez.

### 3) `fim_etw.py` — ETW (Event Tracing for Windows), Doğrudan Win32 API

**Nasıl çalışır:**
Kütüphane kullanmadan, `ctypes` ile doğrudan Windows'un kernel seviyesindeki `Microsoft-Windows-Kernel-File` ETW sağlayıcısına (provider) bağlanıp dosya sistemi sürücüsünün ürettiği ham olayları (Create/Write/Close/SetDelete/Rename vb.) gerçek zamanlı dinler — `watchdog`'un içindeki mekanizmayı bir seviye daha aşağıdan, elle inşa eder.

**Kullanılan teknolojiler:**
- **`ctypes`** — Python'dan doğrudan Win32 API çağırma
- **ETW (Event Tracing for Windows)** — Windows'un resmi kernel/uygulama olay izleme altyapısı (`advapi32.dll`: `StartTraceW`, `EnableTraceEx2`, `OpenTraceW`, `ProcessTrace`)
- **`Microsoft-Windows-Kernel-File` provider'ı** (GUID: `EDD08927-9CC4-4E65-B970-C2560FB5C289`)
- **`WTSGetActiveConsoleSessionId` / `ProcessIdToSessionId`** — olayı üreten sürecin kullanıcı oturumuna mı yoksa sistem/servis (Session 0) oturumuna mı ait olduğunu ayırt etmek için
- **`psutil`** — process ID'den process adını çözmek için

**Neden bu yaklaşım zorlayıcı:**
- ETW, C tabanlı Win32 struct'larının **bayt-hizası (byte alignment)** hassasiyetiyle çalışır; `ctypes` ile bu struct'ları birebir doğru tanımlamak gerekir (`EVENT_TRACE_LOGFILEW.CurrentEvent` alanının gerçek tipi `EVENT_TRACE`'tir, yaygın bir hata olarak `EVENT_RECORD` ile karıştırılıp yanlış struct boyutu kullanılırsa tüm sonraki alan offsetleri kayar ve callback hiç tetiklenmez).
- `EnableTraceEx2`'nin `EnableParameters` parametresi `NULL` olamaz; `SystemTraceProvider` (`EVENT_TRACE_SYSTEM_LOGGER_MODE`) oturumlarında `Wnode.Guid` alanına benzersiz bir GUID atanması zorunludur — dokümantasyonda kolayca gözden kaçan ayrıntılardır.
- Kernel-File provider'ının hangi olayın hangi sayısal ID'ye karşılık geldiği **Windows sürümüne göre değişebiliyor**.
- `SetDelete`/`Rename` gibi olaylar dosya adını **metin olarak taşımaz**, sadece bir bellek işaretçisi (`FileObject`) taşır; gerçek dosya yolunu öğrenmek için bu işaretçiyi önceki `Create` olayında öğrenilen yol ile **eşleştirmek (correlation)** gerekir.

**Avantajı:** Gerçek zamanlı (milisaniye gecikmeyle), hangi process'in (`PID`, isim) değişikliği yaptığını gösterir, sadece kullanıcının aktif oturumundaki işlemleri filtreleyebilir.
**Dezavantajı:** Yönetici yetkisi gerektirir, Windows sürümüne duyarlı ve kırılgan, ekstra gürültü filtrelemesi gerektirir.

---

## 🚀 Kurulum ve Çalıştırma

```bash
pip install -r requirements.txt

# 1) watchdog kütüphanesi ile — admin gerektirmez
python fim.py C:\FileMonitoring

# 2) Sıfırdan yazılmış polling ile — admin gerektirmez, bağımlılık yok
python fim_polling.py

# 3) ETW (kernel) ile — Yönetici olarak çalıştırılmalı
python fim_etw.py
```

`fim_polling.py` ve `fim_etw.py` için izlenen klasör, dosyanın başındaki `WATCH_DIR` değişkeninden değiştirilir (varsayılan `C:\FileMonitoring`). `fim.py` ise izlenecek klasörü komut satırı argümanı olarak alır (`python fim.py <klasör>`, verilmezse mevcut klasörü izler).

---

## 🖥️ Örnek Çıktı (`fim_polling.py`)

```
[16:21:55] ✚  OLUŞTURULDU        New Text Document.txt  (0 B)
[16:21:56] ✖  SİLİNDİ            New Text Document.txt
[16:22:10] ✎  İÇERİK DEĞİŞTİ     notlar.txt  (1.2 KB → 1.4 KB)
[16:22:15] ↦  YENİDEN ADLANDIRILDI  eski_isim.txt  →  yeni_isim.txt
```

---

## 🎓 Bu Projede Öğrenilen/Kullanılan Kavramlar

- **Event Tracing for Windows (ETW)** mimarisi: session, provider, consumer kavramları
- **Win32 API'yi Python `ctypes` ile çağırma**, C struct'larını bayt-hizası uyumlu şekilde Python'da yeniden tanımlama
- **Windows process/oturum (session) modeli**: Session 0 izolasyonu, kullanıcı oturumu ile sistem servislerinin ayrımı
- **Aynı problemi farklı soyutlama seviyelerinde çözme**: hazır kütüphane (`watchdog`) → kendi algoritman (polling) → işletim sistemi kerneli (ETW)
- **Gürültü filtreleme / correlation**: ham kernel verisinden anlamlı, okunabilir bilgi çıkarma

---

## ⚠️ Sınırlamalar

- `fim_etw.py`, `ctypes.windll` kullandığı için sadece **Windows**'ta çalışır. `fim.py` ve `fim_polling.py` de şu an Windows'a göre test edildi (`fim.py` teorik olarak `watchdog` sayesinde Linux/macOS'ta da çalışabilir).
- `fim_polling.py`, çok kısa ömürlü (poll aralığından kısa süren) dosya işlemlerini kaçırabilir.
- `fim_etw.py`, farklı Windows sürümlerinde ek doğrulama/güncelleme gerektirebilir.

---

## 📄 Lisans

Bu proje eğitim amaçlıdır.
