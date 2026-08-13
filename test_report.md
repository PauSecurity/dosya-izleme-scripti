# FIM Tespit Sistemi - Otomatik Test Raporu

Oluşturulma zamanı: 2026-08-13 09:26:17

**Sonuç: 6/11 senaryo beklendiği gibi çalıştı.**

| Senaryo | Açıklama | Beklenen | Gerçekleşen | Durum |
|---|---|---|---|---|
| BENIGN-1 | Normal dosya oluşturma/düzenleme (insan hızında) | ALARM YOK | (hiçbiri) | ✅ PASS |
| BENIGN-2 | Yavaş klasör gezinme (eşiğin altında) | ALARM YOK | (hiçbiri) | ✅ PASS |
| BENIGN-3 | Zararsız komutlar (whoami, Get-Date) | ALARM YOK | (hiçbiri) | ✅ PASS |
| BENIGN-4 | Normal dosya yeniden adlandırma (şüpheli olmayan uzantı) | ALARM YOK | (hiçbiri) | ✅ PASS |
| BENIGN-5 | Gerçek ZIP oluşturma (doğal yüksek entropi, bilinen format) | ALARM YOK | (hiçbiri) | ✅ PASS |
| MALICIOUS-1 | Canary dosyaya dokunma | CANARY | (hiçbiri) | ❌ FAIL |
| MALICIOUS-2 | Hızlı toplu rename (.locked, 35 dosya) | RANSOMWARE_BEHAVIOR | (hiçbiri) | ❌ FAIL |
| MALICIOUS-3 | Hızlı klasör keşfi (25 klasör, korelasyon bağlamı) | ALARM YOK | (hiçbiri) | ✅ PASS |
| MALICIOUS-4 | vssadmin delete shadows (shadow copy yoksa zararsız) | DEFENSE_EVASION | RANSOMWARE_BEHAVIOR | ❌ FAIL |
| MALICIOUS-5 | whoami /priv (sadece listeler, değiştirmez) | PRIVILEGE_ESCALATION | (hiçbiri) | ❌ FAIL |
| MALICIOUS-6 | Bilinmeyen uzantı + yüksek entropi (.dat, rastgele veri) | ENTROPY | (hiçbiri) | ❌ FAIL |

## Başarısız Senaryolar - Analiz Gerekli

- **MALICIOUS-1**: Beklenen alarm (CANARY) gelmedi -> muhtemel KAÇIRILAN TESPİT, eşik/anahtar kelime gözden geçirilmeli.
- **MALICIOUS-2**: Beklenen alarm (RANSOMWARE_BEHAVIOR) gelmedi -> muhtemel KAÇIRILAN TESPİT, eşik/anahtar kelime gözden geçirilmeli.
- **MALICIOUS-4**: Beklenen alarm (DEFENSE_EVASION) gelmedi -> muhtemel KAÇIRILAN TESPİT, eşik/anahtar kelime gözden geçirilmeli.
- **MALICIOUS-5**: Beklenen alarm (PRIVILEGE_ESCALATION) gelmedi -> muhtemel KAÇIRILAN TESPİT, eşik/anahtar kelime gözden geçirilmeli.
- **MALICIOUS-6**: Beklenen alarm (ENTROPY) gelmedi -> muhtemel KAÇIRILAN TESPİT, eşik/anahtar kelime gözden geçirilmeli.