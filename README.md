# NetGuardian-DFIR 🌐🔍

**Gelişmiş Ağ Analiz ve Dijital Adli Bilişim (DFIR) Aracı**  
Python ile geliştirilen bu araç, ağ trafiğini gerçek zamanlı analiz eder, tehditleri tespit eder ve adli bilişim incelemeleri için veri toplar.

<div align="center">
  <img src="https://github.com/user-attachments/assets/b07b1614-725d-462a-bfda-bca6e1a1e6e0" width="500" alt="Ekran Görüntüsü">
</div>


---

## 📌 Öne Çıkan Özellikler
- **Gerçek Zamanlı Paket Dinleme**: Scapy ile ağ trafiğini yakalayın.
- **Tehdit Tespiti**: ARP spoofing, malware imzaları, anormal trafik algılama.
- **VirusTotal Entegrasyonu**: IP/domain analizi için otomatik sorgulama.
- **DFIR Araçları**: Çalışan prosesler, ağ bağlantıları, dosya bütünlük kontrolü.
- **Raporlama**: Analiz sonuçlarını TXT/JSON olarak dışa aktarın.
- **Kullanıcı Dostu Arayüz**: Tkinter tabanlı grafik arayüz.

---

## 🛠 Kurulum

### Ön Koşullar
- Python 3.8+
- Pip paket yöneticisi

### Adım Adım Kurulum
1. Depoyu klonlayın:
   ```bash
   git clone https://github.com/SUmidcyber/TR-NetForensics.git
   cd TR-NetForensics

2. Gereksinimleri yükleyin:

        pip install -r requirements.txt
## VirusTotal API anahtarınızı vt_key.txt dosyasına kaydedin (isteğe bağlı).

## 🚀 Kullanım
1. Arayüzü Başlatın:

        python main.py

**📡 Ağ arayüzünü seçip "Dinlemeye Başla" butonuna basın.**

**⚠️ Tespit edilen tehditler otomatik olarak "Tehdit Tespiti" sekmesinde görünecektir.**

**📊 İstatistikler ve grafikler anlık olarak güncellenir.**

**📝 "Rapor Oluştur" butonu ile analiz sonuçlarını kaydedin.**

## 🔍 Örnek Kullanım Senaryoları

**Senaryo 1: ARP Spoofing Tespiti** 
 - Dinlemeyi başlatın.

 - Başka bir cihazda ARP spoofing saldırısı gerçekleştirin (örneğin arpspoof aracıyla).

 - Araç, sahte ARP paketlerini otomatik tespit edip uyarı verecektir.

## 🤝 Katkıda Bulunma
Forklayın ➡️ Düzenleyin ➡️ Pull Request gönderin.

Hata bildirimleri için Issue açın.


## Linkedin:
https://www.linkedin.com/in/umid-mammadov-951968278/
