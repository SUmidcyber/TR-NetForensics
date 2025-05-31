import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import scapy.all as scapy
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import socket
import psutil
import time
from datetime import datetime
import threading
import os
import json
import subprocess
import requests
import hashlib
from io import StringIO
import sys
import platform
from tkinter import filedialog

class GelismisNetworkAnalizAraci:
    def __init__(self, root):
        self.root = root
        self.root.title("Gelişmiş Ağ Analiz ve DFIR Aracı")
        self.root.geometry("1300x900")
        self.root.configure(bg='#f0f0f0')
        
        # Değişkenler
        self.sniffer_durumu = False
        self.paketler = []
        self.arayuz = None
        self.analiz_sonuclari = {}
        self.virustotal_apikey = ""
        self.tehdit_imzalari = self.tehdit_imzalari_yukle()
        self.dfir_rapor = ""
        
        # Stil Ayarları
        self.stil = ttk.Style()
        self.stil.configure('TFrame', background='#f0f0f0')
        self.stil.configure('TLabel', background='#f0f0f0', font=('Arial', 10))
        self.stil.configure('TButton', font=('Arial', 10))
        self.stil.configure('Header.TLabel', font=('Arial', 12, 'bold'))
        
        # Arayüzü Oluştur
        self.arayuz_olustur()
        
        # Arayüzleri otomatik tespit et
        self.arayuzleri_guncelle()
        
        # VirusTotal API key kontrolü
        self.virustotal_key_kontrol()
        
    def arayuz_olustur(self):
        # Başlık Çerçevesi
        baslik_cercevesi = ttk.Frame(self.root)
        baslik_cercevesi.pack(pady=10, fill=tk.X)
        
        ttk.Label(baslik_cercevesi, text="Gelişmiş Ağ Analiz ve DFIR Aracı", 
                 style='Header.TLabel').pack(side=tk.TOP, pady=5)
        
        # Kontrol Çerçevesi
        kontrol_cercevesi = ttk.Frame(self.root)
        kontrol_cercevesi.pack(fill=tk.X, padx=10, pady=5)
        
        # Arayüz Seçimi
        arayuz_cercevesi = ttk.Frame(kontrol_cercevesi)
        arayuz_cercevesi.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(arayuz_cercevesi, text="Ağ Arayüzü:").pack(side=tk.LEFT)
        
        self.arayuz_combobox = ttk.Combobox(arayuz_cercevesi, state='readonly', width=25)
        self.arayuz_combobox.pack(side=tk.LEFT, padx=5)
        
        yenile_btn = ttk.Button(arayuz_cercevesi, text="Yenile", command=self.arayuzleri_guncelle)
        yenile_btn.pack(side=tk.LEFT, padx=5)
        
        # VirusTotal API Çerçevesi
        vt_cercevesi = ttk.Frame(kontrol_cercevesi)
        vt_cercevesi.pack(side=tk.RIGHT, padx=5)
        
        ttk.Label(vt_cercevesi, text="VirusTotal API Key:").pack(side=tk.LEFT)
        
        self.vt_key_entry = ttk.Entry(vt_cercevesi, width=30)
        self.vt_key_entry.pack(side=tk.LEFT, padx=5)
        
        vt_kaydet_btn = ttk.Button(vt_cercevesi, text="Kaydet", command=self.virustotal_key_kaydet)
        vt_kaydet_btn.pack(side=tk.LEFT, padx=5)
        
        # Buton Çerçevesi
        btn_cercevesi = ttk.Frame(self.root)
        btn_cercevesi.pack(fill=tk.X, padx=10, pady=10)
        
        self.baslat_btn = ttk.Button(btn_cercevesi, text="Dinlemeye Başla", command=self.dinlemeye_basla)
        self.baslat_btn.pack(side=tk.LEFT, padx=5)
        
        self.durdur_btn = ttk.Button(btn_cercevesi, text="Dinlemeyi Durdur", command=self.dinlemeyi_durdur, state=tk.DISABLED)
        self.durdur_btn.pack(side=tk.LEFT, padx=5)
        
        analiz_btn = ttk.Button(btn_cercevesi, text="Trafiği Analiz Et", command=self.trafik_analiz_et)
        analiz_btn.pack(side=tk.LEFT, padx=5)
        
        rapor_btn = ttk.Button(btn_cercevesi, text="Rapor Oluştur", command=self.rapor_olustur)
        rapor_btn.pack(side=tk.LEFT, padx=5)
        
        malware_btn = ttk.Button(btn_cercevesi, text="Malware Taraması", command=self.malware_taramasi_yap)
        malware_btn.pack(side=tk.LEFT, padx=5)
        
        dfir_btn = ttk.Button(btn_cercevesi, text="DFIR Araçları", command=self.dfir_araclari)
        dfir_btn.pack(side=tk.LEFT, padx=5)
        
        # Ana İçerik Çerçevesi
        ana_cerceve = ttk.Frame(self.root)
        ana_cerceve.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Paket Listesi Çerçevesi
        liste_cercevesi = ttk.Frame(ana_cerceve)
        liste_cercevesi.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        ttk.Label(liste_cercevesi, text="Yakalanan Paketler", style='Header.TLabel').pack()
        
        self.paket_agaci = ttk.Treeview(liste_cercevesi, columns=('No', 'Zaman', 'Kaynak', 'Hedef', 'Protokol', 'Uzunluk'), show='headings')
        
        self.paket_agaci.heading('No', text='No')
        self.paket_agaci.heading('Zaman', text='Zaman')
        self.paket_agaci.heading('Kaynak', text='Kaynak IP')
        self.paket_agaci.heading('Hedef', text='Hedef IP')
        self.paket_agaci.heading('Protokol', text='Protokol')
        self.paket_agaci.heading('Uzunluk', text='Uzunluk')
        
        self.paket_agaci.column('No', width=50)
        self.paket_agaci.column('Zaman', width=120)
        self.paket_agaci.column('Kaynak', width=150)
        self.paket_agaci.column('Hedef', width=150)
        self.paket_agaci.column('Protokol', width=80)
        self.paket_agaci.column('Uzunluk', width=80)
        
        self.paket_agaci.pack(fill=tk.BOTH, expand=True)
        
        # Paket Detayları Çerçevesi
        detay_cercevesi = ttk.Frame(ana_cerceve, width=300)
        detay_cercevesi.pack(side=tk.RIGHT, fill=tk.BOTH)
        
        ttk.Label(detay_cercevesi, text="Paket Detayları", style='Header.TLabel').pack()
        
        self.detay_metin = scrolledtext.ScrolledText(detay_cercevesi, wrap=tk.WORD, width=40)
        self.detay_metin.pack(fill=tk.BOTH, expand=True)
        
        # Analiz Sonuçları Çerçevesi
        analiz_cercevesi = ttk.Frame(self.root)
        analiz_cercevesi.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.analiz_not_defteri = ttk.Notebook(analiz_cercevesi)
        self.analiz_not_defteri.pack(fill=tk.BOTH, expand=True)
        
        # İstatistikler Sekmesi
        istatistik_sekmesi = ttk.Frame(self.analiz_not_defteri)
        self.analiz_not_defteri.add(istatistik_sekmesi, text="İstatistikler")
        
        self.istatistik_metin = scrolledtext.ScrolledText(istatistik_sekmesi, wrap=tk.WORD)
        self.istatistik_metin.pack(fill=tk.BOTH, expand=True)
        
        # Tehditler Sekmesi
        tehdit_sekmesi = ttk.Frame(self.analiz_not_defteri)
        self.analiz_not_defteri.add(tehdit_sekmesi, text="Tehdit Tespiti")
        
        self.tehdit_metin = scrolledtext.ScrolledText(tehdit_sekmesi, wrap=tk.WORD)
        self.tehdit_metin.pack(fill=tk.BOTH, expand=True)
        
        # VirusTotal Sekmesi
        vt_sekmesi = ttk.Frame(self.analiz_not_defteri)
        self.analiz_not_defteri.add(vt_sekmesi, text="VirusTotal")
        
        self.vt_metin = scrolledtext.ScrolledText(vt_sekmesi, wrap=tk.WORD)
        self.vt_metin.pack(fill=tk.BOTH, expand=True)
        
        # DFIR Sekmesi
        dfir_sekmesi = ttk.Frame(self.analiz_not_defteri)
        self.analiz_not_defteri.add(dfir_sekmesi, text="DFIR Araçları")
        
        self.dfir_metin = scrolledtext.ScrolledText(dfir_sekmesi, wrap=tk.WORD)
        self.dfir_metin.pack(fill=tk.BOTH, expand=True)
        
        # Görselleştirme Sekmesi
        gorsel_sekmesi = ttk.Frame(self.analiz_not_defteri)
        self.analiz_not_defteri.add(gorsel_sekmesi, text="Görselleştirme")
        
        self.figur = plt.Figure(figsize=(6, 5), dpi=100)
        self.canvas = FigureCanvasTkAgg(self.figur, master=gorsel_sekmesi)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
    def arayuzleri_guncelle(self):
        arayuzler = psutil.net_if_addrs().keys()
        self.arayuz_combobox['values'] = list(arayuzler)
        if arayuzler:
            self.arayuz_combobox.current(0)
            
    def virustotal_key_kontrol(self):
        try:
            with open('vt_key.txt', 'r') as f:
                self.virustotal_apikey = f.read().strip()
                self.vt_key_entry.insert(0, self.virustotal_apikey)
        except FileNotFoundError:
            pass
            
    def virustotal_key_kaydet(self):
        self.virustotal_apikey = self.vt_key_entry.get()
        with open('vt_key.txt', 'w') as f:
            f.write(self.virustotal_apikey)
        messagebox.showinfo("Bilgi", "VirusTotal API anahtarı kaydedildi")
        
    def dinlemeye_basla(self):
        self.arayuz = self.arayuz_combobox.get()
        if not self.arayuz:
            messagebox.showerror("Hata", "Lütfen bir ağ arayüzü seçin")
            return
            
        self.sniffer_durumu = True
        self.baslat_btn.config(state=tk.DISABLED)
        self.durdur_btn.config(state=tk.NORMAL)
        self.paketler = []
        self.paket_agaci.delete(*self.paket_agaci.get_children())
        
        # Dinlemeyi ayrı bir thread'de başlatir
        self.sniffer_thread = threading.Thread(target=self.paketleri_dinle, daemon=True)
        self.sniffer_thread.start()
        
    def dinlemeyi_durdur(self):
        self.sniffer_durumu = False
        self.baslat_btn.config(state=tk.NORMAL)
        self.durdur_btn.config(state=tk.DISABLED)
        
    def paketleri_dinle(self):
        def paket_callback(paket):
            if not self.sniffer_durumu:
                return
                
            paket_dict = {
                'zaman_damgasi': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'paket': paket
            }
            
            self.paketler.append(paket_dict)
            
            # GUI'yi ana thread'de güncelleme verir
            self.root.after(0, self.paket_listesini_guncelle, paket_dict)
            
        scapy.sniff(iface=self.arayuz, prn=paket_callback, store=False)
        
    def paket_listesini_guncelle(self, paket_dict):
        paket = paket_dict['paket']
        
        # Temel paket bilgilerini çıkariyor
        if paket.haslayer(scapy.IP):
            kaynak = paket[scapy.IP].src
            hedef = paket[scapy.IP].dst
            protokol = paket[scapy.IP].proto
            uzunluk = len(paket)
            
            # Protokol eşlemeleri buradan eklene bilir veya sile bilirsin
            protokol_esleme = {
                1: "ICMP",
                6: "TCP",
                17: "UDP",
                2: "IGMP"
            }
            protokol_adi = protokol_esleme.get(protokol, str(protokol))
            
            self.paket_agaci.insert('', tk.END, values=(
                len(self.paketler),
                paket_dict['zaman_damgasi'],
                kaynak,
                hedef,
                protokol_adi,
                uzunluk
            ))
            
    def trafik_analiz_et(self):
        if not self.paketler:
            messagebox.showwarning("Uyarı", "Henüz paket yakalanmadı")
            return
            
        self.analiz_sonuclari = {
            'toplam_paket': len(self.paketler),
            'protokol_dagilimi': {},
            'yuksek_trafik': {},
            'olası_tehditler': [],
            'veri_hacmi': {},
            'vt_sonuclari': {}
        }
        
        # Protokolleri analiz eden for
        protokol_sayimi = {}
        ip_veri_hacmi = {}
        
        for pkt in self.paketler:
            paket = pkt['paket']
            
            if paket.haslayer(scapy.IP):
                kaynak = paket[scapy.IP].src
                hedef = paket[scapy.IP].dst
                uzunluk = len(paket)
                protokol = paket[scapy.IP].proto
                
                # Protokol analizi buradan yapilicak ekleme yapa bilirsin
                protokol_esleme = {
                    1: "ICMP",
                    6: "TCP",
                    17: "UDP",
                    2: "IGMP"
                }
                protokol_adi = protokol_esleme.get(protokol, str(protokol))
                protokol_sayimi[protokol_adi] = protokol_sayimi.get(protokol_adi, 0) + 1
                
                # Veri hacmi analizi
                ip_veri_hacmi[kaynak] = ip_veri_hacmi.get(kaynak, 0) + uzunluk
                ip_veri_hacmi[hedef] = ip_veri_hacmi.get(hedef, 0) + uzunluk
                
                # Tehdit tespiti
                self.tehditleri_tespit_et(paket)
                
                # VirusTotal analizi (ilk 10 IP için)
                if len(self.analiz_sonuclari['vt_sonuclari']) < 10:
                    if kaynak not in self.analiz_sonuclari['vt_sonuclari']:
                        vt_sonuc = self.virustotal_ip_tarama(kaynak)
                        if vt_sonuc:
                            self.analiz_sonuclari['vt_sonuclari'][kaynak] = vt_sonuc
                    
                    if hedef not in self.analiz_sonuclari['vt_sonuclari']:
                        vt_sonuc = self.virustotal_ip_tarama(hedef)
                        if vt_sonuc:
                            self.analiz_sonuclari['vt_sonuclari'][hedef] = vt_sonuc
        
        self.analiz_sonuclari['protokol_dagilimi'] = protokol_sayimi
        self.analiz_sonuclari['veri_hacmi'] = ip_veri_hacmi
        
        # En çok trafik üretenler :)
        sirali_ipler = sorted(ip_veri_hacmi.items(), key=lambda x: x[1], reverse=True)
        self.analiz_sonuclari['yuksek_trafik'] = dict(sirali_ipler[:5])
        
        # Analiz sonuçlarını göster 
        self.analiz_sonuclarini_goster()
        
    def tehditleri_tespit_et(self, paket):
        # ARP Spoofing tespitleri
        if paket.haslayer(scapy.ARP) and paket[scapy.ARP].op == 2:  # ARP cevabı
            if paket[scapy.ARP].hwsrc.lower() != scapy.getmacbyip(paket[scapy.ARP].psrc):
                tehdit = {
                    'tur': 'ARP Spoofing',
                    'kaynak_mac': paket[scapy.ARP].hwsrc,
                    'spoofed_ip': paket[scapy.ARP].psrc,
                    'zaman_damgasi': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                self.analiz_sonuclari['olası_tehditler'].append(tehdit)
        
        # Büyük veri transferi tespiti (1GB eşiği) (artira biliriz)
        if paket.haslayer(scapy.IP) and len(paket) > 1000000:  # Paket başına 1MB şüpheli olur
            tehdit = {
                'tur': 'Büyük Veri Transferi',
                'kaynak': paket[scapy.IP].src,
                'hedef': paket[scapy.IP].dst,
                'boyut': len(paket),
                'zaman_damgasi': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            self.analiz_sonuclari['olası_tehditler'].append(tehdit)
            
        # Malware imza tespiti <3
        if paket.haslayer(scapy.Raw):
            payload = str(paket[scapy.Raw].load)
            for imza, aciklama in self.tehdit_imzalari.items():
                if imza in payload:
                    tehdit = {
                        'tur': 'Malware İmzası Tespit Edildi',
                        'imza': imza,
                        'aciklama': aciklama,
                        'kaynak': paket[scapy.IP].src if paket.haslayer(scapy.IP) else 'N/A',
                        'zaman_damgasi': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    self.analiz_sonuclari['olası_tehditler'].append(tehdit)
        
    def tehdit_imzalari_yukle(self):
        # Gelişmiş tehdit imzaları (gerçek bir uygulamada veritabanından yüklenir) ekleme yaparsan haber ver :)
        imzalar = {
            # Windows kötü amaçlı yazılım imzaları
            "cmd.exe /c": "Windows komut istemi çalıştırma girişimi",
            "powershell -e": "Base64 ile kodlanmış PowerShell komutu",
            "reg add": "Kayıt defteri değişikliği girişimi",
            "schtasks": "Zamanlanmış görev oluşturma girişimi",
            
            # Web saldırı imzaları
            "<?php system(": "PHP komut enjeksiyonu girişimi",
            "/etc/passwd": "Linux şifre dosyasına erişim girişimi",
            "union select": "SQL enjeksiyon girişimi",
            "eval(": "JavaScript/PHP kodu çalıştırma girişimi",
            
            # Ağ saldırı imzaları
            "nc -lvp": "Netcat dinleyici oluşturma",
            "wget http://": "Şüpheli dosya indirme girişimi",
            "curl -o": "Şüpheli dosya indirme girişimi",
            
            # Şifreleme imzaları
            "str_rot13": "ROT13 şifreleme kullanımı",
            "base64_decode": "Base64 kod çözme",
            
            # Exploit imzaları
            "msfvenom": "Metasploit payload oluşturma",
            "x5o!p%@ap": "Office belgesinde gömülü kötü amaçlı kod",
            
            # Linux kötü amaçlı yazılım imzaları
            "chmod 777": "Dosya izinlerini değiştirme girişimi",
            "/bin/bash -i": "Ters kabuk başlatma girişimi",
            
            # Obfuscation teknikleri
            "fromCharCode": "JavaScript obfuscation tekniği",
            "eval(function": "JavaScript obfuscation tekniği"
        }
        
        # Daha fazla imza eklemek için harici dosya okunabilir
        try:
            with open('tehdit_imzalari.json', 'r') as f:
                ek_imzalar = json.load(f)
                imzalar.update(ek_imzalar)
        except FileNotFoundError:
            pass
            
        return imzalar
        
    def virustotal_ip_tarama(self, ip_adresi):
        if not self.virustotal_apikey:
            return None
            
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_adresi}"
        headers = {
            "accept": "application/json",
            "x-apikey": self.virustotal_apikey
        }
        
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                return response.json()
            else:
                return None
        except Exception as e:
            print(f"VirusTotal hatası: {e}")
            return None
            
    def virustotal_domain_tarama(self, domain):
        if not self.virustotal_apikey:
            return None
            
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {
            "accept": "application/json",
            "x-apikey": self.virustotal_apikey
        }
        
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                return response.json()
            else:
                return None
        except Exception as e:
            print(f"VirusTotal hatası: {e}")
            return None
            
    def analiz_sonuclarini_goster(self):
        # İstatistikleri güncelle 
        istatistik_metin = f"Toplam Yakalanan Paket: {self.analiz_sonuclari['toplam_paket']}\n\n"
        
        istatistik_metin += "Protokol Dağılımı:\n"
        for protokol, sayi in self.analiz_sonuclari['protokol_dagilimi'].items():
            istatistik_metin += f"{protokol}: {sayi} paket ({(sayi/self.analiz_sonuclari['toplam_paket'])*100:.2f}%)\n"
            
        istatistik_metin += "\nEn Çok Trafik Üretenler:\n"
        for ip, hacim in self.analiz_sonuclari['yuksek_trafik'].items():
            istatistik_metin += f"{ip}: {self.byte_format(hacim)}\n"
            
        self.istatistik_metin.delete(1.0, tk.END)
        self.istatistik_metin.insert(tk.END, istatistik_metin)
        
        # Tehditleri güncelle
        tehdit_metin = "Tespit Edilen Olası Tehditler:\n\n"
        
        if not self.analiz_sonuclari['olası_tehditler']:
            tehdit_metin += "Herhangi bir tehdit tespit edilmedi\n"
        else:
            for tehdit in self.analiz_sonuclari['olası_tehditler']:
                tehdit_metin += f"Tür: {tehdit['tur']}\n"
                if 'kaynak' in tehdit:
                    tehdit_metin += f"Kaynak: {tehdit['kaynak']}\n"
                if 'hedef' in tehdit:
                    tehdit_metin += f"Hedef: {tehdit['hedef']}\n"
                if 'boyut' in tehdit:
                    tehdit_metin += f"Boyut: {self.byte_format(tehdit['boyut'])}\n"
                if 'imza' in tehdit:
                    tehdit_metin += f"İmza: {tehdit['imza']}\n"
                    tehdit_metin += f"Açıklama: {tehdit['aciklama']}\n"
                tehdit_metin += f"Zaman Damgası: {tehdit['zaman_damgasi']}\n\n"
                
        self.tehdit_metin.delete(1.0, tk.END)
        self.tehdit_metin.insert(tk.END, tehdit_metin)
        
        # VirusTotal sonuçlarını güncelleme yapilir
        vt_metin = "VirusTotal Analiz Sonuçları:\n\n"
        
        if not self.analiz_sonuclari['vt_sonuclari']:
            vt_metin += "VirusTotal analizi yapılmadı veya API anahtarı girilmedi\n"
        else:
            for ip, sonuc in self.analiz_sonuclari['vt_sonuclari'].items():
                vt_metin += f"IP Adresi: {ip}\n"
                
                if 'data' in sonuc and 'attributes' in sonuc['data']:
                    attr = sonuc['data']['attributes']
                    
                    if 'last_analysis_stats' in attr:
                        stats = attr['last_analysis_stats']
                        vt_metin += f"  Kötü amaçlı: {stats.get('malicious', 0)}\n"
                        vt_metin += f"  Şüpheli: {stats.get('suspicious', 0)}\n"
                        vt_metin += f"  Zararsız: {stats.get('harmless', 0)}\n"
                        vt_metin += f"  Tespit Edilmeyen: {stats.get('undetected', 0)}\n"
                    
                    if 'as_owner' in attr:
                        vt_metin += f"  AS Sahibi: {attr['as_owner']}\n"
                    
                    if 'country' in attr:
                        vt_metin += f"  Ülke: {attr['country']}\n"
                    
                    vt_metin += "\n"
                
        self.vt_metin.delete(1.0, tk.END)
        self.vt_metin.insert(tk.END, vt_metin)
        
        # Görselleştirmeyi günceller
        self.gorsellestirmeyi_guncelle()
        
    def gorsellestirmeyi_guncelle(self):
        self.figur.clear()
        
        # Protokol dağılımı pasta grafiği
        ax1 = self.figur.add_subplot(121)
        protokoller = list(self.analiz_sonuclari['protokol_dagilimi'].keys())
        sayilar = list(self.analiz_sonuclari['protokol_dagilimi'].values())
        ax1.pie(sayilar, labels=protokoller, autopct='%1.1f%%')
        ax1.set_title('Protokol Dağılımı')
        
        # En çok trafik üretenler çubuk grafik
        ax2 = self.figur.add_subplot(122)
        ipler = list(self.analiz_sonuclari['yuksek_trafik'].keys())
        hacimler = [v/(1024*1024) for v in self.analiz_sonuclari['yuksek_trafik'].values()]  # MB'ye çevir
        ax2.bar(ipler, hacimler)
        ax2.set_title('En Çok Trafik Üretenler (MB)')
        ax2.set_ylabel('Veri Hacmi (MB)')
        plt.setp(ax2.get_xticklabels(), rotation=45, ha='right')
        
        self.figur.tight_layout()
        self.canvas.draw()
        
    def byte_format(self, boyut):
        # Byte'ları insan tarafından okunabilir formata çevir
        for birim in ['B', 'KB', 'MB', 'GB', 'TB']:
            if boyut < 1024.0:
                return f"{boyut:.2f} {birim}"
            boyut /= 1024.0
        return f"{boyut:.2f} PB"
        
    def rapor_olustur(self):
        """Yakalanan paketler ve analiz sonuçlarından rapor oluşturur"""
        if not self.paketler:
            messagebox.showwarning("Uyarı", "Rapor oluşturmak için önce paket yakalamalısınız")
            return
        
        # Kullanıcıdan dosya yolu seçmesini iste
        dosya_yolu = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Dosyaları", "*.txt"), ("Tüm Dosyalar", "*.*")],
            title="Raporu Kaydet"
        )
        
        if not dosya_yolu:  # Kullanıcı iptal etti
            return
        
        try:
            with open(dosya_yolu, 'w', encoding='utf-8') as f:
                # Temel bilgiler icerir
                f.write("=== Ağ Analiz Raporu ===\n")
                f.write(f"Oluşturulma Tarihi: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Toplam Yakalanan Paket: {len(self.paketler)}\n\n")
                
                # Protokol dağılımıni yapar
                f.write("=== Protokol Dağılımı ===\n")
                for protokol, sayi in self.analiz_sonuclari.get('protokol_dagilimi', {}).items():
                    f.write(f"{protokol}: {sayi} paket\n")
                
                # Tehditler
                f.write("\n=== Tespit Edilen Tehditler ===\n")
                if not self.analiz_sonuclari.get('olası_tehditler', []):
                    f.write("Tehdit tespit edilmedi\n")
                else:
                    for tehdit in self.analiz_sonuclari['olası_tehditler']:
                        f.write(f"\nTür: {tehdit['tur']}\n")
                        if 'kaynak' in tehdit:
                            f.write(f"Kaynak: {tehdit['kaynak']}\n")
                        if 'hedef' in tehdit:
                            f.write(f"Hedef: {tehdit['hedef']}\n")
                        if 'zaman_damgasi' in tehdit:
                            f.write(f"Zaman: {tehdit['zaman_damgasi']}\n")
                
                # DFIR bilgileri
                if hasattr(self, 'dfir_rapor') and self.dfir_rapor:
                    f.write("\n=== DFIR Bilgileri ===\n")
                    f.write(self.dfir_rapor)
                    
            messagebox.showinfo("Başarılı", f"Rapor başarıyla kaydedildi:\n{dosya_yolu}")
        except Exception as e:
            messagebox.showerror("Hata", f"Rapor kaydedilirken hata oluştu:\n{str(e)}")

    def malware_taramasi_yap(self):
        # Sistemde malware taraması yapar
        tarama_sonucu = "Malware Tarama Sonuçları:\n\n"
        
        # Şüpheli prosesleri kontrol et
        supheli_prosesler = []
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline = ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ''
                for imza in self.tehdit_imzalari:
                    if imza.lower() in cmdline.lower():
                        supheli_prosesler.append({
                            'pid': proc.info['pid'],
                            'isim': proc.info['name'],
                            'cmdline': cmdline
                        })
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        if not supheli_prosesler:
            tarama_sonucu += "Herhangi bir şüpheli proses bulunamadı\n"
        else:
            tarama_sonucu += "Şüpheli Prosesler:\n"
            for proc in supheli_prosesler:
                tarama_sonucu += f"PID: {proc['pid']}, İsim: {proc['isim']}\n"
                tarama_sonucu += f"Komut: {proc['cmdline']}\n\n"
                
        # Ağ bağlantılarını kontrol et
        tarama_sonucu += "\nAğ Bağlantıları:\n"
        baglantilar = psutil.net_connections()
        for baglanti in baglantilar:
            if baglanti.status == 'ESTABLISHED' and baglanti.raddr:
                tarama_sonucu += f"Yerel: {baglanti.laddr.ip}:{baglanti.laddr.port} -> Uzak: {baglanti.raddr.ip}:{baglanti.raddr.port} (PID: {baglanti.pid})\n"
                
        self.tehdit_metin.delete(1.0, tk.END)
        self.tehdit_metin.insert(tk.END, tarama_sonucu) 
    def dfir_araclari(self):
        # DFIR (Dijital Adli Bilişim) araçlarını çalıştırır
        self.dfir_rapor = "DFIR (Dijital Adli Bilişim) Araçları:\n\n"
        
        # Sistem bilgilerini topla
        self.dfir_rapor += "=== Sistem Bilgileri ===\n"
        self.dfir_rapor += f"Sistem: {platform.system()} {platform.release()}\n"
        self.dfir_rapor += f"İşletim Sistemi: {platform.platform()}\n"
        self.dfir_rapor += f"Kullanıcı: {os.getlogin()}\n"
        self.dfir_rapor += f"Zaman: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        # Çalışan prosesleri listele
        self.dfir_rapor += "=== Çalışan Prosesler ===\n"
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                self.dfir_rapor += f"PID: {proc.info['pid']}, İsim: {proc.info['name']}, Kullanıcı: {proc.info['username']}\n"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        self.dfir_rapor += "\n"
        
        # Ağ bağlantılarını listele
        self.dfir_rapor += "=== Ağ Bağlantıları ===\n"
        try:
            connections = psutil.net_connections()
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    self.dfir_rapor += f"Yerel: {conn.laddr.ip}:{conn.laddr.port} -> Uzak: {conn.raddr.ip}:{conn.raddr.port} (PID: {conn.pid})\n"
        except Exception as e:
            self.dfir_rapor += f"Ağ bağlantıları alınırken hata: {str(e)}\n"
        self.dfir_rapor += "\n"
        
        # Otomatik başlatma programlarını listele (Windows için)
        if platform.system() == "Windows":
            self.dfir_rapor += "=== Otomatik Başlatma Programları ===\n"
            try:
                startup_path = os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
                if os.path.exists(startup_path):
                    for item in os.listdir(startup_path):
                        self.dfir_rapor += f"Başlangıç Öğesi: {item}\n"
                else:
                    self.dfir_rapor += "Başlangıç klasörü bulunamadı\n"
            except Exception as e:
                self.dfir_rapor += f"Başlangıç programları alınırken hata: {str(e)}\n"
            self.dfir_rapor += "\n"
        
        # Dosya bütünlük kontrolü (önemli sistem dosyaları için)
        self.dfir_rapor += "=== Önemli Dosya Bütünlük Kontrolleri ===\n"
        important_files = {
            'hosts': r'C:\Windows\System32\drivers\etc\hosts' if platform.system() == "Windows" else '/etc/hosts',
            'passwd': '/etc/passwd' if platform.system() != "Windows" else None
        }
        
        for name, path in important_files.items():
            if path:
                if os.path.exists(path):
                    try:
                        with open(path, 'rb') as f:
                            file_hash = hashlib.sha256(f.read()).hexdigest()
                        self.dfir_rapor += f"{name} dosyası SHA-256: {file_hash}\n"
                    except Exception as e:
                        self.dfir_rapor += f"{name} dosyası hash hesaplanırken hata: {str(e)}\n"
                else:
                    self.dfir_rapor += f"{name} dosyası bulunamadı\n"
        self.dfir_rapor += "\n"
        
        # Sonuçları DFIR sekmesine yazdirir <3
        self.dfir_metin.delete(1.0, tk.END)
        self.dfir_metin.insert(tk.END, self.dfir_rapor)

if __name__ == "__main__":
    root = tk.Tk()
    app = GelismisNetworkAnalizAraci(root)
    root.mainloop()  