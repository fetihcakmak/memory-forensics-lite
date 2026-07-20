<div align="center">
<pre>
███╗   ███╗███████╗███╗   ███╗ ██████╗ ██████╗ ██╗   ██╗
████╗ ████║██╔════╝████╗ ████║██╔═══██╗██╔══██╗╚██╗ ██╔╝
██╔████╔██║█████╗  ██╔████╔██║██║   ██║██████╔╝ ╚████╔╝ 
██║╚██╔╝██║██╔══╝  ██║╚██╔╝██║██║   ██║██╔══██╗  ╚██╔╝  
██║ ╚═╝ ██║███████╗██║ ╚═╝ ██║╚██████╔╝██║  ██║   ██║   
╚═╝     ╚═╝╚══════╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
</pre>
</div>

# 🧠 Memory Forensics Lite

> Çalışan Windows süreçlerinin (process) bellek dökümlerini analiz ederek DLL Injection, Hollowlama ve shellcode aktivitesini tespit eden, RAM üzerinden IOC (Indicators of Compromise) avcılığı yapan hafif forensik aracı.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)]()
[![Stdlib](https://img.shields.io/badge/Dep-Stdlib_Only-success)](./)

---

## 📈 Proje Hakkında

Bu araç, RAM'de çalışan süreçlerin (PID) bellek alanlarını okumak için doğrudan `ctypes` üzerinden Windows Kernel API'lerini (OpenProcess, VirtualQueryEx, ReadProcessMemory) kullanır. Herhangi bir dış bağımlılığa (pip) ihtiyaç duymaz.

**Commit Geçmişi:**
| Commit | Açıklama |
|--------|----------|
| `ctypes process memory dumper and ioc string hunter` | Windows API entegrasyonu ve Regex tabanlı IOC (URL, IP, API) arama motoru. |
| `rwx memory region scanner for injection detection` | Bellek enjeksiyonu ve shellcode tespiti için RWX korumalı alan filtresi. |
| `cli interface and automated analysis reporting` | Argparse CLI, PID hedefleme ve raporlama motoru entegrasyonu. |

---

## 🧠 Mimari

```
main.py
  ├── forensics/process_analyzer.py  ← ctypes ile VirtualQueryEx ve ReadProcessMemory
  ├── forensics/injection_detect.py  ← RWX (PAGE_EXECUTE_READWRITE) alanlarını tarama
  └── forensics/string_hunter.py     ← Bellekteki stringlerden IOC (IP, URL) çıkarma
```

---

## ⚡ Kurulum

```bash
git clone https://github.com/fetihcakmak/memory-forensics-lite.git
cd memory-forensics-lite
python main.py --demo   # Ek bağımlılık gerekmez (yalnızca stdlib)
```

## 🚀 Kullanım

```bash
# Simülasyon / Demo modu (Her platformda çalışır)
python main.py --demo

# Gerçek bir süreci analiz etmek (Sadece Windows'ta çalışır ve Administrator yetkisi gerektirebilir)
# Hedef process'in PID numarasını vermeniz gerekir.
python main.py --pid 4512
```

## 🖥️ Örnek Çıktı (Demo Modu)

```
[*] Aşama 1: RWX (Injection) Taraması
  [!] ŞÜPHELİ: 0x00007FF7B4200000 adresinde RWX izni bulundu! Shellcode şüphesi.

[*] Aşama 2: IOC String Avcılığı
  [+] IPv4 Eşleşmeleri: 192.168.1.55 (C2 IP olabilir), 8.8.8.8
  [+] URL Eşleşmeleri: http://malicious-domain.xyz/payload.bin
  [!] Kritik Windows API Eşleşmeleri: VirtualAllocEx, WriteProcessMemory, CreateRemoteThread

Sonuç: Simüle edilen process'te DLL Injection veya Hollowlama aktivitesi yüksek ihtimal.
```

## ⚠️ Etik Kullanım

`--pid` ile gerçek bir süreç hedeflemek, o sürecin belleğini okumak için `OpenProcess`/`ReadProcessMemory` çağırır ve genellikle Administrator yetkisi gerektirir. Bu aracı yalnızca **kendi sisteminizde**, kendi süreçleriniz üzerinde veya DFIR eğitimi/CTF kapsamında izin verilen ortamlarda kullanın. Başkasına ait bir sürecin belleğini izinsiz okumak yasa dışıdır.

## 📄 Lisans

Bu depo şu an bir lisans dosyası içermiyor. Kullanım koşulları için proje sahibiyle iletişime geçin.

---

*Fetih Çakmak — Cybersecurity Portfolio*
