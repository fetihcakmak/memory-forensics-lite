#!/usr/bin/env python3
"""
Memory Forensics Lite - Ana CLI Modülü
Kullanım: python main.py --pid 1234
"""
import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from forensics.process_analyzer import get_process_memory_regions, read_process_memory
from forensics.string_hunter import scan_for_iocs
from forensics.injection_detect import detect_rwx_regions

# --- ANSI Renk Kodları ---
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
MAGENTA= "\033[95m"
BOLD   = "\033[1m"
RESET  = "\033[0m"
GRAY   = "\033[90m"

BANNER = f"""{BOLD}{CYAN}
███╗   ███╗███████╗███╗   ███╗ ██████╗ ██████╗ ██╗   ██╗
████╗ ████║██╔════╝████╗ ████║██╔═══██╗██╔══██╗╚██╗ ██╔╝
██╔████╔██║█████╗  ██╔████╔██║██║   ██║██████╔╝ ╚████╔╝ 
██║╚██╔╝██║██╔══╝  ██║╚██╔╝██║██║   ██║██╔══██╗  ╚██╔╝  
██║ ╚═╝ ██║███████╗██║ ╚═╝ ██║╚██████╔╝██║  ██║   ██║   
╚═╝     ╚═╝╚══════╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
       MEMORY FORENSICS LITE v1.0{RESET}
"""

def print_section(title: str):
    print(f"\n{BOLD}{MAGENTA}[*] {title}{RESET}")

def run_demo():
    print_section("DEMO MODU AKTİF")
    print(f"{GRAY}Sanal PID 9876 üzerinden bellek okuma simüle ediliyor...{RESET}")
    print(f"{CYAN}Taranan Bölge:{RESET} 0x00007FF7B4000000, Boyut: 2048 KB")
    
    print_section("Aşama 1: RWX (Injection) Taraması")
    print(f"  {RED}[!] ŞÜPHELİ:{RESET} 0x00007FF7B4200000 adresinde RWX (Read/Write/Execute) izni bulundu! Shellcode şüphesi.")
    
    print_section("Aşama 2: IOC String Avcılığı")
    print(f"  {GREEN}[+] IPv4 Eşleşmeleri:{RESET}")
    print("      - 192.168.1.55 (C2 IP olabilir)")
    print("      - 8.8.8.8")
    
    print(f"  {GREEN}[+] URL Eşleşmeleri:{RESET}")
    print("      - http://malicious-domain.xyz/payload.bin")
    
    print(f"  {RED}[!] Kritik Windows API Eşleşmeleri:{RESET}")
    print("      - VirtualAllocEx")
    print("      - WriteProcessMemory")
    print("      - CreateRemoteThread")
    print(f"\n{YELLOW}Sonuç:{RESET} Simüle edilen process'te DLL Injection veya Hollowlama aktivitesi yüksek ihtimal.")

def main():
    parser = argparse.ArgumentParser(
        description='Memory Forensics Lite - Süreç (Process) Bellek Analizi'
    )
    parser.add_argument('--pid', type=int, help='Analiz edilecek sürecin PID numarası')
    parser.add_argument('--demo', action='store_true', help='Demo modunda çalıştır (simüle edilmiş sonuçlar)')
    
    args = parser.parse_args()
    print(BANNER)
    
    if not (args.pid or args.demo):
        print(f"{YELLOW}Kullanım örnekleri:{RESET}")
        print("  python main.py --demo")
        print("  python main.py --pid 4512")
        sys.exit(0)

    if args.demo:
        run_demo()
        sys.exit(0)

    if sys.platform != 'win32':
        print(f"{RED}Hata: Bu araç ctypes.windll.kernel32 kullandığı için yalnızca Windows üzerinde çalışır.{RESET}")
        print(f"Ancak demo modunu test edebilirsiniz: {YELLOW}python main.py --demo{RESET}")
        sys.exit(1)

    pid = args.pid
    print_section(f"Süreç (PID: {pid}) Analiz Ediliyor...")
    
    regions = get_process_memory_regions(pid)
    if not regions:
        print(f"{RED}Hata: Süreç bulunamadı veya yetki yetersiz (Administrator olarak çalıştırmayı deneyin).{RESET}")
        sys.exit(1)
        
    print(f"{GREEN}[+]{RESET} Toplam {len(regions)} okunabilir bellek bölgesi bulundu.")
    
    # 1. Detect Injection
    rwx_regions = detect_rwx_regions(regions)
    if rwx_regions:
        print(f"\n{RED}[!] DİKKAT: {len(rwx_regions)} adet RWX bellek bölgesi tespit edildi!{RESET}")
        for base, size in rwx_regions:
            print(f"    -> Adres: {hex(base)}, Boyut: {size} bayt")
    else:
        print(f"\n{GREEN}[+] RWX bellek bölgesi bulunamadı. Injection ihtimali düşük.{RESET}")
        
    # 2. IOC Hunting
    print_section("IOC (Indicators of Compromise) Taraması")
    print(f"{GRAY}Bellek bölgeleri regex motoruyla taranıyor... Bu işlem zaman alabilir.{RESET}")
    
    all_iocs = {"IPv4": set(), "URL": set(), "Email": set(), "Windows_API": set()}
    scanned_bytes = 0
    
    for base, size, protect in regions:
        # Sadece küçük bölgeleri veya RWX bölgelerini tarayalım hız için
        if size < 5 * 1024 * 1024 or protect == 0x40:  # < 5MB or RWX
            data = read_process_memory(pid, base, size)
            if data:
                scanned_bytes += len(data)
                findings = scan_for_iocs(data)
                for key, vals in findings.items():
                    all_iocs[key].update(vals)
                    
    print(f"{GREEN}[+]{RESET} Toplam {scanned_bytes / (1024*1024):.2f} MB bellek taranıp analiz edildi.\n")
    
    has_findings = False
    for key, vals in all_iocs.items():
        if vals:
            has_findings = True
            color = RED if key == "Windows_API" else CYAN
            print(f"  {color}[*] {key} Buluntuları ({len(vals)}):{RESET}")
            for v in list(vals)[:10]:
                print(f"      - {v}")
            if len(vals) > 10:
                print(f"      - ... ve {len(vals) - 10} daha.")
                
    if not has_findings:
        print(f"{GREEN}[+] Şüpheli IOC veya kritik string bulunamadı.{RESET}")

    print()

if __name__ == '__main__':
    main()
