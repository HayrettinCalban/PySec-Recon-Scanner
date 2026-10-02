"""
PySec-Recon-Scanner
Python ile Gelistirilmis Cok Kanalli (Multi-threaded) Ag, Port ve HTTP Guvenlik Basligi Zafiyet Tarayicisi.
"""

import sys
import os

# Windows konsol UTF-8 uyumlulugu
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

import socket
import ssl
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
import requests

# Kritik Standart Portlar ve Servis Isimleri
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet (Insecure)",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    8080: "HTTP-Proxy/Alt"
}

# Olmasi Beklenen Guvenlik Basliklari (OWASP Secure Headers)
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

class PySecRecon:
    def __init__(self, target_host: str):
        self.raw_target = target_host
        self.target_host = target_host.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            self.target_ip = socket.gethostbyname(self.target_host)
        except socket.gaierror:
            print(f"[!] Hata: '{self.target_host}' alan adi cozumlenemedi!")
            sys.exit(1)

    def scan_single_port(self, port: int):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.2)
        try:
            result = s.connect_ex((self.target_ip, port))
            if result == 0:
                service = COMMON_PORTS.get(port, "Bilinmeyen Servis")
                return port, service, "ACIK (OPEN)"
        except Exception:
            pass
        finally:
            s.close()
        return None

    def run_port_scan(self, max_threads=15):
        print(f"\n[*] 1. Port Taramasi Baslatiliyor ({self.target_host} -> {self.target_ip})...")
        open_ports = []
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            results = executor.map(self.scan_single_port, COMMON_PORTS.keys())
            for res in results:
                if res:
                    open_ports.append(res)
                    print(f"    [+] Port {res[0]:<5} [{res[1]:<18}]: {res[2]}")
        if not open_ports:
            print("    [-] Kritik taranan portlar kapali veya filtrelenmis.")
        return open_ports

    def check_http_security_headers(self):
        print(f"\n[*] 2. HTTP Guvenlik Basliklari (Security Headers) Analizi...")
        target_url = f"https://{self.target_host}"
        try:
            response = requests.get(target_url, timeout=5, verify=True)
            headers = response.headers
            missing_headers = []

            for header in SECURITY_HEADERS:
                if header in headers:
                    print(f"    [OK]    {header:<26}: Mevcut")
                else:
                    print(f"    [EKSIK] {header:<26}: Bulunamadi (Tavsiye Edilir)")
                    missing_headers.append(header)
            return missing_headers
        except requests.exceptions.RequestException as e:
            print(f"    [!] Web baglanti uyarisi (HTTPS): {e}")
            return []

    def check_ssl_expiry(self):
        print(f"\n[*] 3. SSL/TLS Sertifika Kontrolu...")
        context = ssl.create_default_context()
        try:
            with socket.create_connection((self.target_host, 443), timeout=4) as sock:
                with context.wrap_socket(sock, server_hostname=self.target_host) as ssock:
                    cert = ssock.getpeercert()
                    exp_date_str = cert['notAfter']
                    exp_date = datetime.strptime(exp_date_str, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                    remaining_days = (exp_date - datetime.now(timezone.utc)).days
                    print(f"    [+] Sertifika Bitis Tarihi: {exp_date_str}")
                    print(f"    [+] Kalan Gecerlilik Suresi: {remaining_days} gun")
        except Exception as e:
            print(f"    [!] SSL kontrolu yapilamadi veya servis kapali: {e}")

if __name__ == "__main__":
    print("=" * 65)
    print("[*] PySec-Recon: Otomatik Zafiyet ve Kesif Araci")
    print("=" * 65)

    # Komut satiri argumani veya varsayilan hedef
    if len(sys.argv) > 1:
        target = sys.argv[1].strip()
    else:
        # Etik test hedefi nmap tarama sunucusu
        target = "scanme.nmap.org"
        print(f"[i] Hedef belirtilmedi. Varsayilan etik test hedefi kullaniliyor: {target}")
        print("[i] Kullanım: python scanner.py <hedef_domain_veya_ip>\n")

    scanner = PySecRecon(target)
    scanner.run_port_scan()
    scanner.check_http_security_headers()
    scanner.check_ssl_expiry()

    print("\n" + "=" * 65)
    print("[+] Kesif ve guvenlik on degerlendirmesi tamamlandi.")
    print("=" * 65)
