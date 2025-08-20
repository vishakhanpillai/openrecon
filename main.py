import socket
import whois
import requests
import tldextract
import dns.resolver
import ssl
from datetime import datetime, timezone
import builtwith

def is_valid_domain(domain):
    ext = tldextract.extract(domain)
    if(ext.domain and ext.suffix):
        return True, ext.top_domain_under_public_suffix
    else:
        return False, None
    

def get_ip_address(domain):
    try:
        ip = socket.gethostbyname(domain)
        # print(f"[+] IP Address of {domain}: {ip}")
        return ip
    except Exception  as e:
        print(f"[+] Could not find IP Address {e}")


def get_http_headers(domain):
    try:
        response = requests.get(f"https://{domain}", timeout=5)
        print("\n[+] HTTP Headers:")
        for header, value in response.headers.items():
            print(f"    {header}: {value}")
    except Exception as e:
        print(f"[!] Could not fetch headers: {e}")


def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        print("\n[+] WHOIS Information:")
        registrar = w.registrar if w.registrar else "Unknown or Hidden"
        print(f"    Domain Name: {w.domain_name}")
        print(f"    Registrar: {registrar}")
        print(f"    Creation Date: {w.creation_date}")
        print(f"    Expiration Date: {w.expiration_date}")
        print(f"    Name Servers: {w.name_servers}")
    except Exception as e:
        print(f"[!] Could not fetch WHOIS: {e}")


def get_robots(domain):

    try:
        url = f"https://{domain}/robots.txt"

        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            for line in response.text.splitlines():
                print(f"    {line}")
        else:
            return "[!] No robots.txt found"
    except Exception as e:
        print(f"[!] Error Fetching robots.txt: {e}")


def get_dns_records(domain):
    print("\n[+] DNS Records:\n[A] - IPV4 [AAAA] - IPV6 [MX] - Mail Exchanger [NS] - Name Server [TXT] - Arbitraty Text Records")
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']

    for rtype in record_types:
        try:
            answer = dns.resolver.resolve(domain, rtype)
            for rdata in answer:
                print(f" {rtype}: {rdata}")
        except Exception as e:
            print(f"    {rtype}: No record found")

def get_ssl_info(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()

        exp_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        exp_date = exp_date.replace(tzinfo=timezone.utc)  # make it timezone-aware
        remaining = exp_date - datetime.now(timezone.utc)

        print("\n[+] SSL Certificate Information:")
        print(f"    Issuer       : {dict(x[0] for x in cert['issuer'])['organizationName']}")
        print(f"    Subject      : {dict(x[0] for x in cert['subject'])['commonName']}")
        print(f"    Expiration   : {exp_date}")
        print(f"    Days Left    : {remaining.days}")
    except Exception as e:
        print(f"[!] Could not fetch SSL certificate: {e}")

def get_technologies_used(domain):
    try:
        print("\n[+] Technology Fingerprinting (BuiltWith):")
        tech = builtwith.parse(f"https://{domain}")
        for category, technologies in tech.items():
            print(f"    {category}: {', '.join(technologies)}")
    except Exception as e:
        print(f"[!] Could not fingerprint technologies: {e}")

def get_sub_domains(domain):
    try:
        sub = ['ftp', 'www', 'blog', 'test', 'dev', 'api']
        found = []

        for i in sub:
            subdomain = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(subdomain)
                print(f"    {subdomain} -> {ip}")
                found.append(subdomain)
            except socket.gaierror:
                continue
        
        if not found:
            print("    [!] No Common subdomains found")
    except Exception as e:
        print(e)
    
def main():
    raw_domain = input("Enter the domain Name(eg. website.com ): ")
    valid, domain = is_valid_domain(raw_domain)

    if not valid:
        print(f"[!] Invalid domain format. Example: example.com or sub.example.org")
        return
    print(f"[!] Valid Domain: {domain}")

    print(f"\n[+] Fetching IP Address of the domain {domain}")
    ip = get_ip_address(domain)
    print(f"\n[!] IP Address of the domain: {ip}")

    print(f"\n[+] Fetching HTTP Headers of the domain {domain}")
    get_http_headers(domain)

    print(f"\n[+] WHOIS Lookup")
    whois_lookup(domain)

    print(f"\n[+] Fetching Contents of Robots.txt")
    get_robots(domain)

    print(f"\n[+] Fetching DNS Records")
    get_dns_records(domain)

    print(f"\n[+] Fetching SSL Certificate Details")
    get_ssl_info(domain)

    print(f"\n[+]Fetching Technologies Used")
    get_technologies_used(domain)

    print(f"\n[+]Subdomain Enumeration")
    get_sub_domains(domain)

if __name__ == "__main__":
    main()
