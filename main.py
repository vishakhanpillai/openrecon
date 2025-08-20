import socket
import whois
import requests
import tldextract
import dns.resolver

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


if __name__ == "__main__":
    main()
