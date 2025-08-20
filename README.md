# Website Enumerator (Passive Recon Tool)

A Python-based passive website enumeration tool that gathers publicly available information about a domain.  
Designed for **learning and ethical reconnaissance** purposes.

---

## Features

- ✅ **Domain Validation** – Ensures input is a valid domain before enumeration.
- ✅ **IP Address Lookup** – Retrieves the IPv4 address of the domain.
- ✅ **HTTP Headers** – Fetches headers to see server and technology info.
- ✅ **WHOIS Lookup** – Provides registrar, creation/expiration dates, and name servers.
- ✅ **robots.txt Fetch** – Displays publicly available robots.txt paths.
- ✅ **DNS Records Enumeration** – Fetches:
  - A (IPv4 addresses)
  - AAAA (IPv6 addresses)
  - MX (Mail servers)
  - NS (Name servers)
  - TXT (Text records, SPF/DKIM/verification)

---

## ⚡ Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/website-enumerator.git
cd website-enumerator
```
2. Install required Python packages
```bash
pip install -r requirements.txt
```
3. Run the Script
```bash
python main.py
```
