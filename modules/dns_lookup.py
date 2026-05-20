"""
ROOTIPV6 NetAudit Toolkit
Developed by Ali Rıza Saydan

ROOTIPV6 Security Labs
Licensed under ROOTIPV6 Community License v1.0
"""

import re
import dns.exception
import dns.resolver
from colorama import Fore, Style
from modules.session_store import save as save_session
DOMAIN_PATTERN = re.compile('^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}$')
RECORD_MENU = {'1': ('A Kaydı', ['A']), '2': ('MX Kaydı', ['MX']), '3': ('NS Kaydı', ['NS']), '4': ('TXT Kaydı', ['TXT']), '5': ('Tümünü Sorgula', ['A', 'MX', 'NS', 'TXT'])}
DNS_TIMEOUT = 5.0

def _validate_domain(domain: str) -> bool:
    domain = domain.strip().lower()
    return bool(DOMAIN_PATTERN.match(domain))

def _get_resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    return resolver

def _query_a(resolver: dns.resolver.Resolver, domain: str) -> list[str]:
    answers = resolver.resolve(domain, 'A')
    return sorted({str(rdata) for rdata in answers})

def _query_mx(resolver: dns.resolver.Resolver, domain: str) -> list[str]:
    answers = resolver.resolve(domain, 'MX')
    records = sorted(answers, key=lambda r: r.preference)
    return [str(rdata.exchange).rstrip('.') for rdata in records]

def _query_ns(resolver: dns.resolver.Resolver, domain: str) -> list[str]:
    answers = resolver.resolve(domain, 'NS')
    return sorted((str(rdata).rstrip('.') for rdata in answers))

def _query_txt(resolver: dns.resolver.Resolver, domain: str) -> list[str]:
    answers = resolver.resolve(domain, 'TXT')
    results: list[str] = []
    for rdata in answers:
        parts = rdata.strings if hasattr(rdata, 'strings') else [bytes(rdata)]
        text = ''.join((part.decode('utf-8') if isinstance(part, bytes) else str(part) for part in parts))
        results.append(text)
    return results

def _query_record(resolver: dns.resolver.Resolver, domain: str, record_type: str) -> tuple[list[str] | None, str | None]:
    query_funcs = {'A': _query_a, 'MX': _query_mx, 'NS': _query_ns, 'TXT': _query_txt}
    try:
        return (query_funcs[record_type](resolver, domain), None)
    except dns.resolver.NXDOMAIN:
        return (None, 'Domain bulunamadı (NXDOMAIN).')
    except dns.resolver.NoAnswer:
        return ([], None)
    except dns.resolver.NoNameservers:
        return (None, 'Nameserver yanıt vermedi.')
    except dns.resolver.Timeout:
        return (None, 'DNS sorgusu zaman aşımına uğradı.')
    except dns.exception.DNSException as exc:
        return (None, f'DNS hatası: {exc}')

def _print_section(record_type: str, records: list[str] | None, error: str | None) -> None:
    print(Fore.CYAN + Style.BRIGHT + f'\n[{record_type}]' + Style.RESET_ALL)
    if error:
        print(Fore.RED + f'  [!] {error}' + Style.RESET_ALL)
        return
    if not records:
        print(Fore.YELLOW + '  Kayıt bulunamadı.' + Style.RESET_ALL)
        return
    for record in records:
        print(Fore.GREEN + record + Style.RESET_ALL)

def _show_record_menu() -> None:
    print(Fore.WHITE + '\nHangi DNS kayıtlarını sorgulamak istiyorsunuz?\n' + Style.RESET_ALL)
    for key, (label, _) in RECORD_MENU.items():
        print(Fore.GREEN + f'  {key}. ' + Fore.WHITE + label + Style.RESET_ALL)
    print()

def run() -> None:
    print(Fore.CYAN + Style.BRIGHT + '\n=== DNS Lookup ===' + Style.RESET_ALL)
    domain_input = input(Fore.WHITE + 'DNS sorgusu yapmak istediğiniz domain adresini giriniz.\n' + 'Örnek: google.com\n> ' + Style.RESET_ALL).strip().lower()
    if not domain_input:
        print(Fore.RED + '[!] Domain adresi boş bırakılamaz.' + Style.RESET_ALL)
        return
    if not _validate_domain(domain_input):
        print(Fore.RED + f'[!] Geçersiz domain formatı: {domain_input}' + Style.RESET_ALL)
        return
    _show_record_menu()
    choice = input(Fore.YELLOW + 'Seçiminiz:\n> ' + Style.RESET_ALL).strip()
    if not choice:
        print(Fore.RED + '[!] Seçim boş bırakılamaz.' + Style.RESET_ALL)
        return
    if choice not in RECORD_MENU:
        print(Fore.RED + '[!] Geçersiz seçim. Lütfen 1-5 arası bir değer girin.' + Style.RESET_ALL)
        return
    _, record_types = RECORD_MENU[choice]
    resolver = _get_resolver()
    print(Fore.YELLOW + '\n[*] DNS sorgusu yapılıyor...' + Style.RESET_ALL)
    print(Fore.CYAN + Style.BRIGHT + '\n' + '=' * 40)
    print('DNS LOOKUP SONUÇLARI')
    print('=' * 40 + Style.RESET_ALL)
    print(Fore.WHITE + f'\nDomain: {domain_input}' + Style.RESET_ALL)
    dns_results: dict[str, dict[str, list[str] | str | None]] = {}
    for record_type in record_types:
        records, error = _query_record(resolver, domain_input, record_type)
        dns_results[record_type] = {'records': records, 'error': error}
        _print_section(record_type, records, error)
    save_session('dns_lookup', {'domain': domain_input, 'results': dns_results})
    print(Fore.GREEN + '\n[+] DNS sorgusu tamamlandı.' + Style.RESET_ALL)
