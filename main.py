#!/usr/bin/env python3
"""
ROOTIPV6 NetAudit Toolkit
Developed by Ali Rıza Saydan

ROOTIPV6 Security Labs
Licensed under ROOTIPV6 Community License v1.0
"""

import sys

from colorama import Fore, Style, init

from modules import (
    dns_lookup,
    log_analyzer,
    ping_scanner,
    port_scanner,
    report,
    snmp_collector,
    ssh_failed,
    whois_lookup,
)
from modules.banner import clear_screen, pause, show_banner
from modules.meta import PROJECT_NAME

init(autoreset=True, strip=False, convert=True)

MENU_ITEMS = {
    "1": ("Port Scanner", port_scanner.run),
    "2": ("Ping Scanner", ping_scanner.run),
    "3": ("DNS Lookup", dns_lookup.run),
    "4": ("Whois / IP Info", whois_lookup.run),
    "5": ("Log Analyzer", log_analyzer.run),
    "6": ("SSH Failed Login Detector", ssh_failed.run),
    "7": ("SNMP Device Info Collector", snmp_collector.run),
    "8": ("Raporlama", report.run),
    "9": ("Çıkış", None),
}


def show_menu() -> None:
    print(Fore.CYAN + Style.BRIGHT + "Ana Menü" + Style.RESET_ALL)
    print(Fore.WHITE + "-" * 40 + Style.RESET_ALL)
    for key, (label, _) in MENU_ITEMS.items():
        print(Fore.GREEN + f"  {key}. " + Fore.WHITE + label + Style.RESET_ALL)
    print()


def get_choice() -> str:
    try:
        choice = input(
            Fore.YELLOW + "Yapmak istediğiniz işlem nedir?\n> " + Style.RESET_ALL
        ).strip()
    except (EOFError, KeyboardInterrupt):
        raise KeyboardInterrupt
    return choice


def handle_choice(choice: str) -> bool:
    if choice not in MENU_ITEMS:
        print(
            Fore.RED + "[!] Geçersiz seçim. Lütfen 1-9 arası bir değer girin."
            + Style.RESET_ALL
        )
        return True

    _, handler = MENU_ITEMS[choice]

    if handler is None:
        print(
            Fore.CYAN + Style.BRIGHT + f"\n{PROJECT_NAME} kapatılıyor..."
            + Style.RESET_ALL
        )
        print(Fore.CYAN + "Güvenli testler dileriz." + Style.RESET_ALL)
        return False

    handler()
    pause()
    return True


def main() -> None:
    try:
        while True:
            clear_screen()
            show_banner()
            show_menu()

            choice = get_choice()
            if not choice:
                print(Fore.RED + "[!] Boş seçim yapılamaz." + Style.RESET_ALL)
                pause()
                continue

            if not handle_choice(choice):
                break

    except KeyboardInterrupt:
        print(
            Fore.CYAN + "\n\n[+] Ctrl+C algılandı. Program kapatılıyor..."
            + Style.RESET_ALL
        )
        sys.exit(0)


if __name__ == "__main__":
    main()
