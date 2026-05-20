"""
ROOTIPV6 NetAudit Toolkit
Developed by Ali Rıza Saydan

ROOTIPV6 Security Labs
Licensed under ROOTIPV6 Community License v1.0
"""

import os
import sys

from colorama import Fore, Style

from modules.meta import AUTHOR, LAB, PROJECT_NAME


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def show_banner() -> None:
    banner = r"""
██████╗  ██████╗  ██████╗ ████████╗██╗██████╗ ██╗   ██╗ ██████╗
██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝██║██╔══██╗██║   ██║██╔════╝
██████╔╝██║   ██║██║   ██║   ██║   ██║██████╔╝██║   ██║██║  ███╗
██╔══██╗██║   ██║██║   ██║   ██║   ██║██╔═══╝ ╚██╗ ██╔╝██║   ██║
██║  ██║╚██████╔╝╚██████╔╝   ██║   ██║██║      ╚████╔╝ ╚██████╔╝
╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   ╚═╝╚═╝       ╚═══╝   ╚═════╝

        NetAudit Toolkit
"""
    print(Fore.CYAN + Style.BRIGHT + banner + Style.RESET_ALL)
    print(Fore.WHITE + f"  Developed by {AUTHOR}" + Style.RESET_ALL)
    print(Fore.WHITE + f"  {LAB}" + Style.RESET_ALL)
    print(
        Fore.YELLOW
        + "  [!] Yalnızca izinli sistemlerde ve audit/test amacıyla kullanın."
        + Style.RESET_ALL
    )
    print()


def placeholder_message() -> None:
    print(Fore.YELLOW + "\n  [*] Bu modül yakında eklenecek." + Style.RESET_ALL)


def pause() -> None:
    try:
        input(
            Fore.WHITE + "\nAna menüye dönmek için Enter'a basın..." + Style.RESET_ALL
        )
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
