"""
ROOTIPV6 NetAudit Toolkit
Developed by Ali Rıza Saydan

ROOTIPV6 Security Labs
Licensed under ROOTIPV6 Community License v1.0
"""

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from colorama import Fore, Style
from modules.session_store import save as save_session
MAX_PREVIEW_LINES = 10
MAX_LINE_DISPLAY = 200
SUSPICIOUS_RULES: list[tuple[str, list[str]]] = [('FAILED LOGIN', ['login failure', 'authentication failed', 'failed login', 'login failed']), ('BRUTE FORCE', ['brute', 'bruteforce', 'brute-force']), ('PORT SCAN', ['port scan', 'portscan']), ('INTERFACE DOWN', ['interface down', 'link down', 'disconnected']), ('DENIED', ['denied', 'access denied']), ('TIMEOUT', ['timeout', 'timed out']), ('INVALID', ['invalid user', 'invalid login', 'invalid']), ('ERROR', ['error', 'failure', 'failed'])]

@dataclass
class SuspiciousLine:
    line_no: int
    category: str
    text: str

def _categorize_line(line: str) -> str | None:
    lower = line.lower()
    for category, patterns in SUSPICIOUS_RULES:
        if any((pattern in lower for pattern in patterns)):
            return category
    return None

def _read_log_file(path: Path) -> list[str]:
    try:
        with path.open('r', encoding='utf-8', errors='replace') as handle:
            return handle.readlines()
    except UnicodeDecodeError as exc:
        raise ValueError(f'Dosya okunamadı: {path}') from exc

def _analyze_lines(lines: list[str]) -> list[SuspiciousLine]:
    suspicious: list[SuspiciousLine] = []
    for index, raw_line in enumerate(lines, start=1):
        line = raw_line.rstrip('\n\r')
        if not line.strip():
            continue
        category = _categorize_line(line)
        if category:
            suspicious.append(SuspiciousLine(index, category, line))
    return suspicious

def _truncate(text: str, max_len: int=MAX_LINE_DISPLAY) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len - 3] + '...'

def _print_results(total_lines: int, suspicious: list[SuspiciousLine]) -> None:
    print(Fore.CYAN + Style.BRIGHT + '\n' + '=' * 40)
    print('LOG ANALYZER SONUÇLARI')
    print('=' * 40 + Style.RESET_ALL + '\n')
    print(Fore.WHITE + f'Toplam satır: {total_lines}' + Style.RESET_ALL)
    print(Fore.WHITE + f'Şüpheli satır: {len(suspicious)}' + Style.RESET_ALL)
    if not suspicious:
        print(Fore.YELLOW + '\n  Şüpheli olay bulunamadı.' + Style.RESET_ALL)
        return
    counts = Counter((item.category for item in suspicious))
    print()
    for category, count in counts.most_common():
        print(Fore.RED + Style.BRIGHT + f'[{category}] ' + Style.RESET_ALL + Fore.YELLOW + f'{count} adet' + Style.RESET_ALL)
    preview = suspicious[:MAX_PREVIEW_LINES]
    print(Fore.CYAN + Style.BRIGHT + f'\nŞüpheli satırlardan ilk {len(preview)} tanesi:' + Style.RESET_ALL)
    for idx, item in enumerate(preview, start=1):
        print(Fore.GREEN + f'{idx}. [{item.category}] (satır {item.line_no}) ' + Fore.WHITE + _truncate(item.text) + Style.RESET_ALL)

def run() -> None:
    print(Fore.CYAN + Style.BRIGHT + '\n=== Log Analyzer ===' + Style.RESET_ALL)
    path_input = input(Fore.WHITE + 'Analiz etmek istediğiniz log dosyasının yolunu giriniz.\n' + 'Örnek: /var/log/syslog veya mikrotik.log\n> ' + Style.RESET_ALL).strip()
    if not path_input:
        print(Fore.RED + '[!] Dosya yolu boş bırakılamaz.' + Style.RESET_ALL)
        return
    log_path = Path(path_input).expanduser()
    if not log_path.exists():
        print(Fore.RED + f'[!] Dosya bulunamadı: {log_path}' + Style.RESET_ALL)
        return
    if not log_path.is_file():
        print(Fore.RED + f'[!] Geçerli bir dosya değil: {log_path}' + Style.RESET_ALL)
        return
    print(Fore.YELLOW + '\n[*] Log dosyası analiz ediliyor...' + Style.RESET_ALL)
    try:
        lines = _read_log_file(log_path)
    except PermissionError:
        print(Fore.RED + f'[!] Dosyaya erişim izni yok: {log_path}' + Style.RESET_ALL)
        return
    except OSError as exc:
        print(Fore.RED + f'[!] Dosya okunamadı: {exc}' + Style.RESET_ALL)
        return
    except ValueError as exc:
        print(Fore.RED + f'[!] {exc}' + Style.RESET_ALL)
        return
    suspicious = _analyze_lines(lines)
    _print_results(len(lines), suspicious)
    counts = Counter((item.category for item in suspicious))
    save_session('log_analysis', {'file': str(log_path), 'total_lines': len(lines), 'suspicious_count': len(suspicious), 'categories': dict(counts), 'samples': [{'line_no': item.line_no, 'category': item.category, 'text': _truncate(item.text)} for item in suspicious[:MAX_PREVIEW_LINES]]})
    print(Fore.GREEN + '\n[+] Analiz tamamlandı.' + Style.RESET_ALL)
