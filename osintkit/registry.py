"""Rejestr narzędzi – wspólny dla CLI i GUI."""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable

from .modules import dnsinfo, domain, emailinfo, exif, ipinfo, sslcert, subdomains, username, web, whois
from .report import Report
from .utils import Progress


@dataclass(frozen=True)
class Tool:
    key: str
    label: str
    short: str
    description: str
    placeholder: str
    icon: str
    run: Callable[..., Report]
    input_kind: str = "text"  # "text" lub "file"


TOOLS: list[Tool] = [
    Tool("domain", "Domena – pełny skan", "Domena",
         "DNS, WHOIS, certyfikat, strona WWW, hosting i subdomeny – wszystko naraz.",
         "example.com", "◆", domain.full_scan),
    Tool("username", "Nazwa użytkownika", "Użytkownik",
         f"Sprawdza, w których z {len(username.SITES)} serwisów istnieje konto o tej nazwie.",
         "johndoe", "☺", username.search),
    Tool("email", "Adres e-mail", "E-mail",
         "Walidacja, serwery MX, dostawca poczty, SPF/DMARC, profil Gravatar.",
         "jan.kowalski@example.com", "@", emailinfo.lookup),
    Tool("ip", "Adres IP", "IP",
         "Geolokalizacja, dostawca, ASN, rekord PTR, otwarte porty (Shodan), właściciel sieci.",
         "8.8.8.8", "◎", ipinfo.lookup),
    Tool("web", "Strona WWW", "WWW",
         "Nagłówki, technologie, bezpieczeństwo, kontakty, ID śledzące, robots.txt, archiwum.",
         "https://example.com", "⊕", web.analyze),
    Tool("dns", "Rekordy DNS", "DNS",
         "A, AAAA, MX, NS, TXT, SOA, CAA oraz SPF/DMARC i usługi wykryte w TXT.",
         "example.com", "≡", dnsinfo.lookup),
    Tool("whois", "WHOIS / RDAP", "WHOIS",
         "Rejestrator, daty rejestracji i wygaśnięcia, właściciel domeny lub sieci IP.",
         "example.com lub 1.1.1.1", "¶", whois.lookup),
    Tool("subdomains", "Subdomeny", "Subdomeny",
         "Subdomeny z logów Certificate Transparency i pasywnego DNS, z adresami IP.",
         "example.com", "⋔", subdomains.search),
    Tool("ssl", "Certyfikat SSL", "SSL",
         "Wystawca, ważność, nazwy SAN (powiązane domeny), odcisk palca, protokół.",
         "example.com", "⊡", sslcert.inspect),
    Tool("exif", "Metadane zdjęcia", "EXIF",
         "EXIF, GPS, aparat, daty, XMP – z pliku na dysku lub adresu URL.",
         "C:\\zdjecia\\foto.jpg lub https://…/foto.jpg", "▣", exif.extract, input_kind="file"),
]

BY_KEY = {tool.key: tool for tool in TOOLS}


def run_tool(key: str, target: str, progress: Progress = None) -> Report:
    tool = BY_KEY[key]
    started = time.perf_counter()
    report = tool.run(target, progress=progress)
    report.title = tool.label
    report.duration = time.perf_counter() - started
    return report
