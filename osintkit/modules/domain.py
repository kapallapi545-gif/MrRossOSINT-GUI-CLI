"""Pełny skan domeny: DNS + WHOIS + SSL + WWW + hosting + subdomeny – równolegle."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from ..net import NetError
from ..report import Report
from ..utils import Progress, normalize_domain, notify
from . import dnsinfo, ipinfo, sslcert, subdomains, web, whois

STEPS = [
    ("DNS", dnsinfo.lookup),
    ("WHOIS", whois.lookup),
    ("Certyfikat SSL", sslcert.inspect),
    ("Strona WWW", web.analyze),
    ("Subdomeny", subdomains.search),
]


def full_scan(target: str, progress: Progress = None) -> Report:
    domain = normalize_domain(target)
    report = Report("domain", domain)
    notify(progress, f"Uruchamiam {len(STEPS)} skanów dla {domain}…", 0.0)

    results: dict[str, Report | Exception] = {}
    with ThreadPoolExecutor(len(STEPS)) as pool:
        futures = {pool.submit(fn, domain): name for name, fn in STEPS}
        for done, future in enumerate(as_completed(futures), 1):
            name = futures[future]
            try:
                results[name] = future.result()
            except (NetError, ValueError, OSError) as exc:
                results[name] = exc
            notify(progress, f"Ukończono: {name} ({done}/{len(STEPS)})", done / len(STEPS))

    for name, _ in STEPS:
        result = results[name]
        if isinstance(result, Report):
            report.merge(result)
        else:
            report.section(name).error = str(result) or type(result).__name__
        if name == "DNS" and isinstance(result, Report):
            _hosting(report, result)
    return report


def _hosting(report: Report, dns_report: Report) -> None:
    """Dodaje informacje o serwerze, na który wskazuje pierwszy rekord A."""
    records = dns_report.sections[0].rows if dns_report.sections else []
    ip = next((value for rtype, value in records if rtype == "A"), None)
    if not ip:
        return
    try:
        ipinfo.geo_section(report, ipinfo.geolocate(ip), title=f"Hosting (IP {ip})")
    except NetError as exc:
        report.section(f"Hosting (IP {ip})").error = str(exc)
