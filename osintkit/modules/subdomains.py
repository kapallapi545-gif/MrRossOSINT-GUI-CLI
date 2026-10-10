"""Subdomeny z pasywnych źródeł (Certificate Transparency, pasywny DNS)."""
from __future__ import annotations

import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..net import NetError, get_json, request
from ..report import MUTED, Report
from ..utils import Progress, normalize_domain, notify

RESOLVE_LIMIT = 600


def from_crtsh(domain: str) -> list[str]:
    resp = request(
        f"https://crt.sh/?q=%25.{domain}&output=json&deduplicate=Y",
        headers={"Accept": "application/json"},
        timeout=45,
        max_bytes=60 * 1024 * 1024,
    )
    if not resp.ok:
        raise NetError(f"HTTP {resp.status}")
    try:
        data = resp.json()
    except ValueError as exc:
        raise NetError("niepoprawna lub zbyt duża odpowiedź") from exc
    names: list[str] = []
    for entry in data:
        names.extend(str(entry.get("name_value", "")).split("\n"))
        names.append(str(entry.get("common_name", "")))
    return names


def from_certspotter(domain: str) -> list[str]:
    data = get_json(
        f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names",
        timeout=25,
    )
    names: list[str] = []
    for issuance in data or []:
        names.extend(issuance.get("dns_names") or [])
    return names


def from_hackertarget(domain: str) -> list[str]:
    resp = request(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=25)
    text = resp.text.strip()
    if not resp.ok or "," not in text:
        raise NetError(text[:80] or f"HTTP {resp.status}")
    return [line.split(",", 1)[0] for line in text.splitlines()]


def from_otx(domain: str) -> list[str]:
    data = get_json(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", timeout=25)
    return [entry.get("hostname", "") for entry in data.get("passive_dns") or []]


SOURCES = {
    "crt.sh": from_crtsh,
    "CertSpotter": from_certspotter,
    "HackerTarget": from_hackertarget,
    "AlienVault OTX": from_otx,
}


def _clean(names: list[str], domain: str) -> set[str]:
    result = set()
    suffix = "." + domain
    for name in names:
        name = name.strip().lower().rstrip(".")
        while name.startswith("*."):
            name = name[2:]
        if name.endswith(suffix) and re.fullmatch(r"[a-z0-9._-]+", name):
            result.add(name)
    return result


def resolve_many(names: list[str], progress: Progress = None, workers: int = 32) -> dict[str, str | None]:
    def resolve_one(name: str) -> tuple[str, str | None]:
        try:
            return name, socket.gethostbyname(name)
        except (OSError, UnicodeError):
            return name, None

    results: dict[str, str | None] = {}
    total = len(names)
    if not total:
        return results
    with ThreadPoolExecutor(workers) as pool:
        futures = [pool.submit(resolve_one, n) for n in names]
        for done, future in enumerate(as_completed(futures), 1):
            name, ip = future.result()
            results[name] = ip
            if done % 10 == 0 or done == total:
                notify(progress, f"Rozwiązywanie adresów: {done}/{total}", done / total)
    return results


def search(target: str, progress: Progress = None) -> Report:
    domain = normalize_domain(target)
    report = Report("subdomains", domain)
    notify(progress, "Przeszukuję logi Certificate Transparency i pasywny DNS…")

    found: dict[str, set[str]] = {}
    errors: list[str] = []
    with ThreadPoolExecutor(len(SOURCES)) as pool:
        futures = {pool.submit(fn, domain): name for name, fn in SOURCES.items()}
        for future in as_completed(futures):
            source = futures[future]
            try:
                names = _clean(future.result(), domain)
            except (NetError, ValueError, AttributeError, TypeError) as exc:
                errors.append(f"{source}: {exc}")
                notify(progress, f"{source}: błąd ({exc})")
                continue
            for name in names:
                found.setdefault(name, set()).add(source)
            notify(progress, f"{source}: {len(names)} subdomen")

    subdomains = sorted(found, key=lambda s: tuple(reversed(s.split("."))))
    to_resolve = subdomains[:RESOLVE_LIMIT]
    ips = resolve_many(to_resolve, progress)

    alive = sum(1 for s in to_resolve if ips.get(s))
    unique_ips = {ip for ip in ips.values() if ip}
    summary = report.section("Podsumowanie")
    summary.add("Domena", domain)
    summary.add("Znalezione subdomeny", len(subdomains))
    summary.add("Aktywne (rozwiązują się)", f"{alive} z {len(to_resolve)}")
    summary.add("Unikalne adresy IP", len(unique_ips))
    summary.add("Źródła", ", ".join(s for s in SOURCES if not any(e.startswith(s + ":") for e in errors)) or "brak")
    if errors:
        summary.add("Niedostępne źródła", "; ".join(errors), MUTED)
    if len(subdomains) > RESOLVE_LIMIT:
        summary.note = f"Rozwiązano tylko pierwsze {RESOLVE_LIMIT} subdomen."

    sec = report.section(f"Subdomeny ({len(subdomains)})").table("Subdomena", "IP", "Źródła")
    for name in subdomains:
        ip = ips.get(name)
        sec.row(name, ip or "—", ", ".join(sorted(found[name])), style=None if ip else MUTED)
    if not subdomains:
        sec.note = "Nie znaleziono subdomen w źródłach pasywnych."
    return report
