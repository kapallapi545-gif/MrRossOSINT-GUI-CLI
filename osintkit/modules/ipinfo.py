"""Adres IP: geolokalizacja, rekord PTR, Shodan InternetDB i właściciel sieci."""
from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor

from ..net import NetError, dns_query, get_json, request
from ..report import BAD, MUTED, OK, WARN, Report, Section
from ..utils import Progress, is_ip, normalize_domain, notify
from . import whois


def resolve(target: str) -> tuple[str, str | None]:
    """Zwraca (ip, host). Dla nazwy domenowej rozwiązuje ją do pierwszego adresu (IPv4 preferowany)."""
    value = target.strip().strip("[]")
    if is_ip(value):
        return str(ipaddress.ip_address(value)), None
    host = normalize_domain(value)
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError):
        raise ValueError(f"Nie można rozwiązać nazwy {host}.") from None
    addresses = sorted({info[4][0] for info in infos}, key=lambda a: (":" in a, a))
    return addresses[0], host


def classify(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> tuple[str, bool]:
    if addr.is_loopback:
        return "loopback (ten komputer)", False
    if addr.is_link_local:
        return "link-local", False
    if addr.is_private:
        return "prywatny (sieć lokalna)", False
    if addr.is_multicast:
        return "multicast", False
    if addr.is_reserved or addr.is_unspecified:
        return "zarezerwowany", False
    if not addr.is_global:
        return "specjalny / niepubliczny", False
    return "publiczny", True


def reverse_dns(ip: str) -> list[str]:
    return dns_query(ipaddress.ip_address(ip).reverse_pointer, "PTR")


def geolocate(ip: str) -> dict:
    """Geolokalizacja z ip-api.com, zapasowo ipwho.is."""
    try:
        data = get_json(
            f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,zip,"
            "lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting",
            timeout=8,
        )
        if data.get("status") == "success":
            return {
                "country": data.get("country"), "country_code": data.get("countryCode"),
                "region": data.get("regionName"), "city": data.get("city"), "zip": data.get("zip"),
                "lat": data.get("lat"), "lon": data.get("lon"), "timezone": data.get("timezone"),
                "isp": data.get("isp"), "org": data.get("org"), "asn": data.get("as"),
                "mobile": data.get("mobile"), "proxy": data.get("proxy"), "hosting": data.get("hosting"),
                "source": "ip-api.com",
            }
    except NetError:
        pass
    data = get_json(f"https://ipwho.is/{ip}", timeout=8)
    if not data.get("success"):
        raise NetError(data.get("message") or "brak danych geolokalizacji")
    conn = data.get("connection") or {}
    asn = conn.get("asn")
    return {
        "country": data.get("country"), "country_code": data.get("country_code"),
        "region": data.get("region"), "city": data.get("city"), "zip": data.get("postal"),
        "lat": data.get("latitude"), "lon": data.get("longitude"),
        "timezone": (data.get("timezone") or {}).get("id"),
        "isp": conn.get("isp"), "org": conn.get("org"),
        "asn": f"AS{asn} {conn.get('org') or ''}".strip() if asn else None,
        "source": "ipwho.is",
    }


def internetdb(ip: str) -> dict | None:
    resp = request(f"https://internetdb.shodan.io/{ip}", headers={"Accept": "application/json"}, timeout=10)
    if resp.status == 404:
        return None
    if not resp.ok:
        raise NetError(f"HTTP {resp.status}")
    return resp.json()


def geo_section(report: Report, geo: dict, title: str = "Geolokalizacja") -> Section:
    sec = report.section(title)
    place = ", ".join(p for p in (geo.get("city"), geo.get("region"), geo.get("country")) if p)
    sec.add("Lokalizacja", place)
    sec.add("Kod kraju", geo.get("country_code"))
    sec.add("Kod pocztowy", geo.get("zip"))
    lat, lon = geo.get("lat"), geo.get("lon")
    if lat is not None and lon is not None:
        sec.add("Współrzędne", f"{lat}, {lon}")
        sec.add("Mapa", f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=11/{lat}/{lon}")
    sec.add("Strefa czasowa", geo.get("timezone"))
    sec.add("Dostawca (ISP)", geo.get("isp"))
    sec.add("Organizacja", geo.get("org"))
    sec.add("ASN", geo.get("asn"))
    traits = []
    if geo.get("hosting"):
        traits.append("hosting / centrum danych")
    if geo.get("proxy"):
        traits.append("proxy / VPN / Tor")
    if geo.get("mobile"):
        traits.append("sieć komórkowa")
    if traits:
        sec.add("Charakter adresu", traits, WARN if geo.get("proxy") else None)
    sec.add("Źródło", geo.get("source"), MUTED)
    sec.note = "Geolokalizacja IP jest przybliżona – zwykle wskazuje miasto lub region dostawcy, nie konkretny adres."
    return sec


def shodan_section(report: Report, data: dict | None) -> Section:
    sec = report.section("Shodan InternetDB (dane pasywne)")
    if not data:
        sec.note = "Brak danych – Shodan nie skanował tego adresu."
        return sec
    ports = sorted(data.get("ports") or [])
    sec.add("Otwarte porty", ", ".join(map(str, ports)) if ports else "brak")
    sec.add("Nazwy hostów", data.get("hostnames"))
    sec.add("Tagi", data.get("tags"))
    sec.add("Oprogramowanie (CPE)", data.get("cpes"))
    vulns = sorted(data.get("vulns") or [])
    if vulns:
        shown = ", ".join(vulns[:25]) + (" …" if len(vulns) > 25 else "")
        sec.add("Podatności (CVE)", f"{len(vulns)}: {shown}", BAD)
    return sec


def _outcome(future):
    try:
        return future.result(), None
    except (NetError, ValueError, KeyError) as exc:
        return None, str(exc)


def lookup(target: str, progress: Progress = None) -> Report:
    ip, host = resolve(target)
    addr = ipaddress.ip_address(ip)
    report = Report("ip", target.strip())
    sec = report.section("Adres IP")
    sec.add("Adres", ip)
    if host:
        sec.add("Rozwiązano z", host)
    sec.add("Wersja", f"IPv{addr.version}")
    kind, public = classify(addr)
    sec.add("Typ adresu", kind, OK if public else WARN)
    if not public:
        sec.note = "Adres niepubliczny – zewnętrzne źródła nie mają o nim danych."
        return report

    notify(progress, f"Zbieram informacje o {ip} (PTR, geolokalizacja, Shodan, RDAP)…")
    with ThreadPoolExecutor(4) as pool:
        f_ptr = pool.submit(reverse_dns, ip)
        f_geo = pool.submit(geolocate, ip)
        f_shodan = pool.submit(internetdb, ip)
        f_rdap = pool.submit(whois.rdap, "ip", ip)

    ptr, _ = _outcome(f_ptr)
    sec.add("Rekord PTR", ptr or "brak")

    geo, err = _outcome(f_geo)
    if geo:
        geo_section(report, geo)
    else:
        report.section("Geolokalizacja").error = err

    shodan, err = _outcome(f_shodan)
    if err:
        report.section("Shodan InternetDB (dane pasywne)").error = err
    else:
        shodan_section(report, shodan)

    rdap_data, err = _outcome(f_rdap)
    if rdap_data:
        whois.ip_section(report, rdap_data)
    else:
        report.section("Właściciel sieci (RDAP)").error = err
    return report
