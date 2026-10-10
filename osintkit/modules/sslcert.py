"""Certyfikat SSL/TLS: wystawca, ważność, nazwy SAN, odcisk palca."""
from __future__ import annotations

import hashlib
import os
import socket
import ssl
import tempfile
import urllib.parse
from datetime import datetime, timezone

from ..net import NetError, describe_error
from ..report import BAD, OK, WARN, Report
from ..utils import Progress, is_ip, normalize_domain, notify

# Wystawcy używani przez antywirusy i proxy, które przechwytują HTTPS na komputerze użytkownika
INTERCEPTORS = ("Avast", "AVG", "Kaspersky", "ESET", "Bitdefender", "Norton", "McAfee", "Sophos",
                "Fortinet", "FortiGate", "Zscaler", "Netskope", "Palo Alto", "Cisco Umbrella",
                "Blue Coat", "Forcepoint", "WatchGuard", "Check Point", "Fiddler", "mitmproxy", "Charles Proxy",
                "Burp")


def _target(target: str) -> tuple[str, int]:
    raw = target.strip()
    if "://" not in raw:
        raw = "https://" + raw
    parts = urllib.parse.urlsplit(raw)
    if not parts.hostname:
        raise ValueError(f"Niepoprawny adres: {target}")
    try:
        port = parts.port or 443
    except ValueError:
        raise ValueError("Niepoprawny numer portu.") from None
    host = parts.hostname if is_ip(parts.hostname) else normalize_domain(parts.hostname)
    return host, port


def _decode_der(der: bytes) -> dict:
    """Dekoduje certyfikat bez weryfikacji (wewnętrzne API CPythona, bez zależności)."""
    pem = ssl.DER_cert_to_PEM_cert(der)
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(pem)
        return ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
    except Exception:
        return {}
    finally:
        os.unlink(path)


def fetch(host: str, port: int = 443, timeout: float = 10.0) -> dict:
    def connect(ctx: ssl.SSLContext) -> dict:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                return {
                    "der": tls.getpeercert(binary_form=True) or b"",
                    "cert": tls.getpeercert() or {},
                    "protocol": tls.version(),
                    "cipher": tls.cipher(),
                }

    try:
        info = connect(ssl.create_default_context())
        info["verified"] = True
    except ssl.SSLCertVerificationError as exc:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            info = connect(ctx)
        except OSError as exc2:
            raise NetError(describe_error(exc2)) from exc2
        info["verified"] = False
        info["verify_error"] = exc.verify_message or str(exc)
        info["cert"] = _decode_der(info["der"]) if info["der"] else {}
    except OSError as exc:
        raise NetError(describe_error(exc)) from exc
    return info


def _name(rdns) -> dict[str, str]:
    out: dict[str, str] = {}
    for rdn in rdns or ():
        for key, value in rdn:
            out.setdefault(key, value)
    return out


def _cert_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), timezone.utc)
    except (ValueError, OverflowError):
        return None


def inspect(target: str, progress: Progress = None) -> Report:
    host, port = _target(target)
    report = Report("ssl", host if port == 443 else f"{host}:{port}")
    notify(progress, f"Łączę się z {host}:{port}…")
    info = fetch(host, port)
    cert, der = info.get("cert") or {}, info.get("der") or b""

    sec = report.section("Certyfikat SSL/TLS")
    if info["verified"]:
        sec.add("Weryfikacja", "poprawny – zaufany łańcuch i zgodna nazwa", OK)
    else:
        sec.add("Weryfikacja", f"NIEPOPRAWNY: {info.get('verify_error')}", BAD)

    subject, issuer = _name(cert.get("subject")), _name(cert.get("issuer"))
    sec.add("Podmiot (CN)", subject.get("commonName"))
    sec.add("Organizacja", subject.get("organizationName"))
    location = ", ".join(
        v for v in (subject.get("localityName"), subject.get("stateOrProvinceName"), subject.get("countryName")) if v
    )
    sec.add("Lokalizacja", location)
    sec.add("Typ walidacji", "OV/EV – zweryfikowana organizacja" if subject.get("organizationName") else "DV – tylko domena")
    issuer_text = issuer.get("commonName", "")
    if issuer.get("organizationName"):
        issuer_text += f" ({issuer['organizationName']})"
    sec.add("Wystawca", issuer_text)
    interceptor = next((name for name in INTERCEPTORS if name.lower() in issuer_text.lower()), None)
    if interceptor:
        sec.note = (f"Połączenie przechwytuje {interceptor} (antywirus/proxy na tym komputerze lub w sieci) – "
                    "to NIE jest prawdziwy certyfikat serwera. Wyłącz skanowanie HTTPS, aby zobaczyć oryginał.")
        sec.add("Przechwycenie TLS", interceptor, WARN)
    if subject and subject == issuer:
        sec.add("Uwaga", "certyfikat samopodpisany", WARN)

    not_before, not_after = _cert_time(cert.get("notBefore")), _cert_time(cert.get("notAfter"))
    if not_before:
        sec.add("Ważny od", f"{not_before:%Y-%m-%d}")
    if not_after:
        days = (not_after - datetime.now(timezone.utc)).days
        if days < 0:
            sec.add("Ważny do", f"{not_after:%Y-%m-%d} (wygasł {-days} dni temu)", BAD)
        elif days < 14:
            sec.add("Ważny do", f"{not_after:%Y-%m-%d} (zostało {days} dni)", WARN)
        else:
            sec.add("Ważny do", f"{not_after:%Y-%m-%d} (zostało {days} dni)", OK)

    sec.add("Numer seryjny", cert.get("serialNumber"))
    if der:
        digest = hashlib.sha256(der).hexdigest().upper()
        sec.add("SHA-256", ":".join(digest[i:i + 2] for i in range(0, len(digest), 2)))
        sec.add("Wyszukaj certyfikat", f"https://crt.sh/?q={hashlib.sha256(der).hexdigest()}")
    sec.add("Protokół", info.get("protocol"))
    cipher = info.get("cipher")
    if cipher:
        sec.add("Szyfr", f"{cipher[0]} ({cipher[2]} bit)")
    sec.add("OCSP", cert.get("OCSP"))
    sec.add("Wystawca CA (URL)", cert.get("caIssuers"))

    names = [value for kind, value in cert.get("subjectAltName", ()) if kind in ("DNS", "IP Address")]
    san = report.section(f"Nazwy w certyfikacie – SAN ({len(names)})").table("Nazwa")
    for name in names:
        san.row(name)
    if len(names) > 1:
        san.note = "Inne domeny w tym samym certyfikacie zwykle należą do tego samego właściciela."
    return report
