"""Wspólne funkcje pomocnicze."""
from __future__ import annotations

import ipaddress
import re
import urllib.parse
from typing import Callable, Optional

# Callback postępu: progress(komunikat, ułamek 0..1 lub None)
Progress = Optional[Callable[..., None]]

_HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")

# Etykiety drugiego poziomu, pod którymi rejestruje się domeny (np. bbc.co.uk, firma.com.pl)
_SLD_LABELS = {"co", "com", "net", "org", "edu", "gov", "ac", "or", "ne", "go", "mil", "gob", "nic", "sch", "ltd", "plc"}
_MULTI_SUFFIXES = {
    "waw.pl", "krakow.pl", "wroclaw.pl", "gda.pl", "gdansk.pl", "poznan.pl", "lodz.pl", "szczecin.pl",
    "katowice.pl", "lublin.pl", "bialystok.pl", "torun.pl", "olsztyn.pl", "rzeszow.pl", "opole.pl",
    "kielce.pl", "info.pl", "biz.pl", "priv.pl", "nom.pl", "pc.pl", "media.pl", "art.pl", "sklep.pl",
    "shop.pl", "auto.pl", "tm.pl", "gmina.pl", "powiat.pl", "slask.pl", "pomorze.pl", "mazury.pl",
}


def notify(progress: Progress, message: str, fraction: float | None = None) -> None:
    if progress is not None:
        progress(message, fraction)


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip().strip("[]"))
        return True
    except ValueError:
        return False


def normalize_domain(target: str) -> str:
    """Wyciąga nazwę hosta z dowolnego wejścia: domeny, URL-a lub adresu e-mail."""
    raw = (target or "").strip()
    if not raw:
        raise ValueError("Podaj domenę.")
    if "@" in raw and "://" not in raw:
        raw = raw.rsplit("@", 1)[1]
    if "://" not in raw:
        raw = "http://" + raw
    try:
        host = urllib.parse.urlsplit(raw).hostname or ""
    except ValueError:
        host = ""
    host = host.strip(".").lower()
    if host.startswith("*."):
        host = host[2:]
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError(f"Niepoprawna domena: {target}") from None
    if not _HOST_RE.match(host):
        raise ValueError(f"Niepoprawna domena: {target}")
    return host


def registered_domain(host: str) -> str:
    """Przybliża domenę rejestrowaną u rejestratora (www.sklep.com.pl -> sklep.com.pl)."""
    if is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    last_two = ".".join(labels[-2:])
    if labels[-2] in _SLD_LABELS or last_two in _MULTI_SUFFIXES:
        return ".".join(labels[-3:])
    return last_two


def human_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"
