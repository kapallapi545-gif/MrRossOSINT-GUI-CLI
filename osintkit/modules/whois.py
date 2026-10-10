"""WHOIS / RDAP dla domen i adresów IP."""
from __future__ import annotations

import re
import socket
from datetime import datetime, timezone

from ..net import NetError, describe_error, request
from ..report import BAD, OK, WARN, Report, Section
from ..utils import Progress, is_ip, normalize_domain, notify, registered_domain

RDAP_BOOTSTRAP = "https://rdap.org"

ROLE_LABELS = {
    "registrant": "Właściciel",
    "administrative": "Kontakt administracyjny",
    "technical": "Kontakt techniczny",
    "abuse": "Kontakt abuse",
}


# --- RDAP ---------------------------------------------------------------------

def rdap(kind: str, query: str, timeout: float = 15.0) -> dict:
    resp = request(
        f"{RDAP_BOOTSTRAP}/{kind}/{query}",
        headers={"Accept": "application/rdap+json, application/json"},
        timeout=timeout,
    )
    if resp.status == 404:
        raise NetError("brak danych RDAP dla tego obiektu")
    if not resp.ok:
        raise NetError(f"RDAP: HTTP {resp.status}")
    try:
        return resp.json()
    except ValueError as exc:
        raise NetError("RDAP: niepoprawna odpowiedź") from exc


def _flatten(items):
    for item in items:
        if isinstance(item, list):
            yield from _flatten(item)
        elif item:
            yield str(item)


def _vcard(entity: dict) -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        items = entity["vcardArray"][1]
    except (KeyError, IndexError, TypeError):
        return result
    for item in items:
        if not isinstance(item, list) or len(item) < 4:
            continue
        name = item[0]
        params = item[1] if isinstance(item[1], dict) else {}
        value = item[3]
        if name == "adr" and params.get("label"):
            value = params["label"]
        if isinstance(value, list):
            value = ", ".join(_flatten(value))
        value = str(value).replace("\n", ", ").strip()
        if value.startswith(("tel:", "mailto:")):
            value = value.split(":", 1)[1]
        if value and name not in result:
            result[name] = value
    return result


def _entities(entities, depth: int = 0):
    for entity in entities or []:
        if isinstance(entity, dict):
            yield entity
            if depth < 3:
                yield from _entities(entity.get("entities"), depth + 1)


def _contacts(sec: Section, entities) -> None:
    seen = set()
    for entity in _entities(entities):
        roles = entity.get("roles") or []
        card = _vcard(entity)
        name = card.get("fn") or card.get("org") or entity.get("handle") or ""
        if "registrar" in roles:
            iana = next(
                (p.get("identifier") for p in entity.get("publicIds") or [] if "IANA" in str(p.get("type", ""))),
                None,
            )
            label = name + (f" (IANA ID {iana})" if iana else "")
            if ("registrar", label) not in seen:
                seen.add(("registrar", label))
                sec.add("Rejestrator", label)
        for role in roles:
            if role not in ROLE_LABELS:
                continue
            org = card.get("org") if card.get("org") != name else None
            parts = [name, org, card.get("email"), card.get("tel"), card.get("adr")]
            value = " · ".join(p for p in parts if p)
            if value and (role, value) not in seen:
                seen.add((role, value))
                sec.add(ROLE_LABELS[role], value)


# --- daty -------------------------------------------------------------------

def parse_date(value: str) -> datetime | None:
    value = (value or "").strip()
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt
    except ValueError:
        pass
    match = re.search(r"(\d{4})[-./](\d{1,2})[-./](\d{1,2})", value)
    if match:
        try:
            return datetime(*map(int, match.groups()))
        except ValueError:
            return None
    match = re.search(r"(\d{1,2})[-./](\d{1,2})[-./](\d{4})", value)
    if match:
        day, month, year = map(int, match.groups())
        try:
            return datetime(year, month, day)
        except ValueError:
            return None
    return None


def _days_from_today(dt: datetime) -> int:
    return (dt.date() - datetime.now(timezone.utc).date()).days


def add_date(sec: Section, label: str, raw: str) -> None:
    dt = parse_date(raw)
    sec.add(label, dt.strftime("%Y-%m-%d") if dt else raw)


def add_registration(sec: Section, raw: str) -> None:
    dt = parse_date(raw)
    if not dt:
        sec.add("Zarejestrowano", raw)
        return
    age = -_days_from_today(dt)
    sec.add("Zarejestrowano", dt.strftime("%Y-%m-%d"))
    if age < 90:
        sec.add("Wiek domeny", f"{age} dni – bardzo świeża domena", WARN)
    else:
        sec.add("Wiek domeny", f"{age} dni (~{age / 365.25:.1f} lat)")


def add_expiry(sec: Section, raw: str) -> None:
    dt = parse_date(raw)
    if not dt:
        sec.add("Wygasa", raw)
        return
    days = _days_from_today(dt)
    if days < 0:
        sec.add("Wygasa", f"{dt:%Y-%m-%d} (wygasła {-days} dni temu)", BAD)
    elif days < 30:
        sec.add("Wygasa", f"{dt:%Y-%m-%d} (za {days} dni)", WARN)
    else:
        sec.add("Wygasa", f"{dt:%Y-%m-%d} (za {days} dni)")


# --- sekcje RDAP ----------------------------------------------------------------

def domain_section(report: Report, data: dict) -> Section:
    sec = report.section("WHOIS (RDAP)")
    sec.add("Domena", (data.get("ldhName") or "").lower())
    for event in data.get("events") or []:
        action, date = event.get("eventAction"), event.get("eventDate", "")
        if action == "registration":
            add_registration(sec, date)
        elif action == "expiration":
            add_expiry(sec, date)
        elif action == "last changed":
            add_date(sec, "Ostatnia zmiana", date)
    sec.add("Status", data.get("status"))
    nameservers = [ns.get("ldhName", "").lower() for ns in data.get("nameservers") or [] if ns.get("ldhName")]
    sec.add("Serwery nazw", nameservers)
    signed = (data.get("secureDNS") or {}).get("delegationSigned")
    if signed is not None:
        sec.add("DNSSEC", "włączony" if signed else "wyłączony", OK if signed else None)
    _contacts(sec, data.get("entities"))
    sec.add("Serwer WHOIS", data.get("port43"))
    return sec


def ip_section(report: Report, data: dict) -> Section:
    sec = report.section("Właściciel sieci (RDAP)")
    sec.add("Nazwa sieci", data.get("name"))
    sec.add("Identyfikator", data.get("handle"))
    start, end = data.get("startAddress"), data.get("endAddress")
    if start and end:
        sec.add("Zakres adresów", f"{start} – {end}")
    cidrs = [
        f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}"
        for c in data.get("cidr0_cidrs") or []
        if c.get("v4prefix") or c.get("v6prefix")
    ]
    sec.add("CIDR", cidrs)
    sec.add("Typ przydziału", data.get("type"))
    sec.add("Kraj", data.get("country"))
    for event in data.get("events") or []:
        if event.get("eventAction") == "registration":
            add_date(sec, "Zarejestrowano", event.get("eventDate", ""))
        elif event.get("eventAction") == "last changed":
            add_date(sec, "Ostatnia zmiana", event.get("eventDate", ""))
    remarks = []
    for remark in data.get("remarks") or []:
        remarks.extend(str(d) for d in remark.get("description") or [])
    if remarks:
        text = " ".join(remarks)
        sec.add("Opis", text[:240] + ("…" if len(text) > 240 else ""))
    _contacts(sec, data.get("entities"))
    sec.add("Serwer WHOIS", data.get("port43"))
    return sec


# --- klasyczny WHOIS (port 43) -------------------------------------------------

def whois_query(query: str, server: str, timeout: float = 10.0) -> str:
    chunks: list[bytes] = []
    try:
        with socket.create_connection((server, 43), timeout=timeout) as sock:
            sock.sendall(query.encode("utf-8") + b"\r\n")
            total = 0
            while total < 1_000_000:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
    except OSError as exc:
        raise NetError(f"WHOIS {server}: {describe_error(exc)}") from exc
    raw = b"".join(chunks)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def raw_whois(domain: str) -> tuple[str, str]:
    tld = domain.rsplit(".", 1)[-1]
    iana = whois_query(tld, "whois.iana.org")
    match = re.search(r"^(?:refer|whois):\s*(\S+)", iana, re.M | re.I)
    if not match:
        raise NetError(f"brak serwera WHOIS dla domeny .{tld}")
    server = match.group(1)
    query = f"-T dn,ace {domain}" if server == "whois.denic.de" else domain
    text = whois_query(query, server)

    referral = re.search(r"Registrar WHOIS Server:\s*(\S+)", text, re.I)
    if referral:
        ref_server = re.sub(r"^\w+://", "", referral.group(1)).strip("/")
        if ref_server and ref_server.lower() != server.lower():
            try:
                detailed = whois_query(domain, ref_server)
                if len(detailed.strip()) > 200:
                    return ref_server, detailed
            except NetError:
                pass
    return server, text


_WHOIS_FIELDS = [
    ("Rejestrator", r"(?:registrar|sponsoring registrar|registrar name)"),
    ("Zarejestrowano", r"(?:creation date|created(?: on| date)?|registered(?: on)?|registration (?:date|time)|domain registration date)"),
    ("Wygasa", r"(?:registry expiry date|registrar registration expiration date|expiration date|expiry date|expires(?: on)?|expire|paid-till|renewal date|expiration time)"),
    ("Ostatnia zmiana", r"(?:updated date|last[ -]modified|last updated|changed|modified)"),
    ("Właściciel", r"(?:registrant(?: name| organi[sz]ation)?|holder)"),
    ("Kraj właściciela", r"(?:registrant country)"),
    ("Abuse e-mail", r"(?:registrar abuse contact email)"),
    ("Status", r"(?:domain status|status)"),
]


def _nameservers(text: str) -> list[str]:
    found: list[str] = []
    in_block = False
    for line in text.splitlines():
        match = re.match(r"^\s*(?:name server|nserver|nameservers?|name servers?)\s*:\s*(\S*)", line, re.I)
        if match:
            in_block = True
            if match.group(1):
                found.append(match.group(1))
            continue
        if in_block:
            cont = re.match(r"^\s+([a-z0-9.-]+\.[a-z]{2,}\.?)(?:\s|$)", line, re.I)
            if cont and ":" not in line.split("[")[0]:
                found.append(cont.group(1))
                continue
            in_block = False
    unique: list[str] = []
    for ns in found:
        ns = ns.lower().rstrip(".")
        if ns and ns not in unique:
            unique.append(ns)
    return unique


def parse_whois(text: str) -> list[tuple[str, object]]:
    out: list[tuple[str, object]] = []
    for label, keys in _WHOIS_FIELDS:
        rx = re.compile(rf"^[ \t]*{keys}[ \t]*:[ \t]*(\S.*)$", re.I | re.M)
        values: list[str] = []
        for match in rx.finditer(text):
            value = match.group(1).strip()
            if label == "Status":
                value = value.split()[0]
            if value and value not in values:
                values.append(value)
        if label == "Rejestrator" and not values:
            match = re.search(r"^REGISTRAR:\s*\n\s*(\S.*)$", text, re.M)
            if match:
                values.append(match.group(1).strip())
        if values:
            out.append((label, values if label == "Status" else values[0]))
    ns = _nameservers(text)
    if ns:
        out.append(("Serwery nazw", ns))
    return out


def _trim_raw(text: str, limit: int = 80) -> str:
    stop = (">>>", "NOTICE:", "TERMS OF USE", "The Registry database contains", "URL of the ICANN Whois",
            "For more information on Whois status")
    lines: list[str] = []
    for line in text.splitlines():
        stripped = line.rstrip()
        if stripped.lstrip().startswith(stop):
            break
        if stripped.startswith(("%", "#")):
            continue
        if not stripped and (not lines or not lines[-1]):
            continue
        lines.append(stripped)
    if len(lines) > limit:
        lines = lines[:limit] + ["…"]
    return "\n".join(lines).strip()


# --- punkt wejścia ---------------------------------------------------------------

def lookup(target: str, progress: Progress = None) -> Report:
    value = target.strip().strip("[]")
    if is_ip(value):
        report = Report("whois", value)
        notify(progress, f"Pobieram dane RDAP dla {value}…")
        try:
            ip_section(report, rdap("ip", value))
        except NetError as exc:
            report.section("Właściciel sieci (RDAP)").error = str(exc)
        return report

    host = normalize_domain(value)
    domain = registered_domain(host)
    report = Report("whois", domain)
    notify(progress, f"Pobieram dane RDAP dla {domain}…")
    try:
        sec = domain_section(report, rdap("domain", domain))
        if domain != host:
            sec.note = f"Dane dla domeny nadrzędnej {domain}."
        return report
    except NetError as exc:
        rdap_error = str(exc)

    notify(progress, "RDAP niedostępne – odpytuję klasyczny WHOIS…")
    sec = report.section("WHOIS")
    try:
        server, text = raw_whois(domain)
    except NetError as exc:
        sec.error = f"RDAP: {rdap_error}; WHOIS: {exc}"
        return report

    sec.add("Domena", domain)
    for label, val in parse_whois(text):
        if label == "Wygasa":
            add_expiry(sec, str(val))
        elif label == "Zarejestrowano":
            add_registration(sec, str(val))
        elif label == "Ostatnia zmiana":
            add_date(sec, label, str(val))
        else:
            sec.add(label, val)
    sec.add("Serwer WHOIS", server)
    if len(sec.fields) <= 2 and re.search(r"no match|not found|no entries|no data found|no information available|nie istnieje", text, re.I):
        sec.note = "Domena nie jest zarejestrowana (lub rejestr nie udostępnia danych)."
    if domain != host:
        sec.note = (sec.note + " " if sec.note else "") + f"Dane dla domeny nadrzędnej {domain}."
    raw = report.section("Surowa odpowiedź WHOIS")
    raw.text = _trim_raw(text)
    return report
