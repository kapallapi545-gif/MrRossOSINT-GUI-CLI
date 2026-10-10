"""Adres e-mail: walidacja, serwery MX, dostawca, SPF/DMARC, Gravatar."""
from __future__ import annotations

import hashlib
import re
from concurrent.futures import ThreadPoolExecutor

from ..net import NetError, dns_query, get_json, request
from ..report import BAD, MUTED, OK, WARN, Report
from ..utils import Progress, notify
from . import dnsinfo

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-']+@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")

FREE_PROVIDERS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com",
    "ymail.com", "icloud.com", "me.com", "mac.com", "aol.com", "proton.me", "protonmail.com", "pm.me",
    "gmx.com", "gmx.net", "gmx.de", "web.de", "mail.com", "yandex.ru", "yandex.com", "mail.ru",
    "zoho.com", "tutanota.com", "tuta.io", "fastmail.com", "hey.com",
    "wp.pl", "o2.pl", "onet.pl", "onet.eu", "op.pl", "poczta.onet.pl", "vp.pl", "interia.pl",
    "interia.eu", "poczta.fm", "gazeta.pl", "tlen.pl", "int.pl", "autograf.pl", "buziaczek.pl",
    "spoko.pl", "go2.pl", "prokonto.pl",
}

DISPOSABLE = {
    "mailinator.com", "10minutemail.com", "10minutemail.net", "guerrillamail.com", "guerrillamail.net",
    "sharklasers.com", "grr.la", "temp-mail.org", "tempmail.com", "tempmail.dev", "temp-mail.io",
    "yopmail.com", "yopmail.fr", "trashmail.com", "trashmail.de", "getnada.com", "nada.email",
    "dispostable.com", "maildrop.cc", "mailnesia.com", "mintemail.com", "throwawaymail.com",
    "fakeinbox.com", "emailondeck.com", "mohmal.com", "tempail.com", "burnermail.io", "spamgourmet.com",
    "mailcatch.com", "moakt.com", "tempr.email", "discard.email", "33mail.com", "inboxkitten.com",
    "1secmail.com", "1secmail.net", "emailfake.com", "mail.tm", "tmpmail.org", "minuteinbox.com",
}

MX_PROVIDERS = [
    (r"google(?:mail)?\.com$", "Google (Gmail / Workspace)"),
    (r"\.protection\.outlook\.com$|outlook\.com$|hotmail\.com$", "Microsoft (Outlook / 365)"),
    (r"yahoodns\.net$", "Yahoo"),
    (r"icloud\.com$|me\.com$", "Apple iCloud"),
    (r"protonmail\.ch$", "Proton Mail"),
    (r"zoho\.(?:com|eu|in)$", "Zoho Mail"),
    (r"yandex\.(?:net|ru)$", "Yandex"),
    (r"messagingengine\.com$", "Fastmail"),
    (r"mx\.cloudflare\.net$", "Cloudflare Email Routing"),
    (r"pphosted\.com$", "Proofpoint"),
    (r"mimecast\.com$", "Mimecast"),
    (r"barracudanetworks\.com$", "Barracuda"),
    (r"ovh\.net$", "OVH"),
    (r"\.(?:wp|o2)\.pl$", "Wirtualna Polska (WP / o2)"),
    (r"onet\.(?:pl|eu)$", "Onet Poczta"),
    (r"interia\.(?:pl|eu)$|poczta\.fm$", "Interia"),
    (r"home\.pl$", "home.pl"),
    (r"nazwa\.pl$", "nazwa.pl"),
    (r"cyberfolks\.pl$", "cyberFolks"),
    (r"zenbox\.pl$", "Zenbox"),
    (r"gmx\.(?:net|com)$", "GMX"),
    (r"mail\.ru$", "Mail.ru"),
    (r"secureserver\.net$", "GoDaddy"),
    (r"emailsrvr\.com$", "Rackspace"),
    (r"amazonaws\.com$", "Amazon SES / WorkMail"),
    (r"trendmicro\.(?:eu|com)$", "Trend Micro (filtr poczty)"),
    (r"messagelabs\.com$", "Broadcom / Symantec (filtr poczty)"),
    (r"iphmx\.com$", "Cisco Secure Email (filtr poczty)"),
    (r"spamexperts\.(?:com|net|eu)$", "SpamExperts / N-able (filtr poczty)"),
    (r"hornetsecurity\.com$", "Hornetsecurity (filtr poczty)"),
]


def mx_records(domain: str) -> list[tuple[int, str]]:
    records = []
    for value in dns_query(domain, "MX"):
        parts = value.split()
        if len(parts) == 2 and parts[0].isdigit():
            records.append((int(parts[0]), parts[1].lower()))
    return sorted(records)


def provider_from_mx(hosts: list[str]) -> str | None:
    for host in hosts:
        for pattern, name in MX_PROVIDERS:
            if re.search(pattern, host):
                return name
    return None


def gravatar(email: str) -> dict | None:
    digest = hashlib.sha256(email.encode("utf-8")).hexdigest()
    resp = request(f"https://gravatar.com/avatar/{digest}?d=404&s=256", timeout=8, max_bytes=1)
    if resp.status != 200:
        return None
    info: dict = {"avatar": f"https://gravatar.com/avatar/{digest}?s=256", "profile": f"https://gravatar.com/{digest}"}
    try:
        profile = get_json(f"https://api.gravatar.com/v3/profiles/{digest}", timeout=8)
        info.update(
            name=profile.get("display_name"),
            profile=profile.get("profile_url") or info["profile"],
            location=profile.get("location"),
            description=profile.get("description"),
            job=" · ".join(p for p in (profile.get("job_title"), profile.get("company")) if p),
            accounts=[a.get("url") for a in profile.get("verified_accounts") or [] if a.get("url")],
        )
    except NetError:
        pass
    return info


def lookup(target: str, progress: Progress = None) -> Report:
    email = target.strip().lower()
    if email.startswith("mailto:"):
        email = email[7:]
    if not EMAIL_RE.match(email):
        raise ValueError("Niepoprawny adres e-mail.")
    local, domain = email.rsplit("@", 1)
    report = Report("email", email)

    notify(progress, f"Sprawdzam domenę {domain} i Gravatar…")
    with ThreadPoolExecutor(3) as pool:
        f_mx = pool.submit(mx_records, domain)
        f_txt = pool.submit(dns_query, domain, "TXT")
        f_grav = pool.submit(gravatar, email)

    sec = report.section("Adres e-mail")
    sec.add("Adres", email)
    sec.add("Nazwa lokalna", local)
    sec.add("Domena", domain)
    if domain in DISPOSABLE:
        sec.add("Typ skrzynki", "jednorazowa (disposable) – adres tymczasowy", BAD)
    elif domain in FREE_PROVIDERS:
        sec.add("Typ skrzynki", "darmowa skrzynka publicznego dostawcy")
    else:
        sec.add("Typ skrzynki", "domena własna / firmowa")
    if "+" in local:
        base, tag = local.split("+", 1)
        sec.add("Alias (plus)", f"główny adres: {base}@{domain}, etykieta: {tag}", WARN)
    if domain in ("gmail.com", "googlemail.com"):
        canonical = local.split("+", 1)[0].replace(".", "") + "@gmail.com"
        if canonical != email:
            sec.add("Adres kanoniczny Gmail", canonical)

    mx_sec = report.section("Serwery pocztowe (MX)")
    try:
        mx = f_mx.result()
    except NetError as exc:
        mx = []
        mx_sec.error = str(exc)
    if mx:
        mx_sec.table("Priorytet", "Serwer")
        for priority, host in mx:
            mx_sec.row(priority, host)
        provider = provider_from_mx([h for _, h in mx])
        sec.add("Dostawca poczty", provider or "nierozpoznany / własny serwer")
        sec.add("Przyjmuje pocztę", "tak (są rekordy MX)", OK)
        try:
            senders = [name for name, _ in dnsinfo.detect_services(f_txt.result()) if name]
        except NetError:
            senders = []
        if senders:
            sec.add("Usługi z SPF / TXT", senders)
    elif not mx_sec.error:
        try:
            has_a = bool(dns_query(domain, "A"))
        except NetError:
            has_a = False
        if has_a:
            mx_sec.note = "Brak rekordów MX – poczta trafiałaby na adres z rekordu A (rzadko spotykane)."
            sec.add("Przyjmuje pocztę", "niepewne (brak MX)", WARN)
        else:
            mx_sec.note = "Domena nie istnieje lub nie ma rekordów DNS."
            sec.add("Przyjmuje pocztę", "nie – adres nie może istnieć", BAD)

    try:
        txt = f_txt.result()
    except NetError:
        txt = None
    dnsinfo.mail_security(report, domain, txt)

    gsec = report.section("Gravatar")
    try:
        grav = f_grav.result()
    except NetError as exc:
        grav = None
        gsec.error = str(exc)
    if grav:
        gsec.add("Konto", "istnieje – adres jest powiązany z profilem Gravatar", OK)
        gsec.add("Nazwa", grav.get("name"))
        gsec.add("Lokalizacja", grav.get("location"))
        gsec.add("Praca", grav.get("job"))
        gsec.add("Opis", grav.get("description"))
        gsec.add("Avatar", grav.get("avatar"))
        gsec.add("Profil", grav.get("profile"))
        for account in grav.get("accounts") or []:
            gsec.add("Powiązane konto", account)
    elif not gsec.error:
        gsec.add("Konto", "brak profilu Gravatar", MUTED)

    nxt = report.section("Dalsze kroki")
    nick = re.sub(r"[^a-z0-9_.-]", "", local.split("+", 1)[0])
    if nick:
        nxt.add("Nazwa użytkownika", f"sprawdź „{nick}” modułem Nazwa użytkownika")
    if domain not in FREE_PROVIDERS and domain not in DISPOSABLE:
        nxt.add("Domena", f"przeskanuj „{domain}” modułem Domena")
    return report
