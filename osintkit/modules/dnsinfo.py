"""Rekordy DNS, SPF/DMARC oraz usługi zdradzane przez rekordy TXT."""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor

from ..net import NetError, dns_query
from ..report import BAD, OK, WARN, Report, Section
from ..utils import Progress, normalize_domain, notify

RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")

# Tokeny weryfikacyjne w TXT ujawniają, z jakich usług korzysta organizacja
TXT_SERVICES = [
    (r"^google-site-verification=", "Google (Search Console / Workspace)"),
    (r"^MS=ms\d+", "Microsoft 365"),
    (r"^facebook-domain-verification=", "Meta / Facebook"),
    (r"^apple-domain-verification=", "Apple"),
    (r"^atlassian-domain-verification=", "Atlassian"),
    (r"^docusign=", "DocuSign"),
    (r"^adobe-idp-site-verification=", "Adobe"),
    (r"^ZOOM_verify_", "Zoom"),
    (r"^stripe-verification=", "Stripe"),
    (r"^globalsign-domain-verification=", "GlobalSign"),
    (r"^openai-domain-verification=", "OpenAI"),
    (r"^anthropic-domain-verification", "Anthropic"),
    (r"^yandex-verification:", "Yandex"),
    (r"^dropbox-domain-verification=", "Dropbox"),
    (r"^slack-domain-verification=", "Slack"),
    (r"^cisco-ci-domain-verification=", "Cisco Webex"),
    (r"^webexdomainverification", "Cisco Webex"),
    (r"^brevo-code:", "Brevo"),
    (r"^Sendinblue-code:", "Brevo (Sendinblue)"),
    (r"^mailru-verification:", "Mail.ru"),
    (r"^pinterest-site-verification=", "Pinterest"),
    (r"^canva-site-verification=", "Canva"),
    (r"^miro-verification=", "Miro"),
    (r"^teamviewer-sso-verification=", "TeamViewer"),
    (r"^have-i-been-pwned-verification=", "Have I Been Pwned"),
    (r"^keybase-site-verification=", "Keybase"),
    (r"^twilio-domain-verification=", "Twilio"),
    (r"^onetrust-domain-verification=", "OneTrust"),
    (r"^citrix-verification-code=", "Citrix"),
    (r"^amazonses:", "Amazon SES"),
    (r"^calendly-site-verification=", "Calendly"),
    (r"^cursor-domain-verification", "Cursor"),
    (r"^loom-site-verification=", "Loom"),
    (r"^shopify-verification-code=", "Shopify"),
    (r"^jamf-site-verification=", "Jamf"),
    (r"^krisp-domain-verification=", "Krisp"),
    (r"^TAILSCALE-", "Tailscale"),
    (r"^notion-domain-verification=", "Notion"),
    (r"^figma-domain-verification=", "Figma"),
    (r"^postman-domain-verification=", "Postman"),
    (r"^wrike-verification=", "Wrike"),
    (r"^smartsheet-site-validation=", "Smartsheet"),
    (r"^zapier-domain-verification", "Zapier"),
    (r"^ahrefs-site-verification_", "Ahrefs"),
    (r"^hubspot-developer-verification=", "HubSpot"),
]

# Fragmenty "include:" w SPF wskazujące na nadawców poczty
SPF_SERVICES = [
    ("_spf.google.com", "Google Workspace"),
    ("spf.protection.outlook.com", "Microsoft 365"),
    ("amazonses.com", "Amazon SES"),
    ("sendgrid.net", "SendGrid"),
    ("mailgun.org", "Mailgun"),
    ("servers.mcsv.net", "Mailchimp"),
    ("spf.mandrillapp.com", "Mailchimp Transactional"),
    ("_spf.salesforce.com", "Salesforce"),
    ("zoho.", "Zoho Mail"),
    ("mail.zendesk.com", "Zendesk"),
    ("spf.brevo.com", "Brevo"),
    ("sendinblue.com", "Brevo (Sendinblue)"),
    ("_spf.mx.cloudflare.net", "Cloudflare Email Routing"),
    ("messagingengine.com", "Fastmail"),
    ("protonmail.ch", "Proton Mail"),
    ("mx.ovh.com", "OVH"),
    ("hubspotemail.net", "HubSpot"),
    ("spf.mtasv.net", "Postmark"),
    ("sparkpostmail.com", "SparkPost"),
    ("intercom.io", "Intercom"),
    ("helpscoutemail.com", "Help Scout"),
    ("_spf.yandex.net", "Yandex 360"),
    ("icloud.com", "iCloud Mail"),
    ("home.pl", "home.pl"),
    ("nazwa.pl", "nazwa.pl"),
    ("cyberfolks", "cyberFolks"),
    ("zenbox", "Zenbox"),
]


def query_all(domain: str, types=RECORD_TYPES) -> dict[str, list[str] | NetError]:
    with ThreadPoolExecutor(len(types)) as pool:
        futures = {rtype: pool.submit(dns_query, domain, rtype) for rtype in types}
    results: dict[str, list[str] | NetError] = {}
    for rtype, future in futures.items():
        try:
            results[rtype] = future.result()
        except NetError as exc:
            results[rtype] = exc
    return results


def detect_services(txt_records: list[str]) -> list[tuple[str, str]]:
    found: dict[str, str] = {}
    for record in txt_records:
        for pattern, name in TXT_SERVICES:
            if re.search(pattern, record, re.I):
                found.setdefault(name, f"TXT: {record[:70]}")
        if record.lower().startswith("v=spf1"):
            for needle, name in SPF_SERVICES:
                if needle in record.lower():
                    found.setdefault(name, f"SPF include: {needle}")
    return list(found.items())


def mail_security(report: Report, domain: str, txt: list[str] | None = None) -> Section:
    sec = report.section("Bezpieczeństwo poczty (SPF / DMARC)")
    if txt is None:
        try:
            txt = dns_query(domain, "TXT")
        except NetError as exc:
            sec.error = str(exc)
            txt = []

    spf = [t for t in txt if t.lower().startswith("v=spf1")]
    if not spf:
        sec.add("SPF", "brak rekordu – łatwiej podszyć się pod tę domenę", WARN)
    else:
        record = spf[0]
        if re.search(r"\+all\b", record):
            style = BAD
        elif re.search(r"[-~]all\b", record):
            style = OK
        else:
            style = WARN
        sec.add("SPF", record, style)
        if len(spf) > 1:
            sec.add("Uwaga", f"{len(spf)} rekordy SPF – dozwolony jest tylko jeden", WARN)

    try:
        dmarc = [t for t in dns_query(f"_dmarc.{domain}", "TXT") if t.lower().startswith("v=dmarc1")]
    except NetError:
        dmarc = []
    if dmarc:
        match = re.search(r"\bp\s*=\s*(\w+)", dmarc[0], re.I)
        policy = match.group(1).lower() if match else "?"
        good = policy in ("reject", "quarantine")
        sec.add("DMARC", dmarc[0], OK if good else WARN)
        labels = {"reject": "odrzucaj podrobione", "quarantine": "kwarantanna", "none": "tylko monitoruj"}
        sec.add("Polityka DMARC", labels.get(policy, policy), OK if good else WARN)
    else:
        sec.add("DMARC", "brak rekordu", WARN)
    return sec


def lookup(target: str, progress: Progress = None) -> Report:
    domain = normalize_domain(target)
    report = Report("dns", domain)
    notify(progress, f"Odpytuję rekordy DNS dla {domain}…")
    records = query_all(domain)

    sec = report.section("Rekordy DNS").table("Typ", "Wartość")
    errors = []
    for rtype in RECORD_TYPES:
        result = records[rtype]
        if isinstance(result, NetError):
            errors.append(f"{rtype}: {result}")
            continue
        for value in result:
            sec.row(rtype, value)
    if errors:
        sec.error = "; ".join(errors)
    if not sec.rows and not errors:
        sec.note = "Brak rekordów – domena prawdopodobnie nie istnieje."
        return report

    notify(progress, "Sprawdzam SPF / DMARC…")
    txt = records["TXT"] if isinstance(records["TXT"], list) else []
    mail_security(report, domain, txt)

    services = detect_services(txt)
    if services:
        svc = report.section("Usługi wykryte w rekordach TXT").table("Usługa", "Dowód")
        for name, evidence in services:
            svc.row(name, evidence)
    return report
