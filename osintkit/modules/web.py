"""Analiza strony WWW: odpowiedź HTTP, technologie, bezpieczeństwo, kontakty, archiwum."""
from __future__ import annotations

import html
import http
import re
import urllib.parse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

from ..net import NetError, Response, get_json, request
from ..report import BAD, MUTED, OK, WARN, Report
from ..utils import Progress, human_size, notify, registered_domain

SECURITY_HEADERS = [
    ("Strict-Transport-Security", "HSTS – wymusza HTTPS"),
    ("Content-Security-Policy", "CSP – ogranicza źródła skryptów"),
    ("X-Frame-Options", "ochrona przed clickjackingiem"),
    ("X-Content-Type-Options", "blokuje zgadywanie typu MIME"),
    ("Referrer-Policy", "kontrola nagłówka Referer"),
    ("Permissions-Policy", "dostęp do kamery, mikrofonu, lokalizacji…"),
    ("Cross-Origin-Opener-Policy", "izolacja okien przeglądarki"),
]

# (nazwa, kategoria, [(gdzie, wzorzec)]) – gdzie: body | generator | cookie | header:<nazwa>
FINGERPRINTS = [
    ("WordPress", "CMS", [("generator", r"WordPress"), ("body", r"/wp-(?:content|includes)/")]),
    ("Joomla", "CMS", [("generator", r"Joomla"), ("body", r"/media/(?:jui|system)/js/")]),
    ("Drupal", "CMS", [("generator", r"Drupal"), ("header:x-generator", r"Drupal"), ("body", r"Drupal\.settings|/sites/default/files/")]),
    ("Ghost", "CMS", [("generator", r"Ghost")]),
    ("TYPO3", "CMS", [("generator", r"TYPO3")]),
    ("Wix", "Kreator stron", [("header:x-wix-request-id", r"."), ("body", r"static\.wixstatic\.com")]),
    ("Squarespace", "Kreator stron", [("body", r"static1?\.squarespace\.com")]),
    ("Webflow", "Kreator stron", [("body", r"data-wf-(?:page|site)=")]),
    ("Shopify", "E-commerce", [("header:x-shopify-stage", r"."), ("body", r"cdn\.shopify\.com")]),
    ("WooCommerce", "E-commerce", [("body", r"woocommerce")]),
    ("PrestaShop", "E-commerce", [("generator", r"PrestaShop"), ("cookie", r"PrestaShop-"), ("body", r"prestashop")]),
    ("Magento", "E-commerce", [("body", r"Mage\.Cookies|/static/version\d+/frontend/")]),
    ("Next.js", "Framework JS", [("header:x-powered-by", r"Next\.js"), ("body", r"__NEXT_DATA__|/_next/static/")]),
    ("Nuxt", "Framework JS", [("body", r"__NUXT__|/_nuxt/")]),
    ("React", "Biblioteka JS", [("body", r"data-reactroot|react-dom(?:\.production)?(?:\.min)?\.js")]),
    ("Vue.js", "Framework JS", [("body", r"vue(?:\.runtime)?(?:\.global)?(?:\.prod)?(?:\.min)?\.js|data-v-[0-9a-f]{8}")]),
    ("Angular", "Framework JS", [("body", r"ng-version=\"|ng-app=")]),
    ("SvelteKit", "Framework JS", [("body", r"__sveltekit")]),
    ("Gatsby", "Framework JS", [("body", r"___gatsby")]),
    ("Astro", "Framework JS", [("generator", r"Astro"), ("body", r"astro-island")]),
    ("jQuery", "Biblioteka JS", [("body", r"jquery(?:[.-]\d[\d.]*)?(?:\.min)?\.js")]),
    ("Bootstrap", "Framework CSS", [("body", r"bootstrap(?:\.bundle)?(?:\.min)?\.(?:css|js)")]),
    ("Font Awesome", "Ikony", [("body", r"font-?awesome")]),
    ("Google Fonts", "Czcionki", [("body", r"fonts\.googleapis\.com")]),
    ("Google Analytics", "Analityka", [("body", r"google-analytics\.com|gtag\(\s*['\"]config")]),
    ("Google Tag Manager", "Analityka", [("body", r"googletagmanager\.com/gtm\.js|GTM-[A-Z0-9]{4,8}")]),
    ("Meta Pixel", "Marketing", [("body", r"connect\.facebook\.net/[^\"']*fbevents\.js|fbq\(")]),
    ("Hotjar", "Analityka", [("body", r"static\.hotjar\.com")]),
    ("Microsoft Clarity", "Analityka", [("body", r"clarity\.ms/tag")]),
    ("Yandex Metrica", "Analityka", [("body", r"mc\.yandex\.ru")]),
    ("Matomo", "Analityka", [("body", r"matomo\.js|piwik\.js|_paq\.push")]),
    ("Plausible", "Analityka", [("body", r"plausible\.io/js")]),
    ("Cloudflare Web Analytics", "Analityka", [("body", r"static\.cloudflareinsights\.com")]),
    ("HubSpot", "Marketing", [("body", r"js\.hs-scripts\.com|js\.hsforms\.net")]),
    ("Intercom", "Czat", [("body", r"widget\.intercom\.io|intercomSettings")]),
    ("Tawk.to", "Czat", [("body", r"embed\.tawk\.to")]),
    ("LiveChat", "Czat", [("body", r"cdn\.livechatinc\.com")]),
    ("Cookiebot", "Zgody cookies", [("body", r"consent\.cookiebot\.com")]),
    ("OneTrust", "Zgody cookies", [("body", r"cdn\.cookielaw\.org")]),
    ("Google reCAPTCHA", "Ochrona", [("body", r"google\.com/recaptcha|recaptcha/api\.js")]),
    ("hCaptcha", "Ochrona", [("body", r"hcaptcha\.com/1/api\.js")]),
    ("Cloudflare Turnstile", "Ochrona", [("body", r"challenges\.cloudflare\.com/turnstile")]),
    ("Stripe", "Płatności", [("body", r"js\.stripe\.com")]),
    ("PayPal", "Płatności", [("body", r"paypal\.com/sdk/js|paypalobjects\.com")]),
    ("Przelewy24", "Płatności", [("body", r"przelewy24")]),
    ("PayU", "Płatności", [("body", r"secure\.payu\.com")]),
    ("Cloudflare", "CDN / WAF", [("header:cf-ray", r"."), ("header:server", r"cloudflare")]),
    ("Amazon CloudFront", "CDN", [("header:x-amz-cf-id", r"."), ("header:via", r"CloudFront")]),
    ("Fastly", "CDN", [("header:x-fastly-request-id", r"."), ("header:x-served-by", r"cache-")]),
    ("Akamai", "CDN", [("header:x-akamai-transformed", r"."), ("header:server", r"AkamaiGHost")]),
    ("Vercel", "Hosting", [("header:x-vercel-id", r"."), ("header:server", r"Vercel")]),
    ("Netlify", "Hosting", [("header:x-nf-request-id", r"."), ("header:server", r"Netlify")]),
    ("GitHub Pages", "Hosting", [("header:server", r"GitHub\.com")]),
    ("Google Cloud", "Hosting", [("header:via", r"1\.1 google"), ("header:server", r"^(?:gws|Google Frontend)")]),
    ("Microsoft Azure", "Hosting", [("header:x-azure-ref", r"."), ("header:x-ms-request-id", r".")]),
    ("Amazon S3", "Hosting", [("header:server", r"AmazonS3")]),
    ("Varnish", "Cache", [("header:x-varnish", r"."), ("header:via", r"varnish")]),
    ("nginx", "Serwer WWW", [("header:server", r"nginx")]),
    ("Apache", "Serwer WWW", [("header:server", r"Apache")]),
    ("Microsoft IIS", "Serwer WWW", [("header:server", r"Microsoft-IIS")]),
    ("LiteSpeed", "Serwer WWW", [("header:server", r"LiteSpeed")]),
    ("Caddy", "Serwer WWW", [("header:server", r"Caddy")]),
    ("OpenResty", "Serwer WWW", [("header:server", r"openresty")]),
    ("PHP", "Język", [("header:x-powered-by", r"PHP"), ("cookie", r"\bPHPSESSID\b")]),
    ("ASP.NET", "Framework", [("header:x-aspnet-version", r"."), ("header:x-powered-by", r"ASP\.NET"), ("cookie", r"ASP\.NET_SessionId|\.AspNetCore\.")]),
    ("Express", "Framework", [("header:x-powered-by", r"Express")]),
    ("Laravel", "Framework", [("cookie", r"\blaravel_session\b")]),
    ("Django", "Framework", [("cookie", r"\bcsrftoken\b"), ("body", r"csrfmiddlewaretoken")]),
    ("Ruby on Rails", "Framework", [("body", r"name=\"csrf-param\" content=\"authenticity_token")]),
    ("Java", "Język", [("cookie", r"\bJSESSIONID\b")]),
]

SOCIAL_PATTERNS = [
    ("Facebook", r"https?://(?:www\.|m\.)?facebook\.com/(?!sharer|share|dialog|plugins|tr[/?])[A-Za-z0-9.\-_%]+"),
    ("Instagram", r"https?://(?:www\.)?instagram\.com/(?!p/|explore|reel)[A-Za-z0-9._]+"),
    ("X / Twitter", r"https?://(?:www\.)?(?:twitter|x)\.com/(?!intent|share|home|i/)[A-Za-z0-9_]+"),
    ("LinkedIn", r"https?://(?:[a-z]{2,3}\.)?linkedin\.com/(?:company|in|school)/[A-Za-z0-9\-_%]+"),
    ("YouTube", r"https?://(?:www\.)?youtube\.com/(?:channel/|c/|user/|@)[A-Za-z0-9\-_.]+"),
    ("TikTok", r"https?://(?:www\.)?tiktok\.com/@[A-Za-z0-9._]+"),
    ("GitHub", r"https?://(?:www\.)?github\.com/[A-Za-z0-9\-]+"),
    ("Telegram", r"https?://(?:t\.me|telegram\.me)/[A-Za-z0-9_]+"),
    ("Discord", r"https?://(?:discord\.gg|discord\.com/invite)/[A-Za-z0-9]+"),
    ("Threads", r"https?://(?:www\.)?threads\.net/@[A-Za-z0-9._]+"),
    ("Pinterest", r"https?://(?:[a-z]{2}\.|www\.)?pinterest\.[a-z.]+/(?!pin/)[A-Za-z0-9_]+"),
]

# Identyfikatory śledzące – ten sam ID na kilku stronach zwykle oznacza tego samego właściciela
TRACKER_IDS = [
    ("Google Analytics 4", r"""(?:gtag\(\s*['"]config['"]\s*,\s*['"]|[?&]id=)(G-[A-Z0-9]{6,12})"""),
    ("Universal Analytics", r"\b(UA-\d{4,10}-\d{1,4})\b"),
    ("Google Tag Manager", r"\b(GTM-[A-Z0-9]{4,8})\b"),
    ("Google AdSense", r"\b(ca-pub-\d{10,20})\b"),
    ("Meta Pixel", r"""fbq\(\s*['"]init['"]\s*,\s*['"](\d{10,20})['"]"""),
    ("Yandex Metrica", r"""ym\(\s*(\d{5,12})\s*,\s*['"]init['"]"""),
    ("Hotjar", r"hjid\s*[:=]\s*(\d{5,10})"),
]

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}")
_ASSET_EXT = ("png", "jpg", "jpeg", "gif", "webp", "svg", "css", "js", "avif", "ico")


def _normalize_url(target: str) -> str:
    url = target.strip()
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    if not urllib.parse.urlsplit(url).hostname:
        raise ValueError(f"Niepoprawny adres URL: {target}")
    return url


def _fetch_page(url: str) -> tuple[Response, str | None]:
    try:
        return request(url, timeout=15), None
    except NetError as exc:
        if "certyfikat" in str(exc):
            resp = request(url, timeout=15, verify=False)
            return resp, f"Certyfikat SSL jest niepoprawny ({exc}) – stronę pobrano bez weryfikacji."
        if url.lower().startswith("https://"):
            fallback = "http://" + url[8:]
            try:
                return request(fallback, timeout=15), f"HTTPS niedostępne ({exc}) – użyto HTTP."
            except NetError:
                pass
        raise


def _fetch_text(url: str) -> str | None:
    try:
        resp = request(url, timeout=10, max_bytes=512 * 1024)
    except NetError:
        return None
    if resp.status != 200:
        return None
    text = resp.text
    if "<html" in text[:600].lower() or "<!doctype" in text[:200].lower():
        return None  # "miękki 404" – serwer zwraca stronę HTML zamiast pliku
    return text


def wayback(host: str) -> dict:
    result: dict = {}
    try:
        rows = get_json(
            f"https://web.archive.org/cdx/search/cdx?url={host}&output=json&limit=1&fl=timestamp", timeout=20
        )
        if isinstance(rows, list) and len(rows) > 1:
            result["first"] = rows[1][0]
    except NetError as exc:
        result["error"] = str(exc)
    try:
        data = get_json(f"https://archive.org/wayback/available?url={host}", timeout=15)
        closest = (data.get("archived_snapshots") or {}).get("closest") or {}
        if closest.get("timestamp"):
            result["last"] = closest["timestamp"]
    except NetError as exc:
        result.setdefault("error", str(exc))
    return result


def _clean(text: str | None) -> str | None:
    if not text:
        return None
    text = re.sub(r"\s+", " ", html.unescape(text)).strip()
    return text[:240] + ("…" if len(text) > 240 else "") if text else None


def _meta(page: str, name: str) -> str | None:
    for tag in re.findall(r"<meta\b[^>]*>", page, re.I):
        if re.search(rf"""(?:name|property)\s*=\s*["']{re.escape(name)}["']""", tag, re.I):
            match = re.search(r"""content\s*=\s*(["'])(.*?)\1""", tag, re.I | re.S)
            if match:
                return _clean(match.group(2))
    return None


def _ts(stamp: str) -> str:
    return f"{stamp[0:4]}-{stamp[4:6]}-{stamp[6:8]}" if len(stamp) >= 8 else stamp


def detect_technologies(resp: Response, page: str) -> list[tuple[str, str, str]]:
    generator = _meta(page, "generator") or ""
    cookies = " ".join(c.split("=", 1)[0] for c in resp.header_all("set-cookie"))
    found = []
    for name, category, rules in FINGERPRINTS:
        for where, pattern in rules:
            if where == "body":
                haystack = page
            elif where == "generator":
                haystack = generator
            elif where == "cookie":
                haystack = cookies
            else:
                haystack = resp.header(where.split(":", 1)[1]) or ""
            if not haystack:
                continue
            match = re.search(pattern, haystack, re.I)
            if not match:
                continue
            if where == "generator":
                evidence = f"meta generator: {generator}"
            elif where.startswith("header:"):
                evidence = f"{where[7:]}: {haystack[:60]}"
            elif where == "cookie":
                evidence = f"cookie {match.group(0)}"
            else:
                evidence = f"kod strony: {match.group(0)[:50]}"
            found.append((name, category, evidence))
            break
    return found


def analyze(target: str, progress: Progress = None) -> Report:
    url = _normalize_url(target)
    report = Report("web", url)
    notify(progress, f"Pobieram {url}…")
    resp, note = _fetch_page(url)
    ctype = (resp.header("content-type") or "").lower()
    page = resp.text if ("html" in ctype or not ctype) else ""
    final = urllib.parse.urlsplit(resp.url)
    origin = f"{final.scheme}://{final.netloc}"
    host = final.hostname or ""

    notify(progress, "Pobieram robots.txt, security.txt i dane z Wayback Machine…")
    with ThreadPoolExecutor(3) as pool:
        f_robots = pool.submit(_fetch_text, origin + "/robots.txt")
        f_sectxt = pool.submit(_fetch_text, origin + "/.well-known/security.txt")
        f_archive = pool.submit(wayback, host)

        # --- odpowiedź HTTP
        sec = report.section("Odpowiedź HTTP")
        sec.add("Adres", url)
        if resp.redirects:
            sec.add("Przekierowania", " → ".join([url] + resp.redirects))
        if resp.url != url:
            sec.add("Adres końcowy", resp.url)
        try:
            phrase = http.HTTPStatus(resp.status).phrase
        except ValueError:
            phrase = ""
        sec.add("Status", f"{resp.status} {phrase}".strip(), OK if resp.ok else (WARN if resp.status < 500 else BAD))
        sec.add("HTTPS", resp.url.lower().startswith("https://"), OK if resp.url.lower().startswith("https://") else BAD)
        sec.add("Serwer", resp.header("server"))
        sec.add("X-Powered-By", resp.header("x-powered-by"))
        sec.add("Typ treści", resp.header("content-type"))
        sec.add("Rozmiar strony", human_size(len(resp.body)))
        if page:
            title = re.search(r"<title[^>]*>(.*?)</title>", page, re.I | re.S)
            sec.add("Tytuł", _clean(title.group(1)) if title else None)
            sec.add("Opis", _meta(page, "description") or _meta(page, "og:description"))
            sec.add("Generator", _meta(page, "generator"))
            lang = re.search(r"<html[^>]*\blang\s*=\s*[\"']?([\w-]+)", page, re.I)
            sec.add("Język", lang.group(1) if lang else None)
        if note:
            sec.note = note

        # --- nagłówki bezpieczeństwa
        present = [(h, d, resp.header(h)) for h, d in SECURITY_HEADERS]
        score = sum(1 for _, _, v in present if v)
        shdr = report.section(f"Nagłówki bezpieczeństwa ({score}/{len(SECURITY_HEADERS)})").table("Nagłówek", "Stan", "Znaczenie")
        for header, desc, value in present:
            shdr.row(header, "obecny" if value else "brak", desc, style=OK if value else BAD)

        # --- technologie
        techs = detect_technologies(resp, page)
        tsec = report.section(f"Wykryte technologie ({len(techs)})").table("Technologia", "Kategoria", "Dowód")
        for name, category, evidence in techs:
            tsec.row(name, category, evidence)
        if not techs:
            tsec.note = "Nie rozpoznano technologii."

        # --- ciasteczka
        cookies = resp.header_all("set-cookie")
        if cookies:
            csec = report.section(f"Ciasteczka ({len(cookies)})").table("Nazwa", "Secure", "HttpOnly", "SameSite")
            for raw in cookies:
                parts = [p.strip() for p in raw.split(";")]
                name = parts[0].split("=", 1)[0]
                attrs = {p.split("=", 1)[0].lower(): (p.split("=", 1)[1] if "=" in p else "") for p in parts[1:]}
                secure, httponly = "secure" in attrs, "httponly" in attrs
                csec.row(name, secure, httponly, attrs.get("samesite") or "—", style=OK if secure and httponly else WARN)

        # --- kontakty i media społecznościowe
        base = registered_domain(host) if host else ""
        if page:
            text = html.unescape(page)
            emails = []
            for email in EMAIL_RE.findall(text):
                email = email.lower().strip(".")
                domain = email.rsplit("@", 1)[1]
                if email.rsplit(".", 1)[-1] in _ASSET_EXT or "sentry" in domain or "wixpress" in domain:
                    continue
                if email not in emails:
                    emails.append(email)
            phones = []
            for phone in re.findall(r"""href\s*=\s*["']tel:([^"']+)""", page, re.I):
                phone = urllib.parse.unquote(phone).strip()
                if phone not in phones:
                    phones.append(phone)
            social: list[tuple[str, str]] = []
            for network, pattern in SOCIAL_PATTERNS:
                links: list[str] = []
                for link in re.findall(pattern, page):
                    link = link.rstrip("/\\\"'")
                    linked = registered_domain((urllib.parse.urlsplit(link).hostname or "").lower())
                    if link not in links and linked != base:  # pomijamy linki do samej badanej strony
                        links.append(link)
                social += [(network, link) for link in links[:4]]
            if emails or phones or social:
                ksec = report.section("Kontakty i media społecznościowe")
                ksec.add("E-mail", emails[:15])
                ksec.add("Telefon", phones[:10])
                for network, link in social:
                    ksec.add(network, link)

            # --- identyfikatory śledzące
            ids = []
            for name, pattern in TRACKER_IDS:
                for value in dict.fromkeys(re.findall(pattern, page)):
                    ids.append((name, value))
            if ids:
                isec = report.section("Identyfikatory śledzące").table("Usługa", "Identyfikator")
                for name, value in ids[:20]:
                    isec.row(name, value)
                isec.note = "Ten sam identyfikator na innych stronach zwykle wskazuje na tego samego właściciela."

            # --- powiązane domeny
            counter: Counter[str] = Counter()
            for link in re.findall(r"""(?:href|src)\s*=\s*["'](https?://[^"'\s>]+)""", page, re.I):
                linked = (urllib.parse.urlsplit(link).hostname or "").lower()
                if linked and base and not (linked == base or linked.endswith("." + base)):
                    counter[linked] += 1
            if counter:
                lsec = report.section(f"Domeny zewnętrzne ({len(counter)})").table("Domena", "Odwołania")
                for domain, count in counter.most_common(25):
                    lsec.row(domain, count)

    # --- robots.txt
    robots = f_robots.result()
    rsec = report.section("robots.txt")
    if robots:
        lines = [line.split("#", 1)[0].strip() for line in robots.splitlines()]
        disallow = list(dict.fromkeys(
            line.split(":", 1)[1].strip() for line in lines
            if line.lower().startswith("disallow:") and line.split(":", 1)[1].strip()
        ))
        sitemaps = [line.split(":", 1)[1].strip() for line in lines if line.lower().startswith("sitemap:")]
        rsec.add("Adres", origin + "/robots.txt")
        rsec.add("Mapy strony", sitemaps[:5])
        rsec.add("Zablokowane ścieżki", len(disallow))
        if disallow:
            rsec.table("Ścieżka (Disallow)")
            for path in disallow[:30]:
                rsec.row(path)
    else:
        rsec.note = "Brak pliku robots.txt."

    # --- security.txt
    sectxt = f_sectxt.result()
    if sectxt:
        ssec = report.section("security.txt")
        for line in sectxt.splitlines():
            key, _, value = line.partition(":")
            if key.strip().lower() in ("contact", "policy", "expires", "hiring", "preferred-languages") and value.strip():
                ssec.add(key.strip(), value.strip())

    # --- Wayback Machine
    archive = f_archive.result()
    asec = report.section("Archiwum internetu (Wayback Machine)")
    if archive.get("first"):
        asec.add("Pierwsza kopia", f"{_ts(archive['first'])} – https://web.archive.org/web/{archive['first']}/{host}")
    if archive.get("last"):
        asec.add("Najnowsza kopia", f"{_ts(archive['last'])} – https://web.archive.org/web/{archive['last']}/{host}")
    if archive.get("first") or archive.get("last"):
        asec.add("Wszystkie kopie", f"https://web.archive.org/web/*/{host}*")
    elif archive.get("error"):
        asec.error = f"Wayback Machine chwilowo nie odpowiada ({archive['error']})."
    else:
        asec.note = "Strona nie była archiwizowana."

    # --- wszystkie nagłówki (powtarzające się, np. dziesiątki "link", są zwijane)
    hsec = report.section("Wszystkie nagłówki HTTP").table("Nagłówek", "Wartość")
    counts = Counter(key.lower() for key, _ in resp.headers)
    shown: Counter[str] = Counter()
    for key, value in resp.headers:
        name = key.lower()
        shown[name] += 1
        if shown[name] > 3:
            if shown[name] == counts[name]:
                hsec.row(key, f"… i jeszcze {counts[name] - 3} takich nagłówków", style=MUTED)
            continue
        hsec.row(key, value if len(value) < 300 else value[:300] + "…", style=MUTED if name == "set-cookie" else None)
    return report
