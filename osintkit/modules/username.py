"""Wyszukiwanie nazwy użytkownika w popularnych serwisach (w stylu Sherlocka)."""
from __future__ import annotations

import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Callable

from ..net import NetError, get_json, request
from ..report import MUTED, OK, WARN, Report
from ..utils import Progress, notify

FOUND, MISSING, UNKNOWN, SKIPPED = "found", "missing", "unknown", "skipped"

GENERIC = r"^[A-Za-z0-9_.-]{1,40}$"
SUBDOMAIN = r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"


@dataclass(frozen=True)
class Site:
    name: str
    url: str                                  # adres profilu dla człowieka, {u} = nazwa
    category: str
    probe: str | None = None                  # adres sprawdzany zamiast url (np. API)
    check: str = "status"                     # status | json | missing_text | present_text | missing_url
    text: str | None = None                   # fraza do wyszukania ({u} = nazwa)
    test: Callable[[Any], bool] | None = None # dla check="json": czy konto istnieje
    missing: tuple[int, ...] = (404, 410)     # kody oznaczające brak konta
    method: str = "GET"
    body: Callable[[str], Any] | None = None
    headers: tuple[tuple[str, str], ...] = ()
    pattern: str = GENERIC
    follow: bool = True


# Każdy wpis został sprawdzony na istniejących i nieistniejących kontach.
# Serwisy z blokadą botów (Cloudflare/CAPTCHA) lub wymagające logowania są pominięte.
SITES: list[Site] = [
    # --- programowanie i IT
    Site("GitHub", "https://github.com/{u}", "Programowanie", pattern=r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$"),
    Site("GitLab", "https://gitlab.com/{u}", "Programowanie", probe="https://gitlab.com/api/v4/users?username={u}",
         check="json", test=lambda d: isinstance(d, list) and len(d) > 0),
    Site("Codeberg", "https://codeberg.org/{u}", "Programowanie", probe="https://codeberg.org/api/v1/users/{u}"),
    Site("Gitee", "https://gitee.com/{u}", "Programowanie"),
    Site("Hugging Face", "https://huggingface.co/{u}", "Programowanie",
         probe="https://huggingface.co/api/users/{u}/overview"),
    Site("Docker Hub", "https://hub.docker.com/u/{u}", "Programowanie", probe="https://hub.docker.com/v2/users/{u}/"),
    Site("Dev.to", "https://dev.to/{u}", "Programowanie", probe="https://dev.to/api/users/by_username?url={u}"),
    Site("Hacker News", "https://news.ycombinator.com/user?id={u}", "Programowanie",
         probe="https://hacker-news.firebaseio.com/v0/user/{u}.json", check="json", test=lambda d: d is not None),
    Site("Lobsters", "https://lobste.rs/~{u}", "Programowanie"),
    Site("Habr", "https://habr.com/en/users/{u}/", "Programowanie"),
    Site("Replit", "https://replit.com/@{u}", "Programowanie"),
    Site("Codewars", "https://www.codewars.com/users/{u}", "Programowanie",
         probe="https://www.codewars.com/api/v1/users/{u}"),
    Site("Codeforces", "https://codeforces.com/profile/{u}", "Programowanie",
         probe="https://codeforces.com/api/user.info?handles={u}", check="json", missing=(400, 404),
         test=lambda d: d.get("status") == "OK"),
    Site("Keybase", "https://keybase.io/{u}", "Programowanie",
         probe="https://keybase.io/_/api/1.0/user/lookup.json?usernames={u}&fields=basics", check="json",
         test=lambda d: bool(d.get("them")) and d["them"][0] is not None),
    Site("HackerOne", "https://hackerone.com/{u}", "Bezpieczeństwo"),
    Site("Trello", "https://trello.com/{u}", "Produktywność", probe="https://trello.com/1/Members/{u}"),
    Site("Scratch", "https://scratch.mit.edu/users/{u}/", "Programowanie",
         probe="https://api.scratch.mit.edu/users/{u}"),
    # --- społeczności i blogi
    Site("YouTube", "https://www.youtube.com/@{u}", "Wideo", headers=(("Cookie", "SOCS=CAI; CONSENT=YES+1"),)),
    Site("TikTok", "https://www.tiktok.com/@{u}", "Wideo", check="present_text", text='"uniqueId":"{u}"'),
    Site("Pinterest", "https://www.pinterest.com/{u}/", "Społeczności", check="present_text",
         text="- Profile | Pinterest"),
    Site("Mastodon", "https://mastodon.social/@{u}", "Społeczności",
         probe="https://mastodon.social/api/v1/accounts/lookup?acct={u}"),
    Site("Bluesky", "https://bsky.app/profile/{u}.bsky.social", "Społeczności",
         probe="https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={u}.bsky.social",
         missing=(400, 404), pattern=SUBDOMAIN),
    Site("Telegram", "https://t.me/{u}", "Komunikatory", check="present_text", text="tgme_page_title",
         pattern=r"^[A-Za-z][A-Za-z0-9_]{4,31}$"),
    Site("Snapchat", "https://www.snapchat.com/add/{u}", "Społeczności"),
    Site("VK", "https://vk.com/{u}", "Społeczności"),
    Site("Tumblr", "https://{u}.tumblr.com", "Blogi", pattern=SUBDOMAIN),
    Site("Medium", "https://medium.com/@{u}", "Blogi", probe="https://medium.com/feed/@{u}"),
    Site("Substack", "https://{u}.substack.com", "Blogi", pattern=SUBDOMAIN),
    Site("Linktree", "https://linktr.ee/{u}", "Społeczności"),
    Site("About.me", "https://about.me/{u}", "Społeczności"),
    Site("Gravatar", "https://gravatar.com/{u}", "Społeczności", probe="https://en.gravatar.com/{u}.json"),
    Site("Disqus", "https://disqus.com/by/{u}/", "Społeczności"),
    Site("Wikipedia", "https://en.wikipedia.org/wiki/User:{u}", "Społeczności",
         probe="https://en.wikipedia.org/w/api.php?action=query&list=users&ususers={u}&format=json", check="json",
         test=lambda d: not {"missing", "invalid"} & set(d["query"]["users"][0])),
    Site("Pastebin", "https://pastebin.com/u/{u}", "Społeczności"),
    Site("Pepper.pl", "https://www.pepper.pl/profile/{u}", "Społeczności"),
    # --- muzyka, wideo, sztuka, hobby
    Site("Vimeo", "https://vimeo.com/{u}", "Wideo"),
    Site("Dailymotion", "https://www.dailymotion.com/{u}", "Wideo", probe="https://api.dailymotion.com/user/{u}"),
    Site("Rumble", "https://rumble.com/user/{u}", "Wideo"),
    Site("SoundCloud", "https://soundcloud.com/{u}", "Muzyka"),
    Site("Bandcamp", "https://{u}.bandcamp.com", "Muzyka", check="missing_url", text="/signup", pattern=SUBDOMAIN),
    Site("Mixcloud", "https://www.mixcloud.com/{u}/", "Muzyka", probe="https://api.mixcloud.com/{u}/"),
    Site("Discogs", "https://www.discogs.com/user/{u}", "Muzyka", probe="https://api.discogs.com/users/{u}"),
    Site("Flickr", "https://www.flickr.com/people/{u}/", "Zdjęcia"),
    Site("Behance", "https://www.behance.net/{u}", "Sztuka"),
    Site("Dribbble", "https://dribbble.com/{u}", "Sztuka"),
    Site("DeviantArt", "https://www.deviantart.com/{u}", "Sztuka"),
    Site("MyAnimeList", "https://myanimelist.net/profile/{u}", "Hobby"),
    Site("Wattpad", "https://www.wattpad.com/user/{u}", "Hobby", probe="https://www.wattpad.com/api/v3/users/{u}",
         missing=(400, 404)),
    Site("Duolingo", "https://www.duolingo.com/profile/{u}", "Hobby",
         probe="https://www.duolingo.com/2017-06-30/users?username={u}&fields=users%7Busername%7D", check="json",
         test=lambda d: bool(d.get("users"))),
    Site("Patreon", "https://www.patreon.com/{u}", "Wsparcie twórców"),
    Site("Buy Me a Coffee", "https://buymeacoffee.com/{u}", "Wsparcie twórców"),
    Site("Gumroad", "https://{u}.gumroad.com", "Wsparcie twórców", pattern=SUBDOMAIN),
    # --- gry i streaming
    Site("Steam", "https://steamcommunity.com/id/{u}", "Gry", check="missing_text",
         text="The specified profile could not be found"),
    Site("Kick", "https://kick.com/{u}", "Gry", probe="https://kick.com/api/v2/channels/{u}"),
    Site("Chess.com", "https://www.chess.com/member/{u}", "Gry", probe="https://api.chess.com/pub/player/{u}"),
    Site("Lichess", "https://lichess.org/@/{u}", "Gry", probe="https://lichess.org/api/user/{u}"),
    Site("Minecraft", "https://namemc.com/profile/{u}", "Gry",
         probe="https://api.mojang.com/users/profiles/minecraft/{u}", missing=(204, 404),
         pattern=r"^[A-Za-z0-9_]{3,16}$"),
    Site("Roblox", "https://www.roblox.com/search/users?keyword={u}", "Gry",
         probe="https://users.roblox.com/v1/usernames/users", method="POST", check="json",
         body=lambda u: {"usernames": [u], "excludeBannedUsers": False}, test=lambda d: bool(d.get("data"))),
    Site("Speedrun.com", "https://www.speedrun.com/users/{u}", "Gry", probe="https://www.speedrun.com/api/v1/users/{u}"),
    Site("itch.io", "https://{u}.itch.io", "Gry", pattern=SUBDOMAIN),
]

STATUS_LABELS = {FOUND: "znaleziono", MISSING: "brak", UNKNOWN: "niepewne", SKIPPED: "pominięto"}


def check_site(site: Site, username: str, timeout: float = 12.0) -> tuple[str, str]:
    """Zwraca (status, szczegóły)."""
    if not re.fullmatch(site.pattern, username):
        return SKIPPED, "nazwa nie spełnia zasad serwisu"
    quoted = urllib.parse.quote(username, safe="")
    probe = (site.probe or site.url).format(u=quoted)
    try:
        resp = request(
            probe,
            method=site.method,
            json_body=site.body(username) if site.body else None,
            headers=dict(site.headers) or None,
            timeout=timeout,
            follow_redirects=site.follow,
            max_bytes=900_000,
        )
    except NetError as exc:
        return UNKNOWN, str(exc)

    if resp.status in site.missing:
        return MISSING, ""
    if not site.follow and 300 <= resp.status < 400:
        return MISSING, "przekierowanie"
    if resp.status in (401, 403, 429) or resp.status >= 500:
        return UNKNOWN, f"HTTP {resp.status} (blokada lub limit zapytań)"
    if site.check == "status":
        return (FOUND, "") if resp.status == 200 else (UNKNOWN, f"HTTP {resp.status}")
    if resp.status >= 400:
        return UNKNOWN, f"HTTP {resp.status}"
    needle = (site.text or "").replace("{u}", username)
    if site.check == "json":
        try:
            return (FOUND, "") if site.test(resp.json()) else (MISSING, "")
        except (ValueError, KeyError, IndexError, TypeError, AttributeError):
            return UNKNOWN, "nieoczekiwana odpowiedź"
    if site.check == "missing_text":
        return (MISSING, "") if needle in resp.text else (FOUND, "")
    if site.check == "present_text":
        return (FOUND, "") if needle in resp.text else (MISSING, "")
    if site.check == "missing_url":
        return (MISSING, "") if needle in resp.url else (FOUND, "")
    return UNKNOWN, "nieznana metoda"


def github_details(username: str) -> dict | None:
    try:
        return get_json(f"https://api.github.com/users/{urllib.parse.quote(username)}", timeout=10)
    except NetError:
        return None


def search(target: str, progress: Progress = None, sites: list[Site] | None = None) -> Report:
    username = target.strip().lstrip("@")
    if not username or re.search(r"\s", username):
        raise ValueError("Podaj nazwę użytkownika bez spacji.")
    sites = sites or SITES
    report = Report("username", username)
    results: list[tuple[Site, str, str]] = []

    notify(progress, f"Sprawdzam „{username}” w {len(sites)} serwisach…", 0.0)
    with ThreadPoolExecutor(16) as pool:
        futures = {pool.submit(check_site, site, username): site for site in sites}
        for done, future in enumerate(as_completed(futures), 1):
            site = futures[future]
            status, detail = future.result()
            results.append((site, status, detail))
            notify(progress, f"[{done}/{len(sites)}] {site.name}: {STATUS_LABELS[status]}", done / len(sites))

    order = {s.name: i for i, s in enumerate(sites)}
    results.sort(key=lambda r: order[r[0].name])
    quoted = urllib.parse.quote(username, safe="")
    found = [(s, d) for s, st, d in results if st == FOUND]
    unknown = [(s, d) for s, st, d in results if st == UNKNOWN]
    missing = [s for s, st, _ in results if st == MISSING]
    skipped = [s for s, st, _ in results if st == SKIPPED]

    summary = report.section("Podsumowanie")
    summary.add("Nazwa użytkownika", username)
    summary.add("Sprawdzone serwisy", len(sites))
    summary.add("Znalezione konta", len(found), OK if found else None)
    summary.add("Niepewne wyniki", len(unknown), WARN if unknown else None)
    summary.note = "Zajęta nazwa nie oznacza, że konto należy do tej samej osoby – zweryfikuj profile ręcznie."

    fsec = report.section(f"Znalezione konta ({len(found)})").table("Serwis", "Kategoria", "Profil")
    for site, _ in found:
        fsec.row(site.name, site.category, site.url.format(u=quoted), style=OK)
    if not found:
        fsec.note = "Nie znaleziono kont o tej nazwie."

    if unknown:
        usec = report.section(f"Niepewne – sprawdź ręcznie ({len(unknown)})").table("Serwis", "Powód", "Link")
        for site, detail in unknown:
            usec.row(site.name, detail, site.url.format(u=quoted), style=WARN)

    if missing:
        report.section(f"Brak konta ({len(missing)})").add("Serwisy", ", ".join(s.name for s in missing), MUTED)
    if skipped:
        report.section("Pominięte").add("Niedozwolona nazwa w", ", ".join(s.name for s in skipped), MUTED)

    if any(s.name == "GitHub" for s, _ in found):
        notify(progress, "Pobieram szczegóły profilu GitHub…")
        data = github_details(username)
        if data:
            gh = report.section("Profil GitHub")
            gh.add("Imię / nazwa", data.get("name"))
            gh.add("Bio", data.get("bio"))
            gh.add("Firma", data.get("company"))
            gh.add("Lokalizacja", data.get("location"))
            gh.add("Strona", data.get("blog"))
            gh.add("E-mail (publiczny)", data.get("email"))
            gh.add("X / Twitter", data.get("twitter_username"))
            gh.add("Repozytoria", data.get("public_repos"))
            gh.add("Obserwujący", data.get("followers"))
            gh.add("Utworzono", (data.get("created_at") or "")[:10])
    return report
