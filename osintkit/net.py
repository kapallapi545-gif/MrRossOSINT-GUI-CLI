"""Warstwa sieciowa oparta wyłącznie na bibliotece standardowej (HTTP + DNS-over-HTTPS)."""
from __future__ import annotations

import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
import zlib
from dataclasses import dataclass, field

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
)
DEFAULT_TIMEOUT = 12.0
MAX_BODY = 3 * 1024 * 1024

_SSL_VERIFIED = ssl.create_default_context()
_SSL_UNVERIFIED = ssl._create_unverified_context()  # tylko gdy wywołujący jawnie poprosi (verify=False)


class NetError(Exception):
    """Błąd sieci: timeout, brak DNS, odmowa połączenia itp."""


@dataclass
class Response:
    status: int
    url: str
    headers: list[tuple[str, str]]
    body: bytes
    redirects: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def header(self, name: str, default: str | None = None) -> str | None:
        name = name.lower()
        for key, value in reversed(self.headers):
            if key.lower() == name:
                return value
        return default

    def header_all(self, name: str) -> list[str]:
        name = name.lower()
        return [value for key, value in self.headers if key.lower() == name]

    @property
    def text(self) -> str:
        match = re.search(r"charset=[\"']?([\w-]+)", self.header("content-type") or "", re.I)
        charset = match.group(1) if match else "utf-8"
        try:
            return self.body.decode(charset, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")

    def json(self):
        return json.loads(self.body.decode("utf-8", errors="replace"))


class _RedirectRecorder(urllib.request.HTTPRedirectHandler):
    """Zapamiętuje łańcuch przekierowań (albo blokuje je, gdy follow=False)."""

    def __init__(self, follow: bool) -> None:
        self.follow = follow
        self.chain: list[str] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not self.follow:
            return None
        self.chain.append(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def describe_error(exc: BaseException) -> str:
    reason = getattr(exc, "reason", exc)
    if isinstance(reason, socket.gaierror):
        return "nie można rozwiązać nazwy hosta"
    if isinstance(reason, ssl.SSLCertVerificationError):
        return f"błąd certyfikatu SSL ({reason.verify_message})"
    if isinstance(reason, (socket.timeout, TimeoutError)):
        return "przekroczono limit czasu"
    if isinstance(reason, ConnectionRefusedError):
        return "połączenie odrzucone"
    if isinstance(reason, ConnectionResetError):
        return "połączenie zerwane przez serwer"
    return str(reason) or type(reason).__name__


def _decompress(body: bytes, encoding: str | None) -> bytes:
    encoding = (encoding or "").lower()
    try:
        if "gzip" in encoding:
            return zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(body)
        if "deflate" in encoding:
            try:
                return zlib.decompressobj().decompress(body)
            except zlib.error:
                return zlib.decompressobj(-zlib.MAX_WBITS).decompress(body)
    except zlib.error:
        pass
    return body


def request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
    json_body=None,
    timeout: float = DEFAULT_TIMEOUT,
    follow_redirects: bool = True,
    max_bytes: int = MAX_BODY,
    verify: bool = True,
) -> Response:
    """Wykonuje żądanie HTTP. Kody 4xx/5xx zwraca jako Response, błędy sieci jako NetError."""
    hdrs = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,pl;q=0.8",
        "Accept-Encoding": "gzip, deflate",
    }
    if headers:
        hdrs.update(headers)
    if json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")

    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    recorder = _RedirectRecorder(follow_redirects)
    opener = urllib.request.build_opener(
        recorder, urllib.request.HTTPSHandler(context=_SSL_VERIFIED if verify else _SSL_UNVERIFIED)
    )
    try:
        resp = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as exc:
        resp = exc
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise NetError(describe_error(exc)) from exc

    try:
        body = resp.read(max_bytes) or b""
    except Exception as exc:  # IncompleteRead, timeout w trakcie czytania itp.
        body = getattr(exc, "partial", b"") or b""
    finally:
        resp.close()

    headers_list = list(resp.headers.items()) if resp.headers is not None else []
    response = Response(
        status=resp.getcode() or 0,
        url=resp.geturl() or url,
        headers=headers_list,
        body=b"",
        redirects=recorder.chain,
    )
    response.body = _decompress(body, response.header("content-encoding"))
    return response


def get_json(url: str, **kwargs):
    headers = {"Accept": "application/json", **(kwargs.pop("headers", None) or {})}
    resp = request(url, headers=headers, **kwargs)
    if not resp.ok:
        raise NetError(f"HTTP {resp.status}")
    try:
        return resp.json()
    except ValueError as exc:
        raise NetError("niepoprawna odpowiedź JSON") from exc


# --- DNS-over-HTTPS -----------------------------------------------------------

DNS_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33, "CAA": 257}
_DOH_SERVERS = ("https://cloudflare-dns.com/dns-query", "https://dns.google/resolve")
_TXT_PART = re.compile(r'"((?:[^"\\]|\\.)*)"')


def _clean_dns_value(rtype: str, value: str) -> str:
    if rtype == "TXT":
        parts = _TXT_PART.findall(value)
        return "".join(parts) if parts else value
    if rtype in ("NS", "CNAME", "PTR", "MX"):
        return value.rstrip(".")
    return value


def dns_query(name: str, rtype: str = "A", timeout: float = 8.0) -> list[str]:
    """Odpytuje DNS przez HTTPS (Cloudflare, zapasowo Google). Zwraca listę wartości rekordów."""
    code = DNS_TYPES[rtype]
    last_error = "brak odpowiedzi"
    for server in _DOH_SERVERS:
        url = f"{server}?{urllib.parse.urlencode({'name': name, 'type': rtype})}"
        try:
            data = get_json(url, headers={"Accept": "application/dns-json"}, timeout=timeout)
        except NetError as exc:
            last_error = str(exc)
            continue
        answers = data.get("Answer") or []
        return [_clean_dns_value(rtype, a.get("data", "")) for a in answers if a.get("type") == code]
    raise NetError(f"zapytanie DNS {rtype} nie powiodło się: {last_error}")
