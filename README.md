# MrRossOSINT-GUI

Narzędzie do pasywnego rekonesansu OSINT z **wierszem poleceń** i **interfejsem graficznym**.
Napisane w czystym Pythonie (3.9+), bez żadnych zależności: wystarczy zainstalowany Python.

Korzysta wyłącznie z publicznych, pasywnych źródeł: nie skanuje portów, nie loguje się nigdzie
i nie wymaga kluczy API.

## Moduły

| Moduł | Polecenie | Co sprawdza |
|---|---|---|
| Domena – pełny skan | `domain` | DNS, WHOIS, SSL, strona WWW, hosting i subdomeny jednocześnie |
| Nazwa użytkownika | `username` | Konta o danej nazwie w 60 serwisach (GitHub, TikTok, Steam, Roblox, Minecraft…) + szczegóły profilu GitHub |
| Adres e-mail | `email` | Walidacja, serwery MX, dostawca poczty, SPF/DMARC, Gravatar, skrzynki jednorazowe |
| Adres IP | `ip` | Geolokalizacja, ISP/ASN, PTR, otwarte porty i CVE (Shodan InternetDB), właściciel sieci (RDAP) |
| Strona WWW | `web` | Nagłówki, technologie, nagłówki bezpieczeństwa, ciasteczka, e-maile i media społecznościowe, ID śledzące (GA, GTM, Pixel), robots.txt, security.txt, Wayback Machine |
| Rekordy DNS | `dns` | A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, SPF/DMARC i usługi zdradzane przez rekordy TXT |
| WHOIS / RDAP | `whois` | Rejestrator, daty, wiek domeny, właściciel, kontakty; dla IP – właściciel sieci |
| Subdomeny | `subdomains` | crt.sh, CertSpotter, HackerTarget, AlienVault OTX + rozwiązywanie adresów IP |
| Certyfikat SSL | `ssl` | Wystawca, ważność, SAN (powiązane domeny), odcisk SHA-256, wykrywanie przechwytywania TLS przez antywirus/proxy |
| Metadane zdjęcia | `exif` | EXIF, GPS z linkiem do mapy, aparat, numery seryjne, daty, XMP; JPEG, PNG, WebP, TIFF, HEIC – z pliku lub URL |

## Uruchamianie

**GUI:** kliknij dwukrotnie `MrRossOSINT-GUI.bat` albo:

```bash
python osint_gui.py
```

**Menu interaktywne w konsoli:** kliknij dwukrotnie `osint.bat` albo:

```bash
python osint.py
```

**Pojedyncze polecenia:**

```bash
python osint.py domain example.com
python osint.py username johndoe
python osint.py email jan@example.com
python osint.py ip 8.8.8.8
python osint.py exif C:\zdjecia\foto.jpg
python osint.py web https://example.com -o raport.html
python osint.py dns example.com --json
```

Opcje każdego modułu:

- `-o PLIK` – zapisuje raport (`.html`, `.json` lub `.md`)
- `--json` – wypisuje wynik jako JSON (np. do dalszego przetwarzania)
- `--no-color` – wyłącza kolory

W GUI: **Enter** uruchamia wyszukiwanie, **Ctrl+S** eksportuje raport, a linki w wynikach są klikalne.
Historia wyszukiwań z bieżącej sesji jest w lewym panelu.

## Struktura

```
osint.py / osint_gui.py   punkty wejścia
osintkit/
  net.py                  HTTP i DNS-over-HTTPS (tylko biblioteka standardowa)
  report.py               model raportu i eksport JSON / Markdown / HTML
  __init__.py             nazwa aplikacji (APP_NAME) i wersja
  registry.py             lista modułów wspólna dla CLI i GUI
  cli.py, gui.py          interfejsy
  modules/                moduły wyszukiwania
```

Nowy serwis w wyszukiwarce nazw użytkownika dodajesz jednym wpisem `Site(...)` w
`osintkit/modules/username.py`. Wcześniej sprawdź go na istniejącym i nieistniejącym koncie.

## Uwagi

- Zajęta nazwa użytkownika nie oznacza, że konto należy do tej samej osoby. Wyniki weryfikuj ręcznie.
- Geolokalizacja IP jest przybliżona: wskazuje miasto lub region dostawcy, a nie adres.
- Jeśli antywirus (np. Avast, ESET, Kaspersky) skanuje HTTPS, moduł SSL pokaże jego certyfikat
  i ostrzeże o tym. Prawdziwy certyfikat zobaczysz po wyłączeniu skanowania HTTPS.
- Darmowe źródła mają limity zapytań (np. HackerTarget, AlienVault). Przy częstym użyciu niektóre
  mogą chwilowo zwracać błąd, a narzędzie wtedy korzysta z pozostałych.
- Używaj zgodnie z prawem: do badania własnej ekspozycji w sieci, w pracy (bezpieczeństwo, due diligence),
  w CTF-ach i szkoleniach. Nie używaj narzędzia do nękania ani śledzenia innych osób.
