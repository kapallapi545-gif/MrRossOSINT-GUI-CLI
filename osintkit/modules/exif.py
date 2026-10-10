"""Metadane zdjęć (EXIF / GPS / XMP / PNG) – parser w czystym Pythonie, bez Pillow."""
from __future__ import annotations

import hashlib
import html
import re
import struct
import urllib.parse
import zlib
from datetime import datetime
from fractions import Fraction
from pathlib import Path

from ..net import NetError, request
from ..report import MUTED, WARN, Report
from ..utils import Progress, human_size, notify

MAX_SIZE = 64 * 1024 * 1024

IFD0_TAGS = {
    0x010E: "ImageDescription", 0x010F: "Make", 0x0110: "Model", 0x0112: "Orientation",
    0x011A: "XResolution", 0x011B: "YResolution", 0x0128: "ResolutionUnit", 0x0131: "Software",
    0x0132: "DateTime", 0x013B: "Artist", 0x013C: "HostComputer", 0x8298: "Copyright",
    0x9C9B: "XPTitle", 0x9C9C: "XPComment", 0x9C9D: "XPAuthor", 0x9C9E: "XPKeywords", 0x9C9F: "XPSubject",
}
EXIF_TAGS = {
    0x829A: "ExposureTime", 0x829D: "FNumber", 0x8822: "ExposureProgram", 0x8827: "ISO",
    0x9000: "ExifVersion", 0x9003: "DateTimeOriginal", 0x9004: "DateTimeDigitized",
    0x9010: "OffsetTime", 0x9011: "OffsetTimeOriginal", 0x9201: "ShutterSpeedValue",
    0x9202: "ApertureValue", 0x9204: "ExposureBiasValue", 0x9205: "MaxApertureValue",
    0x9207: "MeteringMode", 0x9208: "LightSource", 0x9209: "Flash", 0x920A: "FocalLength",
    0x9286: "UserComment", 0x9290: "SubSecTime", 0x9291: "SubSecTimeOriginal",
    0xA002: "PixelXDimension", 0xA003: "PixelYDimension", 0xA401: "CustomRendered",
    0xA402: "ExposureMode", 0xA403: "WhiteBalance", 0xA404: "DigitalZoomRatio",
    0xA405: "FocalLengthIn35mmFilm", 0xA406: "SceneCaptureType", 0xA420: "ImageUniqueID",
    0xA430: "CameraOwnerName", 0xA431: "BodySerialNumber", 0xA432: "LensSpecification",
    0xA433: "LensMake", 0xA434: "LensModel", 0xA435: "LensSerialNumber",
}
GPS_TAGS = {
    0x00: "GPSVersionID", 0x01: "GPSLatitudeRef", 0x02: "GPSLatitude", 0x03: "GPSLongitudeRef",
    0x04: "GPSLongitude", 0x05: "GPSAltitudeRef", 0x06: "GPSAltitude", 0x07: "GPSTimeStamp",
    0x0C: "GPSSpeedRef", 0x0D: "GPSSpeed", 0x10: "GPSImgDirectionRef", 0x11: "GPSImgDirection",
    0x12: "GPSMapDatum", 0x1B: "GPSProcessingMethod", 0x1D: "GPSDateStamp",
}
TYPE_SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8}

LABELS = {
    "Make": "Producent", "Model": "Model", "LensMake": "Producent obiektywu", "LensModel": "Obiektyw",
    "LensSpecification": "Specyfikacja obiektywu", "BodySerialNumber": "Numer seryjny aparatu",
    "LensSerialNumber": "Numer seryjny obiektywu", "CameraOwnerName": "Właściciel aparatu",
    "Software": "Oprogramowanie", "HostComputer": "Komputer", "Artist": "Autor", "XPAuthor": "Autor (Windows)",
    "Copyright": "Prawa autorskie", "ImageDescription": "Opis", "XPTitle": "Tytuł (Windows)",
    "XPComment": "Komentarz (Windows)", "XPSubject": "Temat (Windows)", "XPKeywords": "Słowa kluczowe",
    "UserComment": "Komentarz", "ImageUniqueID": "Unikalny ID zdjęcia",
    "DateTimeOriginal": "Data wykonania", "DateTimeDigitized": "Data digitalizacji",
    "DateTime": "Data modyfikacji", "OffsetTimeOriginal": "Strefa czasowa wykonania", "OffsetTime": "Strefa czasowa",
    "ExposureTime": "Czas naświetlania", "FNumber": "Przysłona", "ISO": "ISO", "FocalLength": "Ogniskowa",
    "FocalLengthIn35mmFilm": "Ogniskowa (ekw. 35 mm)", "ExposureProgram": "Program ekspozycji",
    "ExposureBiasValue": "Korekta ekspozycji", "MeteringMode": "Pomiar światła", "Flash": "Lampa błyskowa",
    "WhiteBalance": "Balans bieli", "ExposureMode": "Tryb ekspozycji", "DigitalZoomRatio": "Zoom cyfrowy",
    "SceneCaptureType": "Typ sceny", "Orientation": "Orientacja", "PixelXDimension": "Szerokość (EXIF)",
    "PixelYDimension": "Wysokość (EXIF)",
}
CAMERA = ["Make", "Model", "LensMake", "LensModel", "LensSpecification", "BodySerialNumber", "LensSerialNumber",
          "CameraOwnerName", "Software", "HostComputer", "Artist", "XPAuthor", "Copyright", "ImageDescription",
          "XPTitle", "XPComment", "XPSubject", "XPKeywords", "UserComment", "ImageUniqueID"]
DATES = ["DateTimeOriginal", "DateTimeDigitized", "DateTime", "OffsetTimeOriginal", "OffsetTime"]
SHOT = ["ExposureTime", "FNumber", "ISO", "FocalLength", "FocalLengthIn35mmFilm", "ExposureProgram",
        "ExposureBiasValue", "MeteringMode", "Flash", "WhiteBalance", "ExposureMode", "DigitalZoomRatio",
        "SceneCaptureType", "Orientation", "PixelXDimension", "PixelYDimension"]
SENSITIVE = {"BodySerialNumber", "LensSerialNumber", "CameraOwnerName", "Artist", "XPAuthor", "HostComputer"}
HIDDEN = {"ExifVersion", "XResolution", "YResolution", "ResolutionUnit", "SubSecTime", "SubSecTimeOriginal",
          "ShutterSpeedValue", "ApertureValue", "MaxApertureValue", "CustomRendered", "LightSource"}

ORIENTATION = {1: "normalna", 2: "odbicie poziome", 3: "obrót 180°", 4: "odbicie pionowe",
               5: "odbicie + obrót 90°", 6: "obrót 90° w prawo", 7: "odbicie + obrót 270°", 8: "obrót 90° w lewo"}
EXPOSURE_PROGRAM = {0: "nieokreślony", 1: "manualny", 2: "automatyczny", 3: "priorytet przysłony",
                    4: "priorytet migawki", 5: "kreatywny", 6: "akcja", 7: "portret", 8: "krajobraz"}
METERING = {0: "nieznany", 1: "średni", 2: "centralnie ważony", 3: "punktowy", 4: "wielopunktowy",
            5: "matrycowy", 6: "częściowy"}
XMP_KEYS = {
    "xmp:CreatorTool": "Program", "xmp:CreateDate": "Utworzono", "xmp:ModifyDate": "Zmodyfikowano",
    "photoshop:DateCreated": "Data (Photoshop)", "dc:creator": "Autor", "dc:rights": "Prawa autorskie",
    "dc:title": "Tytuł", "dc:description": "Opis", "photoshop:City": "Miasto", "photoshop:Country": "Kraj",
    "Iptc4xmpCore:Location": "Miejsce", "photoshop:Credit": "Źródło", "aux:SerialNumber": "Numer seryjny",
    "aux:Lens": "Obiektyw", "exif:GPSLatitude": "GPS – szerokość", "exif:GPSLongitude": "GPS – długość",
}


class _Tiff:
    def __init__(self, data: bytes) -> None:
        if data[:2] == b"II":
            self.endian = "<"
        elif data[:2] == b"MM":
            self.endian = ">"
        else:
            raise ValueError("niepoprawny nagłówek TIFF")
        self.data = data
        if self.u16(2) != 42:
            raise ValueError("niepoprawny nagłówek TIFF")

    def u16(self, offset: int) -> int:
        return struct.unpack_from(self.endian + "H", self.data, offset)[0]

    def u32(self, offset: int) -> int:
        return struct.unpack_from(self.endian + "I", self.data, offset)[0]

    def ifd(self, offset: int) -> dict[int, object]:
        entries: dict[int, object] = {}
        if offset <= 0 or offset + 2 > len(self.data):
            return entries
        for i in range(min(self.u16(offset), 1000)):
            pos = offset + 2 + i * 12
            if pos + 12 > len(self.data):
                break
            tag, typ, count = struct.unpack_from(self.endian + "HHI", self.data, pos)
            size = TYPE_SIZES.get(typ)
            if not size or size * count > 1_000_000:
                continue
            total = size * count
            start = pos + 8 if total <= 4 else self.u32(pos + 8)
            raw = self.data[start:start + total]
            if len(raw) < total:
                continue
            try:
                entries[tag] = self._decode(typ, raw, count)
            except (struct.error, ZeroDivisionError):
                continue
        return entries

    def _decode(self, typ: int, raw: bytes, count: int):
        if typ == 2:
            return raw.split(b"\0", 1)[0].decode("utf-8", errors="replace").strip()
        if typ in (1, 6, 7):
            return bytes(raw)
        if typ in (5, 10):
            fmt = "I" if typ == 5 else "i"
            nums = struct.unpack(self.endian + fmt * (2 * count), raw)
            values = tuple(Fraction(nums[i], nums[i + 1]) if nums[i + 1] else Fraction(0) for i in range(0, len(nums), 2))
        else:
            fmt = {3: "H", 4: "I", 8: "h", 9: "i", 11: "f", 12: "d"}[typ]
            values = struct.unpack(self.endian + fmt * count, raw)
        return values[0] if count == 1 else values


def parse_tiff(data: bytes) -> dict[str, dict[str, object]]:
    tiff = _Tiff(data)
    ifd0 = tiff.ifd(tiff.u32(4))
    out: dict[str, dict[str, object]] = {"image": {}, "exif": {}, "gps": {}}
    for tag, value in ifd0.items():
        if tag in IFD0_TAGS:
            out["image"][IFD0_TAGS[tag]] = value
    if isinstance(ifd0.get(0x8769), int):
        for tag, value in tiff.ifd(ifd0[0x8769]).items():
            if tag in EXIF_TAGS:
                out["exif"][EXIF_TAGS[tag]] = value
    if isinstance(ifd0.get(0x8825), int):
        for tag, value in tiff.ifd(ifd0[0x8825]).items():
            if tag in GPS_TAGS:
                out["gps"][GPS_TAGS[tag]] = value
    return out


# --- kontenery plików -----------------------------------------------------------

def detect_format(data: bytes) -> str:
    if data[:3] == b"\xff\xd8\xff":
        return "JPEG"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "PNG"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "WebP"
    if data[:4] in (b"II*\0", b"MM\0*"):
        return "TIFF"
    if data[4:8] == b"ftyp" and data[8:12] in (b"heic", b"heix", b"mif1", b"hevc", b"heim", b"heis"):
        return "HEIC"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "GIF"
    return "nieznany"


def _containers(kind: str, data: bytes) -> dict:
    info: dict = {"tiff": None, "xmp": None, "text": {}, "size": None}
    try:
        if kind == "JPEG":
            _jpeg(data, info)
        elif kind == "PNG":
            _png(data, info)
        elif kind == "WebP":
            _webp(data, info)
        elif kind == "TIFF":
            info["tiff"] = data
        elif kind == "GIF":
            info["size"] = struct.unpack("<HH", data[6:10])
    except (struct.error, IndexError, zlib.error):
        pass
    if info["tiff"] is None:  # np. HEIC – szukamy bloku EXIF bezpośrednio
        pos = data.find(b"Exif\x00\x00")
        if pos != -1:
            info["tiff"] = data[pos + 6:]
    if info["xmp"] is None:
        match = re.search(rb"<x:xmpmeta.*?</x:xmpmeta>", data[:4_000_000], re.S)
        if match:
            info["xmp"] = match.group(0).decode("utf-8", errors="replace")
    return info


def _jpeg(data: bytes, info: dict) -> None:
    pos = 2
    while pos + 4 <= len(data):
        if data[pos] != 0xFF:
            break
        marker = data[pos + 1]
        if marker == 0xFF:
            pos += 1
            continue
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        if marker in (0xD9, 0xDA):
            break
        length = struct.unpack(">H", data[pos + 2:pos + 4])[0]
        segment = data[pos + 4:pos + 2 + length]
        if marker == 0xE1:
            if segment.startswith(b"Exif\x00\x00") and info["tiff"] is None:
                info["tiff"] = segment[6:]
            elif segment.startswith(b"http://ns.adobe.com/xap/1.0/\x00"):
                info["xmp"] = segment[29:].decode("utf-8", errors="replace")
        elif marker == 0xFE:
            comment = segment.decode("utf-8", errors="replace").strip("\0 \r\n")
            if comment:
                info["text"]["Komentarz JPEG"] = comment
        elif marker in (0xC0, 0xC1, 0xC2) and len(segment) >= 5:
            height, width = struct.unpack(">HH", segment[1:5])
            info["size"] = (width, height)
        pos += 2 + length


def _png(data: bytes, info: dict) -> None:
    pos = 8
    while pos + 8 <= len(data):
        length, ctype = struct.unpack(">I4s", data[pos:pos + 8])
        chunk = data[pos + 8:pos + 8 + length]
        if ctype == b"IHDR":
            info["size"] = struct.unpack(">II", chunk[:8])
        elif ctype == b"eXIf":
            info["tiff"] = chunk
        elif ctype == b"tEXt":
            key, _, value = chunk.partition(b"\0")
            info["text"][key.decode("latin-1")] = value.decode("latin-1")
        elif ctype == b"zTXt":
            key, _, rest = chunk.partition(b"\0")
            info["text"][key.decode("latin-1")] = zlib.decompress(rest[1:]).decode("latin-1")
        elif ctype == b"iTXt":
            key, _, rest = chunk.partition(b"\0")
            compressed = rest[0] if rest else 0
            _lang, _, rest = rest[2:].partition(b"\0")
            _translated, _, text = rest.partition(b"\0")
            if compressed:
                text = zlib.decompress(text)
            name, value = key.decode("latin-1"), text.decode("utf-8", errors="replace")
            if name == "XML:com.adobe.xmp":
                info["xmp"] = value
            else:
                info["text"][name] = value
        elif ctype == b"IEND":
            break
        pos += 12 + length


def _webp(data: bytes, info: dict) -> None:
    pos = 12
    while pos + 8 <= len(data):
        ctype = data[pos:pos + 4]
        size = struct.unpack("<I", data[pos + 4:pos + 8])[0]
        chunk = data[pos + 8:pos + 8 + size]
        if ctype == b"EXIF":
            info["tiff"] = chunk[6:] if chunk.startswith(b"Exif\x00\x00") else chunk
        elif ctype == b"XMP ":
            info["xmp"] = chunk.decode("utf-8", errors="replace")
        elif ctype == b"VP8X" and size >= 10:
            info["size"] = (1 + int.from_bytes(chunk[4:7], "little"), 1 + int.from_bytes(chunk[7:10], "little"))
        elif ctype == b"VP8 " and size >= 10 and not info["size"]:
            width, height = struct.unpack("<HH", chunk[6:10])
            info["size"] = (width & 0x3FFF, height & 0x3FFF)
        elif ctype == b"VP8L" and size >= 5 and not info["size"]:
            bits = int.from_bytes(chunk[1:5], "little")
            info["size"] = ((bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1)
        pos += 8 + size + (size & 1)


# --- formatowanie ------------------------------------------------------------------

def _fmt(name: str, value) -> str:
    if isinstance(value, bytes):
        if name.startswith("XP"):
            return value.decode("utf-16-le", errors="replace").rstrip("\0").strip()
        if name in ("UserComment", "GPSProcessingMethod"):
            return value[8:].decode("utf-8", errors="replace").strip("\0 ")
        if name == "GPSVersionID":
            return ".".join(str(b) for b in value)
        if value and all(32 <= b < 127 for b in value):
            return value.decode("ascii")
        return value[:24].hex(" ") + (" …" if len(value) > 24 else "")
    if isinstance(value, tuple):
        return ", ".join(_fmt(name, v) for v in value)
    if isinstance(value, Fraction):
        number = float(value)
        if name == "ExposureTime":
            return f"1/{round(1 / number)} s" if 0 < number < 1 else f"{number:g} s"
        if name == "FNumber":
            return f"f/{number:.1f}"
        if name == "FocalLength":
            return f"{number:g} mm"
        if name == "ExposureBiasValue":
            return f"{number:+.1f} EV"
        return f"{number:.4g}"
    if name == "Orientation":
        return ORIENTATION.get(value, str(value))
    if name == "Flash" and isinstance(value, int):
        return "użyta" if value & 1 else "nie użyta"
    if name == "ExposureProgram":
        return EXPOSURE_PROGRAM.get(value, str(value))
    if name == "MeteringMode":
        return METERING.get(value, str(value))
    if name == "WhiteBalance":
        return {0: "automatyczny", 1: "manualny"}.get(value, str(value))
    if name == "ExposureMode":
        return {0: "automatyczny", 1: "manualny", 2: "bracketing"}.get(value, str(value))
    if name == "FocalLengthIn35mmFilm":
        return f"{value} mm"
    return str(value)


def _gps_coords(gps: dict) -> tuple[float, float] | None:
    lat, lon = gps.get("GPSLatitude"), gps.get("GPSLongitude")
    if not (isinstance(lat, tuple) and isinstance(lon, tuple) and len(lat) == 3 and len(lon) == 3):
        return None

    def dms(parts) -> float:
        return float(parts[0]) + float(parts[1]) / 60 + float(parts[2]) / 3600

    latitude, longitude = dms(lat), dms(lon)
    if str(gps.get("GPSLatitudeRef", "N")).upper().startswith("S"):
        latitude = -latitude
    if str(gps.get("GPSLongitudeRef", "E")).upper().startswith("W"):
        longitude = -longitude
    if latitude == 0 and longitude == 0:
        return None
    return round(latitude, 6), round(longitude, 6)


def _xmp_fields(xmp: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, label in XMP_KEYS.items():
        match = re.search(rf'{re.escape(key)}="([^"]*)"', xmp) or re.search(
            rf"<{re.escape(key)}>(.*?)</{re.escape(key)}>", xmp, re.S
        )
        if match:
            value = re.sub(r"<[^>]+>", " ", match.group(1))
            value = re.sub(r"\s+", " ", html.unescape(value)).strip()
            if value:
                out[label] = value[:200]
    return out


# --- punkt wejścia --------------------------------------------------------------------

def extract(target: str, progress: Progress = None) -> Report:
    source = target.strip().strip('"').strip("'")
    if not source:
        raise ValueError("Podaj ścieżkę do pliku lub adres URL zdjęcia.")
    report = Report("exif", source)
    file_sec = report.section("Plik")

    if re.match(r"^https?://", source, re.I):
        notify(progress, "Pobieram obraz…")
        resp = request(source, timeout=30, max_bytes=MAX_SIZE)
        if not resp.ok:
            raise NetError(f"HTTP {resp.status}")
        data = resp.body
        name = Path(urllib.parse.urlsplit(source).path).name or source
        file_sec.add("Źródło", source)
        file_sec.add("Typ (serwer)", resp.header("content-type"))
    else:
        path = Path(source).expanduser()
        if not path.is_file():
            raise ValueError(f"Plik nie istnieje: {path}")
        if path.stat().st_size > MAX_SIZE:
            raise ValueError("Plik jest zbyt duży (limit 64 MB).")
        data = path.read_bytes()
        name = path.name
        file_sec.add("Ścieżka", str(path.resolve()))
        file_sec.add("Zmodyfikowano (dysk)", datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"))

    notify(progress, "Analizuję metadane…")
    kind = detect_format(data)
    containers = _containers(kind, data)
    file_sec.add("Nazwa", name)
    file_sec.add("Format", kind)
    file_sec.add("Rozmiar", human_size(len(data)))
    if containers["size"]:
        width, height = containers["size"]
        file_sec.add("Wymiary", f"{width} × {height} px")
    file_sec.add("MD5", hashlib.md5(data).hexdigest())
    file_sec.add("SHA-256", hashlib.sha256(data).hexdigest())

    meta: dict[str, dict[str, object]] = {"image": {}, "exif": {}, "gps": {}}
    if containers["tiff"]:
        try:
            meta = parse_tiff(containers["tiff"])
        except (ValueError, struct.error) as exc:
            report.section("EXIF").error = f"Uszkodzone dane EXIF: {exc}"
    tags = {**meta["image"], **meta["exif"]}

    def group(title: str, names: list[str]) -> None:
        sec = report.section(title)
        for tag in names:
            if tag in tags:
                text = _fmt(tag, tags[tag])
                sec.add(LABELS.get(tag, tag), text, WARN if tag in SENSITIVE else None)

    group("Aparat i autor", CAMERA)
    group("Daty", DATES)
    group("Parametry zdjęcia", SHOT)

    gps = meta["gps"]
    if gps:
        gsec = report.section("Lokalizacja GPS")
        coords = _gps_coords(gps)
        if coords:
            lat, lon = coords
            gsec.note = "Zdjęcie zawiera dokładną lokalizację miejsca wykonania!"
            gsec.add("Współrzędne", f"{lat}, {lon}", WARN)
            gsec.add("Google Maps", f"https://www.google.com/maps?q={lat},{lon}")
            gsec.add("OpenStreetMap", f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=17/{lat}/{lon}")
        altitude = gps.get("GPSAltitude")
        if isinstance(altitude, Fraction):
            below = gps.get("GPSAltitudeRef") in (b"\x01", 1)
            gsec.add("Wysokość", f"{'-' if below else ''}{float(altitude):.1f} m n.p.m.")
        stamp = gps.get("GPSTimeStamp")
        if isinstance(stamp, tuple) and len(stamp) == 3:
            clock = ":".join(f"{int(float(v)):02d}" for v in stamp)
            gsec.add("Czas GPS (UTC)", f"{gps.get('GPSDateStamp', '')} {clock}".strip())
        if isinstance(gps.get("GPSImgDirection"), Fraction):
            gsec.add("Kierunek zdjęcia", f"{float(gps['GPSImgDirection']):.0f}°")
        if isinstance(gps.get("GPSSpeed"), Fraction):
            gsec.add("Prędkość", f"{float(gps['GPSSpeed']):.1f} {gps.get('GPSSpeedRef', '')}")
        gsec.add("Metoda", _fmt("GPSProcessingMethod", gps["GPSProcessingMethod"]) if "GPSProcessingMethod" in gps else None)

    known = set(CAMERA) | set(DATES) | set(SHOT) | HIDDEN
    rest = {k: v for k, v in tags.items() if k not in known}
    if rest:
        osec = report.section("Pozostałe tagi EXIF")
        for tag, value in rest.items():
            osec.add(tag, _fmt(tag, value))

    if containers["xmp"]:
        xmp = _xmp_fields(containers["xmp"])
        if xmp:
            xsec = report.section("Metadane XMP")
            for key, value in xmp.items():
                xsec.add(key, value)
    if containers["text"]:
        tsec = report.section("Metadane tekstowe")
        for key, value in containers["text"].items():
            tsec.add(key, value[:300] + ("…" if len(value) > 300 else ""))

    if not tags and not gps and not containers["xmp"] and not containers["text"]:
        sec = report.section("Metadane")
        sec.note = ("Nie znaleziono metadanych – mogły zostać usunięte "
                    "(robią to m.in. Facebook, Instagram, WhatsApp, Discord).")
    elif not gps:
        report.section("Lokalizacja GPS").add("GPS", "brak danych o lokalizacji", MUTED)
    return report
