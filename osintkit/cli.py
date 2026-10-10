"""Interfejs wiersza poleceń: polecenia, tryb interaktywny i kolorowe raporty."""
from __future__ import annotations

import argparse
import itertools
import os
import shutil
import sys
import textwrap
import threading
import time

from . import APP_NAME, __version__
from .net import NetError
from .registry import BY_KEY, TOOLS, run_tool
from .report import BAD, MUTED, OK, WARN, Report, Section

BANNER = r"""
  __  __        ____                     ___   ____   ___  _   _  _____
 |  \/  | _ __ |  _ \   ___   ___  ___  / _ \ / ___| |_ _|| \ | ||_   _|
 | |\/| || '__|| |_) | / _ \ / __|/ __|| | | |\___ \  | | |  \| |  | |
 | |  | || |   |  _ < | (_) |\__ \\__ \| |_| | ___) | | | | |\  |  | |
 |_|  |_||_|   |_| \_\ \___/ |___/|___/ \___/ |____/ |___||_| \_|  |_|"""

CODES = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m", "red": "\033[91m", "green": "\033[92m",
    "yellow": "\033[93m", "blue": "\033[94m", "cyan": "\033[96m", "gray": "\033[90m", "white": "\033[97m",
}
STYLE_COLORS = {OK: ("green",), BAD: ("red",), WARN: ("yellow",), MUTED: ("gray",)}


class Painter:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, *styles: str) -> str:
        if not self.enabled or not styles:
            return text
        return "".join(CODES[s] for s in styles) + text + CODES["reset"]

    def style(self, text: str, style: str | None) -> str:
        return self(text, *STYLE_COLORS.get(style or "", ()))


def _enable_vt(handle_id: int) -> bool:
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(handle_id)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


def setup_console() -> tuple[bool, bool]:
    """Ustawia UTF-8 i kolory ANSI. Zwraca (kolory na stdout, interaktywny stderr)."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
    live = sys.stderr.isatty()
    if os.name == "nt":
        if color:
            color = _enable_vt(-11)
        if live:
            live = _enable_vt(-12)
    return color, live


class Spinner:
    """Pokazuje postęp na stderr w jednej linii (tylko w terminalu)."""

    FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self, paint: Painter, enabled: bool) -> None:
        self.paint = paint
        self.enabled = enabled
        self.message = ""
        self.fraction: float | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None

    def __enter__(self) -> Spinner:
        if self.enabled:
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join()
            sys.stderr.write("\r\033[K")
            sys.stderr.flush()

    def update(self, message: str, fraction: float | None = None) -> None:
        with self._lock:
            self.message = message
            if fraction is not None:
                self.fraction = fraction

    def _loop(self) -> None:
        width = shutil.get_terminal_size((100, 20)).columns
        for frame in itertools.cycle(self.FRAMES):
            if self._stop.is_set():
                return
            with self._lock:
                message, fraction = self.message, self.fraction
            bar = ""
            if fraction is not None:
                filled = int(fraction * 20)
                bar = "█" * filled + "░" * (20 - filled) + f" {int(fraction * 100):3d}%  "
            room = max(10, width - len(bar) - 4)
            text = message if len(message) <= room else message[: room - 1] + "…"
            sys.stderr.write("\r\033[K" + self.paint(frame, "cyan") + " " + self.paint(bar, "cyan") + self.paint(text, "gray"))
            sys.stderr.flush()
            time.sleep(0.08)


# --- renderowanie raportu ---------------------------------------------------------

def _wrap(text: str, width: int) -> list[str]:
    lines: list[str] = []
    for paragraph in text.splitlines() or [""]:
        lines.extend(textwrap.wrap(paragraph, width, break_long_words=False, break_on_hyphens=False) or [""])
    return lines


def _render_table(sec: Section, paint: Painter, width: int) -> list[str]:
    headers = sec.headers or [""] * len(sec.rows[0])
    ncol = len(headers)
    widths = [len(h) for h in headers]
    for row in sec.rows:
        for i, cell in enumerate(row[:ncol]):
            widths[i] = max(widths[i], len(cell))
    widths = [min(w, 80) for w in widths]
    available = width - 2 - 2 * (ncol - 1)
    while sum(widths) > available and max(widths) > 10:
        widths[widths.index(max(widths))] -= 1

    def fit(text: str, w: int) -> str:
        return text.ljust(w) if len(text) <= w else text[: w - 1] + "…"

    out = []
    if any(headers):
        out.append("  " + paint("  ".join(fit(h, w) for h, w in zip(headers, widths)).rstrip(), "bold", "gray"))
        out.append("  " + paint("─" * min(width - 2, sum(widths) + 2 * (ncol - 1)), "gray"))
    for row, style in zip(sec.rows, sec.row_styles):
        cells = [fit(row[i] if i < len(row) else "", w) for i, w in enumerate(widths)]
        if style == OK:
            line = paint(cells[0], "green") + "  " + "  ".join(cells[1:]) if ncol > 1 else paint(cells[0], "green")
        else:
            line = paint.style("  ".join(cells), style)
        out.append("  " + line.rstrip())
    return out


def render(report: Report, paint: Painter, width: int | None = None) -> str:
    width = width or min(shutil.get_terminal_size((110, 24)).columns, 140)
    out = [
        "",
        paint("◆ ", "cyan") + paint(report.heading, "bold", "white") + paint("  →  ", "gray") + paint(report.target, "bold", "cyan"),
        paint(f"  {report.created:%Y-%m-%d %H:%M:%S} · {report.duration:.1f} s", "gray"),
    ]
    for sec in report.visible_sections:
        title = f"── {sec.title} "
        out += ["", paint(title + "─" * max(0, width - len(title) - 1), "cyan")]
        if sec.error:
            out.append("  " + paint(f"✗ {sec.error}", "red"))
        if sec.note:
            for line in _wrap(f"ℹ {sec.note}", width - 4):
                out.append("  " + paint(line, "yellow"))
        if sec.fields:
            key_width = min(max(len(f.key) for f in sec.fields), 26)
            value_width = max(20, width - key_width - 6)
            for f in sec.fields:
                lines = _wrap(f.value, value_width)
                out.append(f"  {paint(f.key.ljust(key_width), 'gray')}  {paint.style(lines[0], f.style)}")
                out += [" " * (key_width + 4) + paint.style(line, f.style) for line in lines[1:]]
        if sec.rows:
            if sec.fields:
                out.append("")
            out += _render_table(sec, paint, width)
        if sec.text:
            out += ["  " + paint(line, "dim") for line in sec.text.splitlines()]
    return "\n".join(out) + "\n"


# --- uruchamianie --------------------------------------------------------------------

def execute(key: str, target: str, paint: Painter, live: bool) -> tuple[int, Report | None]:
    """Uruchamia narzędzie ze spinnerem. Zwraca (kod wyjścia, raport lub None)."""
    try:
        with Spinner(paint, live) as spinner:
            return 0, run_tool(key, target, progress=spinner.update)
    except KeyboardInterrupt:
        print(paint("\nPrzerwano.", "yellow"), file=sys.stderr)
        return 130, None
    except ValueError as exc:
        print(paint(f"✗ {exc}", "red"), file=sys.stderr)
        return 2, None
    except NetError as exc:
        print(paint(f"✗ Błąd sieci: {exc}", "red"), file=sys.stderr)
        return 1, None
    except Exception as exc:  # ostatnia linia obrony – nie pokazujemy tracebacku użytkownikowi
        print(paint(f"✗ Nieoczekiwany błąd: {type(exc).__name__}: {exc}", "red"), file=sys.stderr)
        return 1, None


def save_report(report: Report, path: str, paint: Painter) -> bool:
    try:
        saved = report.save(path)
    except (OSError, ValueError) as exc:
        print(paint(f"✗ Nie zapisano raportu: {exc}", "red"), file=sys.stderr)
        return False
    print(paint(f"✓ Zapisano raport: {saved}", "green"), file=sys.stderr)
    return True


def interactive(paint: Painter, live: bool) -> int:
    print(paint(BANNER, "cyan", "bold") + paint(f"\n  {APP_NAME} v{__version__}", "gray"))
    print(paint("  Pasywny rekonesans z publicznych źródeł. Używaj legalnie i etycznie.\n", "gray"))
    while True:
        print(paint("  Moduły:", "bold"))
        for i, tool in enumerate(TOOLS, 1):
            print(f"  {paint(f'{i:>2}', 'cyan')}  {tool.label:<22} {paint(tool.description, 'gray')}")
        print(f"  {paint(' g', 'cyan')}  {'Interfejs graficzny':<22}")
        print(f"  {paint(' q', 'cyan')}  Wyjście\n")
        try:
            choice = input(paint("› Wybierz moduł: ", "bold")).strip().lstrip("﻿").lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if choice in ("q", "0", "exit", "quit", "wyjdz", "wyjście"):
            return 0
        if choice == "g":
            from .gui import main as gui_main

            return gui_main()
        tool = None
        if choice.isdigit() and 1 <= int(choice) <= len(TOOLS):
            tool = TOOLS[int(choice) - 1]
        elif choice in BY_KEY:
            tool = BY_KEY[choice]
        if not tool:
            print(paint("  Nieznany wybór.\n", "yellow"))
            continue
        try:
            target = input(paint(f"› {tool.label} – cel (np. {tool.placeholder}): ", "bold")).strip().lstrip("﻿")
            if not target:
                print()
                continue
            _, report = execute(tool.key, target, paint, live)
            if report:
                print(render(report, paint))
                path = input(paint("› Zapisać raport? Podaj plik .html/.json/.md lub Enter: ", "bold")).strip()
                if path:
                    save_report(report, path, paint)
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        print()


def build_parser() -> argparse.ArgumentParser:
    examples = "\n".join(f"  osint {t.key:<11} {t.placeholder.split(' lub ')[0]}" for t in TOOLS)
    parser = argparse.ArgumentParser(
        prog="osint",
        description=f"{APP_NAME} – pasywny rekonesans (CLI + GUI). Bez argumentów uruchamia menu.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Przykłady:\n{examples}\n  osint domain example.com -o raport.html\n  osint gui",
    )
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="<moduł>")
    for tool in TOOLS:
        sp = sub.add_parser(tool.key, help=tool.label, description=tool.description)
        sp.add_argument("target", help=f"cel, np. {tool.placeholder}")
        sp.add_argument("--json", action="store_true", help="wypisz wynik jako JSON")
        sp.add_argument("-o", "--output", metavar="PLIK", help="zapisz raport (.html, .json lub .md)")
        sp.add_argument("--no-color", action="store_true", help="wyłącz kolory")
    sub.add_parser("gui", help="uruchom interfejs graficzny")
    sub.add_parser("menu", help="tryb interaktywny (domyślny)")
    return parser


def main(argv: list[str] | None = None) -> int:
    color, live = setup_console()
    args = build_parser().parse_args(argv)
    if args.command == "gui":
        from .gui import main as gui_main

        return gui_main()
    if args.command in (None, "menu"):
        return interactive(Painter(color), live)
    paint = Painter(color and not args.no_color)
    code, report = execute(args.command, args.target, paint, live and not args.json)
    if report is None:
        return code
    print(report.to_json() if args.json else render(report, paint))
    if args.output and not save_report(report, args.output, paint):
        return 1
    return 0
