"""Interfejs graficzny (tkinter): ciemny motyw, praca w tle, historia i eksport raportów."""
from __future__ import annotations

import queue
import re
import sys
import tempfile
import threading
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter import font as tkfont

from . import APP_NAME, __version__
from .net import NetError
from .registry import BY_KEY, TOOLS, Tool, run_tool
from .report import URL_RE, Report, Section

C = {
    "bg": "#0d1117", "side": "#010409", "panel": "#161b22", "panel2": "#21262d", "border": "#30363d",
    "hover": "#1c2128", "text": "#e6edf3", "muted": "#8b949e", "accent": "#2dd4bf", "accent_hover": "#5eead4",
    "accent_fg": "#042f2e", "ok": "#3fb950", "bad": "#f85149", "warn": "#d29922", "link": "#58a6ff",
    "select": "#264f78",
}
STYLE_COLORS = {"ok": C["ok"], "bad": C["bad"], "warn": C["warn"], "muted": C["muted"]}
MAX_ROWS = 1500
HISTORY_LIMIT = 50


def _pick_font(root: tk.Misc, candidates: tuple[str, ...], fallback: str) -> str:
    families = set(tkfont.families(root))
    return next((name for name in candidates if name in families), fallback)


class FlatButton(tk.Label):
    """Płaski przycisk z efektem najechania (tk.Button źle wygląda w ciemnym motywie)."""

    def __init__(self, parent, text: str, command, accent: bool = False, font=None, padx=16, pady=8) -> None:
        self.colors = (
            (C["accent"], C["accent_hover"], C["accent_fg"]) if accent else (C["panel2"], C["border"], C["text"])
        )
        super().__init__(parent, text=text, bg=self.colors[0], fg=self.colors[2], font=font,
                         padx=padx, pady=pady, cursor="hand2")
        self.command = command
        self.enabled = True
        self.bind("<Enter>", lambda _e: self.enabled and self.config(bg=self.colors[1]))
        self.bind("<Leave>", lambda _e: self.config(bg=self.colors[0]))
        self.bind("<Button-1>", lambda _e: self.enabled and self.command())

    def set_enabled(self, enabled: bool, text: str | None = None) -> None:
        self.enabled = enabled
        self.config(fg=self.colors[2] if enabled else C["muted"], cursor="hand2" if enabled else "arrow",
                    bg=self.colors[0])
        if text:
            self.config(text=text)


class ThinProgress(tk.Frame):
    """Cienki pasek postępu (ttk w motywie clam nie pozwala zmniejszyć grubości)."""

    def __init__(self, parent, height: int) -> None:
        super().__init__(parent, bg=C["panel"], height=height)
        self.bar = tk.Frame(self, bg=C["accent"])
        self._pos = 0.0
        self._job: str | None = None
        self.set(0)

    def set(self, fraction: float) -> None:
        self.stop()
        if fraction <= 0:
            self.bar.place_forget()
        else:
            self.bar.place(relx=0, rely=0, relheight=1, relwidth=min(1.0, fraction))

    def start(self) -> None:
        if self._job is None:
            self._animate()

    def stop(self) -> None:
        if self._job is not None:
            self.after_cancel(self._job)
            self._job = None

    def _animate(self) -> None:
        self._pos = self._pos + 0.012 if self._pos < 1.0 else -0.3
        self.bar.place(relx=self._pos, rely=0, relheight=1, relwidth=0.3)
        self._job = self.after(16, self._animate)


class OsintApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.events: queue.Queue = queue.Queue()
        self.tool: Tool = TOOLS[0]
        self.report: Report | None = None
        self.history: list[Report] = []
        self.running = False
        self.placeholder_on = False
        self.links: dict[str, str] = {}

        self.scale = root.winfo_fpixels("1i") / 96
        ui = _pick_font(root, ("Segoe UI", "SF Pro Text", "Helvetica Neue", "Ubuntu", "DejaVu Sans"), "Arial")
        mono = _pick_font(root, ("Cascadia Mono", "Consolas", "JetBrains Mono", "Menlo", "DejaVu Sans Mono"), "Courier New")
        self.font = {
            "ui": (ui, 10), "ui_b": (ui, 10, "bold"), "small": (ui, 9), "small_b": (ui, 8, "bold"),
            "logo": (ui, 13, "bold"), "title": (ui, 18, "bold"), "h1": (ui, 15, "bold"), "h2": (ui, 11, "bold"),
            "entry": (ui, 12), "mono": (mono, 10), "mono_b": (mono, 10, "bold"), "mono_s": (mono, 9),
            "italic": (ui, 10, "italic"),
        }
        self.ui_metrics = tkfont.Font(root, family=ui, size=10)
        self.mono_metrics = tkfont.Font(root, family=mono, size=10)

        self._style()
        self._build()
        self._bind_keys()
        self.select_tool(self.tool.key)
        self.show_welcome()
        root.after(60, self._pump)

    def px(self, value: float) -> int:
        return int(value * self.scale)

    # --- budowa interfejsu --------------------------------------------------------

    def _style(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("Osint.Vertical.TScrollbar", background=C["panel2"], troughcolor=C["panel"],
                        bordercolor=C["panel"], arrowcolor=C["muted"], lightcolor=C["panel2"],
                        darkcolor=C["panel2"], gripcount=0, arrowsize=self.px(12))
        style.map("Osint.Vertical.TScrollbar", background=[("active", C["border"])])

    def _build(self) -> None:
        root, px = self.root, self.px
        root.configure(bg=C["bg"])
        root.columnconfigure(1, weight=1)
        root.rowconfigure(0, weight=1)

        # --- pasek boczny
        side = tk.Frame(root, bg=C["side"], width=px(250))
        side.grid(row=0, column=0, sticky="ns")
        side.pack_propagate(False)

        logo = tk.Frame(side, bg=C["side"])
        logo.pack(fill="x", padx=px(20), pady=(px(20), px(14)))
        tk.Label(logo, text=f"◉ {APP_NAME}", font=self.font["logo"], fg=C["accent"], bg=C["side"]).pack(anchor="w")
        tk.Label(logo, text="rekonesans pasywny · OSINT", font=self.font["small"], fg=C["muted"],
                 bg=C["side"]).pack(anchor="w")

        self._side_label(side, "MODUŁY")
        self.items: dict[str, tuple[tk.Frame, tk.Frame, tk.Label, tk.Label]] = {}
        for tool in TOOLS:
            self._tool_item(side, tool)

        tk.Label(side, text=f"v{__version__} · tylko publiczne źródła", font=self.font["small"], fg=C["border"],
                 bg=C["side"]).pack(side="bottom", anchor="w", padx=px(20), pady=px(12))
        self._side_label(side, "HISTORIA")
        self.history_box = tk.Listbox(
            side, bg=C["side"], fg=C["muted"], selectbackground=C["panel2"], selectforeground=C["text"],
            activestyle="none", highlightthickness=0, bd=0, font=self.font["small"], exportselection=False,
        )
        self.history_box.pack(fill="both", expand=True, padx=px(14), pady=(0, px(4)))
        self.history_box.bind("<<ListboxSelect>>", self._open_history)

        # --- część główna
        main = tk.Frame(root, bg=C["bg"])
        main.grid(row=0, column=1, sticky="nsew")
        main.columnconfigure(0, weight=1)
        main.rowconfigure(3, weight=1)
        pad = px(28)

        head = tk.Frame(main, bg=C["bg"])
        head.grid(row=0, column=0, sticky="ew", padx=pad, pady=(px(22), px(12)))
        self.title_lbl = tk.Label(head, font=self.font["title"], fg=C["text"], bg=C["bg"], anchor="w")
        self.title_lbl.pack(fill="x")
        self.desc_lbl = tk.Label(head, font=self.font["ui"], fg=C["muted"], bg=C["bg"], anchor="w", justify="left")
        self.desc_lbl.pack(fill="x")

        bar = tk.Frame(main, bg=C["bg"])
        bar.grid(row=1, column=0, sticky="ew", padx=pad)
        bar.columnconfigure(0, weight=1)
        self.entry_border = tk.Frame(bar, bg=C["border"], padx=1, pady=1)
        self.entry_border.grid(row=0, column=0, sticky="ew")
        inner = tk.Frame(self.entry_border, bg=C["panel"])
        inner.pack(fill="both", expand=True)
        self.entry = tk.Entry(inner, font=self.font["entry"], bg=C["panel"], fg=C["text"], relief="flat", bd=0,
                              insertbackground=C["text"], highlightthickness=0, selectbackground=C["select"])
        self.entry.pack(fill="x", padx=px(12), pady=px(9))
        self.entry.bind("<FocusIn>", self._focus_in)
        self.entry.bind("<FocusOut>", self._focus_out)
        self.entry.bind("<Return>", lambda _e: self.start())

        self.browse_btn = FlatButton(bar, "Przeglądaj…", self.browse, font=self.font["ui_b"],
                                     padx=px(14), pady=px(9))
        self.run_btn = FlatButton(bar, "Szukaj  ▶", self.start, accent=True, font=self.font["ui_b"],
                                  padx=px(20), pady=px(9))
        self.run_btn.grid(row=0, column=2, sticky="ns", padx=(px(10), 0))

        status = tk.Frame(main, bg=C["bg"])
        status.grid(row=2, column=0, sticky="ew", padx=pad, pady=(px(12), px(10)))
        self.progress = ThinProgress(status, height=max(3, px(3)))
        self.progress.pack(fill="x")
        self.status_lbl = tk.Label(status, text="Gotowy.", font=self.font["small"], fg=C["muted"], bg=C["bg"],
                                   anchor="w")
        self.status_lbl.pack(fill="x", pady=(px(5), 0))

        card = tk.Frame(main, bg=C["panel"], highlightthickness=1, highlightbackground=C["border"])
        card.grid(row=3, column=0, sticky="nsew", padx=pad)
        card.rowconfigure(0, weight=1)
        card.columnconfigure(0, weight=1)
        self.text = tk.Text(card, bg=C["panel"], fg=C["text"], relief="flat", bd=0, highlightthickness=0,
                            wrap="word", font=self.font["ui"], padx=px(20), pady=px(16), cursor="arrow",
                            insertbackground=C["panel"], selectbackground=C["select"], spacing1=1, spacing3=1)
        self.text.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(card, orient="vertical", command=self.text.yview, style="Osint.Vertical.TScrollbar")
        scroll.grid(row=0, column=1, sticky="ns")
        self.text.configure(yscrollcommand=scroll.set)
        self._text_tags()

        footer = tk.Frame(main, bg=C["bg"])
        footer.grid(row=4, column=0, sticky="ew", padx=pad, pady=(px(12), px(20)))
        buttons = [("Eksportuj…", self.export), ("Otwórz w przeglądarce", self.open_in_browser),
                   ("Kopiuj", self.copy), ("Wyczyść", self.clear)]
        for label, command in buttons:
            FlatButton(footer, label, command, font=self.font["ui"], padx=px(14), pady=px(6)).pack(
                side="left", padx=(0, px(8)))
        tk.Label(footer, text="Enter – szukaj   ·   Ctrl+S – eksport   ·   Ctrl+L – pole wyszukiwania",
                 font=self.font["small"], fg=C["muted"], bg=C["bg"]).pack(side="right")

    def _side_label(self, parent, text: str) -> None:
        tk.Label(parent, text=text, font=self.font["small_b"], fg=C["muted"], bg=C["side"]).pack(
            anchor="w", padx=self.px(20), pady=(self.px(14), self.px(6)))

    def _tool_item(self, parent, tool: Tool) -> None:
        row = tk.Frame(parent, bg=C["side"], cursor="hand2")
        row.pack(fill="x", padx=self.px(10))
        bar = tk.Frame(row, bg=C["side"], width=self.px(3))
        bar.pack(side="left", fill="y")
        icon = tk.Label(row, text=tool.icon, font=self.font["ui"], fg=C["muted"], bg=C["side"], width=2,
                        anchor="center", cursor="hand2")
        icon.pack(side="left", padx=(self.px(10), 0))
        label = tk.Label(row, text=tool.label, font=self.font["ui"], fg=C["muted"], bg=C["side"], anchor="w",
                         padx=self.px(8), pady=self.px(6), cursor="hand2")
        label.pack(side="left", fill="x", expand=True)
        for widget in (row, icon, label):
            widget.bind("<Button-1>", lambda _e, k=tool.key: self.select_tool(k, focus=True))
            widget.bind("<Enter>", lambda _e, k=tool.key: self._hover(k, True))
            widget.bind("<Leave>", lambda _e, k=tool.key: self._hover(k, False))
        self.items[tool.key] = (row, bar, icon, label)

    def _hover(self, key: str, inside: bool) -> None:
        if key == self.tool.key:
            return
        color = C["hover"] if inside else C["side"]
        for widget in self.items[key]:
            widget.config(bg=color)

    def _text_tags(self) -> None:
        t, px = self.text, self.px
        t.tag_configure("h1", font=self.font["h1"], foreground=C["text"], spacing3=px(2))
        t.tag_configure("meta", font=self.font["small"], foreground=C["muted"], spacing3=px(4))
        t.tag_configure("section", font=self.font["h2"], foreground=C["accent"], spacing1=px(18), spacing3=px(6))
        t.tag_configure("key", foreground=C["muted"])
        t.tag_configure("val", foreground=C["text"])
        for name, color in STYLE_COLORS.items():
            t.tag_configure(name, foreground=color)
        t.tag_configure("error", foreground=C["bad"], lmargin1=px(4), lmargin2=px(22))
        t.tag_configure("note", foreground=C["warn"], font=self.font["italic"], lmargin1=px(4), lmargin2=px(22))
        t.tag_configure("mono", font=self.font["mono"])
        t.tag_configure("th", font=self.font["mono_b"], foreground=C["muted"])
        t.tag_configure("table", wrap="none", lmargin1=px(4))
        t.tag_configure("pre", font=self.font["mono_s"], foreground=C["muted"], wrap="char", lmargin1=px(4),
                        lmargin2=px(4))
        t.tag_configure("tool_link", foreground=C["text"], font=self.font["ui_b"])
        t.tag_configure("link", foreground=C["link"], underline=True)
        t.tag_bind("link", "<Enter>", lambda _e: t.config(cursor="hand2"))
        t.tag_bind("link", "<Leave>", lambda _e: t.config(cursor="arrow"))
        t.tag_bind("link", "<Button-1>", self._click_link)
        t.tag_bind("tool_link", "<Enter>", lambda _e: t.config(cursor="hand2"))
        t.tag_bind("tool_link", "<Leave>", lambda _e: t.config(cursor="arrow"))

    def _bind_keys(self) -> None:
        self.root.bind("<Control-s>", lambda _e: self.export())
        self.root.bind("<Control-l>", lambda _e: (self.entry.focus_set(), self.entry.select_range(0, "end")))
        # pole tekstowe raportu: tylko do odczytu, ale z możliwością zaznaczania i kopiowania
        self.text.bind("<Key>", lambda e: None if (e.state & 0x4 and e.keysym.lower() in ("c", "a")) else "break")
        self.text.bind("<Control-a>", lambda _e: (self.text.tag_add("sel", "1.0", "end"), "break")[1])

    # --- pole wyszukiwania --------------------------------------------------------------

    def _show_placeholder(self) -> None:
        if self.entry.get() and not self.placeholder_on:
            return
        self.entry.delete(0, "end")
        self.entry.insert(0, f"np. {self.tool.placeholder}")
        self.entry.config(fg=C["muted"])
        self.placeholder_on = True

    def _focus_in(self, _event=None) -> None:
        self.entry_border.config(bg=C["accent"])
        if self.placeholder_on:
            self.entry.delete(0, "end")
            self.entry.config(fg=C["text"])
            self.placeholder_on = False

    def _focus_out(self, _event=None) -> None:
        self.entry_border.config(bg=C["border"])
        if not self.entry.get():
            self._show_placeholder()

    def entry_value(self) -> str:
        return "" if self.placeholder_on else self.entry.get().strip()

    def set_entry(self, value: str) -> None:
        self.placeholder_on = False
        self.entry.config(fg=C["text"])
        self.entry.delete(0, "end")
        self.entry.insert(0, value)

    # --- akcje ------------------------------------------------------------------------------

    def select_tool(self, key: str, focus: bool = False) -> None:
        self.tool = BY_KEY[key]
        for item_key, (row, bar, icon, label) in self.items.items():
            active = item_key == key
            bg = C["panel"] if active else C["side"]
            row.config(bg=bg)
            icon.config(bg=bg, fg=C["accent"] if active else C["muted"])
            label.config(bg=bg, fg=C["text"] if active else C["muted"], font=self.font["ui_b" if active else "ui"])
            bar.config(bg=C["accent"] if active else bg)
        self.title_lbl.config(text=f"{self.tool.icon}  {self.tool.label}")
        self.desc_lbl.config(text=self.tool.description)
        if self.tool.input_kind == "file":
            self.browse_btn.grid(row=0, column=1, sticky="ns", padx=(self.px(10), 0))
        else:
            self.browse_btn.grid_remove()
        if self.placeholder_on or not self.entry.get():
            if self.root.focus_get() is self.entry:
                self.placeholder_on = False
            else:
                self.placeholder_on = True
                self._show_placeholder()
        if focus:
            self.entry.focus_set()

    def browse(self) -> None:
        path = filedialog.askopenfilename(
            parent=self.root, title="Wybierz zdjęcie",
            filetypes=[("Obrazy", "*.jpg *.jpeg *.png *.webp *.tif *.tiff *.heic"), ("Wszystkie pliki", "*.*")],
        )
        if path:
            self.set_entry(str(Path(path)))
            self.start()

    def start(self) -> None:
        if self.running:
            return
        target = self.entry_value()
        if not target:
            self._set_status("Wpisz cel wyszukiwania.", C["warn"])
            self.entry_border.config(bg=C["bad"])
            self.root.after(700, lambda: self.entry_border.config(
                bg=C["accent"] if self.root.focus_get() is self.entry else C["border"]))
            self.entry.focus_set()
            return
        self.running = True
        self.run_btn.set_enabled(False, "Szukam…")
        self._progress(f"{self.tool.label}: {target}", None)
        self._render_loading(self.tool, target)
        threading.Thread(target=self._worker, args=(self.tool.key, target), daemon=True).start()

    def _worker(self, key: str, target: str) -> None:
        def progress(message: str, fraction: float | None = None) -> None:
            self.events.put(("progress", message, fraction))

        try:
            report = run_tool(key, target, progress=progress)
        except (ValueError, NetError) as exc:
            self.events.put(("error", str(exc)))
        except Exception as exc:  # GUI nie może się wyłożyć na błędzie modułu
            self.events.put(("error", f"Nieoczekiwany błąd: {type(exc).__name__}: {exc}"))
        else:
            self.events.put(("done", report))

    def _pump(self) -> None:
        try:
            while True:
                event = self.events.get_nowait()
                if event[0] == "progress":
                    self._progress(event[1], event[2])
                elif event[0] == "done":
                    self._finish()
                    self._add_history(event[1])
                    self.show_report(event[1])
                elif event[0] == "error":
                    self._finish()
                    self.show_error(event[1])
        except queue.Empty:
            pass
        self.root.after(60, self._pump)

    def _progress(self, message: str, fraction: float | None) -> None:
        self._set_status(message)
        if fraction is None:
            self.progress.start()
        else:
            self.progress.set(fraction)

    def _finish(self) -> None:
        self.running = False
        self.run_btn.set_enabled(True, "Szukaj  ▶")
        self.progress.set(0)

    def _set_status(self, text: str, color: str | None = None) -> None:
        self.status_lbl.config(text=text, fg=color or C["muted"])

    def _add_history(self, report: Report) -> None:
        self.history.insert(0, report)
        del self.history[HISTORY_LIMIT:]
        self.history_box.delete(0, "end")
        for item in self.history:
            self.history_box.insert("end", f" {item.created:%H:%M}  {BY_KEY[item.tool].short}: {item.target}")

    def _open_history(self, _event=None) -> None:
        selection = self.history_box.curselection()
        if not selection or self.running:
            return
        report = self.history[selection[0]]
        self.select_tool(report.tool)
        self.set_entry(report.target)
        self.show_report(report)

    def export(self) -> None:
        if not self.report:
            self._set_status("Brak raportu do eksportu.", C["warn"])
            return
        safe = re.sub(r"[^\w.-]+", "_", self.report.target)[:40].strip("_")
        path = filedialog.asksaveasfilename(
            parent=self.root, title="Zapisz raport",
            initialfile=f"osint_{self.report.tool}_{safe}_{self.report.created:%Y%m%d_%H%M}",
            defaultextension=".html",
            filetypes=[("Raport HTML", "*.html"), ("JSON", "*.json"), ("Markdown", "*.md")],
        )
        if not path:
            return
        try:
            saved = self.report.save(path)
        except (OSError, ValueError) as exc:
            messagebox.showerror("Eksport", str(exc), parent=self.root)
            return
        self._set_status(f"Zapisano raport: {saved}", C["ok"])

    def open_in_browser(self) -> None:
        if not self.report:
            self._set_status("Brak raportu do wyświetlenia.", C["warn"])
            return
        path = Path(tempfile.gettempdir()) / f"osint_{self.report.tool}_{self.report.created:%Y%m%d_%H%M%S}.html"
        self.report.save(path)
        webbrowser.open(path.as_uri())
        self._set_status(f"Otwarto raport w przeglądarce ({path.name}).", C["ok"])

    def copy(self) -> None:
        if not self.report:
            self._set_status("Brak raportu do skopiowania.", C["warn"])
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(self.report.to_markdown())
        self._set_status("Raport skopiowany do schowka (Markdown).", C["ok"])

    def clear(self) -> None:
        self.report = None
        self.show_welcome()
        self._set_status("Gotowy.")

    # --- renderowanie --------------------------------------------------------------------

    def _begin(self) -> tk.Text:
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.links.clear()
        for tag in self.text.tag_names():
            if tag.startswith(("url", "kv", "tool-")):
                self.text.tag_delete(tag)
        return self.text

    def show_welcome(self) -> None:
        t = self._begin()
        t.insert("end", f"Witaj w {APP_NAME}\n", "h1")
        t.insert("end", "Wybierz moduł, wpisz cel i naciśnij Enter. Kliknij nazwę modułu poniżej, aby zacząć.\n", "meta")
        t.insert("end", "Moduły\n", "section")
        bold = tkfont.Font(self.root, font=self.font["ui_b"])
        icon_w = self.px(30)
        label_w = icon_w + max(bold.measure(tool.label) for tool in TOOLS) + self.px(36)
        t.tag_configure("kvw", tabs=(icon_w, label_w), lmargin1=self.px(6), lmargin2=label_w, spacing1=self.px(3))
        for tool in TOOLS:
            tag = f"tool-{tool.key}"
            t.tag_bind(tag, "<Button-1>", lambda _e, k=tool.key: self.select_tool(k, focus=True))
            t.insert("end", tool.icon, ("kvw", "tool_link", tag))
            t.insert("end", "\t" + tool.label, ("kvw", "tool_link", tag))
            t.insert("end", "\t" + tool.description + "\n", ("kvw", "key"))
        t.insert("end", "Dobre praktyki\n", "section")
        t.tag_configure("bullet", tabs=(icon_w,), lmargin1=self.px(6), lmargin2=icon_w, spacing1=self.px(3))
        for line in (
            "Narzędzie korzysta wyłącznie z publicznych, pasywnych źródeł – nie skanuje portów i nie loguje się nigdzie.",
            "Wyniki traktuj jako wskazówki: zajęta nazwa użytkownika nie oznacza tej samej osoby, a geolokalizacja IP jest przybliżona.",
            "Używaj zgodnie z prawem: do badania własnej ekspozycji, w pracy, w CTF-ach i za zgodą osób, których dotyczy wyszukiwanie.",
        ):
            t.insert("end", f"•\t{line}\n", ("bullet", "val"))
        t.configure(state="disabled")

    def _render_loading(self, tool: Tool, target: str) -> None:
        t = self._begin()
        t.insert("end", f"{tool.label}\n", "h1")
        t.insert("end", f"{target}\n", "meta")
        t.insert("end", "\nTrwa wyszukiwanie… wyniki pojawią się tutaj.\n", "key")
        t.configure(state="disabled")

    def show_error(self, message: str) -> None:
        t = self._begin()
        t.insert("end", "Nie udało się wykonać wyszukiwania\n", "h1")
        t.insert("end", f"✗  {message}\n", "error")
        t.configure(state="disabled")
        self._set_status(message, C["bad"])

    def show_report(self, report: Report) -> None:
        self.report = report
        t = self._begin()
        t.insert("end", f"{report.heading}\n", "h1")
        t.insert("end", f"{report.target}    ·    {report.created:%Y-%m-%d %H:%M:%S}    ·    {report.duration:.1f} s\n", "meta")
        for index, sec in enumerate(report.visible_sections):
            t.insert("end", f"{sec.title}\n", "section")
            if sec.error:
                t.insert("end", f"✗  {sec.error}\n", "error")
            if sec.note:
                t.insert("end", f"▸  {sec.note}\n", "note")
            if sec.fields:
                self._render_fields(index, sec)
            if sec.rows:
                self._render_table(sec)
            if sec.text:
                t.insert("end", sec.text + "\n", "pre")
        t.configure(state="disabled")
        t.yview_moveto(0)
        count = len(report.visible_sections)
        self._set_status(f"Gotowe – {count} sekcji w {report.duration:.1f} s.", C["ok"])

    def _insert_linked(self, text: str, tags: tuple[str, ...]) -> None:
        pos = 0
        for match in URL_RE.finditer(text):
            url = match.group(0).rstrip(".,);")
            if match.start() > pos:
                self.text.insert("end", text[pos:match.start()], tags)
            tag = f"url{len(self.links)}"
            self.links[tag] = url
            self.text.insert("end", url, tags + ("link", tag))
            pos = match.start() + len(url)
        if pos < len(text):
            self.text.insert("end", text[pos:], tags)

    def _render_fields(self, index: int, sec: Section) -> None:
        key_width = max(self.ui_metrics.measure(f.key) for f in sec.fields) + self.px(28)
        key_width = min(key_width, self.px(250))
        tag = f"kv{index}"
        self.text.tag_configure(tag, tabs=(key_width,), lmargin1=self.px(4), lmargin2=key_width)
        self.text.tag_configure("charwrap", wrap="char")
        for f in sec.fields:
            # długie wartości bez spacji (ścieżki, hashe) zawijamy po znakach, żeby nie przeskakiwały pod etykietę
            line = (tag, "charwrap") if len(f.value) > 50 and not re.search(r"\s", f.value) else (tag,)
            self.text.insert("end", f.key + "\t", line + ("key",))
            self._insert_linked(f.value, line + (f.style or "val",))
            self.text.insert("end", "\n", line)

    def _render_table(self, sec: Section) -> None:
        t = self.text
        headers = sec.headers or [""] * len(sec.rows[0])
        rows = sec.rows[:MAX_ROWS]
        ncol = len(headers)
        widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row[:ncol]):
                widths[i] = max(widths[i], len(cell))
        widths = [min(w, 70) for w in widths]
        available = max(40, (self.text.winfo_width() - self.px(70)) // max(1, self.mono_metrics.measure("0")))
        while sum(widths) + 3 * (ncol - 1) > available and max(widths) > 12:
            widths[widths.index(max(widths))] -= 1

        def fit(text: str, width: int) -> str:
            return text if len(text) <= width else text[: width - 1] + "…"

        if any(headers):
            line = "   ".join(fit(h, w).ljust(w) for h, w in zip(headers, widths)).rstrip()
            t.insert("end", line + "\n", ("mono", "th", "table"))
            t.insert("end", "─" * (sum(widths) + 3 * (ncol - 1)) + "\n", ("mono", "muted", "table"))
        for row, style in zip(rows, sec.row_styles):
            for i, width in enumerate(widths):
                cell = row[i] if i < len(row) else ""
                shown = fit(cell, width)
                # wiersze "ok" wyróżniamy tylko w pierwszej kolumnie, żeby tabela pozostała czytelna
                cell_style = style if (style != "ok" or i == 0) else None
                tags: tuple[str, ...] = ("mono", "table", cell_style or "val")
                if URL_RE.fullmatch(cell):
                    tag = f"url{len(self.links)}"
                    self.links[tag] = cell
                    tags += ("link", tag)
                t.insert("end", shown, tags)
                padding = " " * (width - len(shown)) + ("   " if i < ncol - 1 else "")
                t.insert("end", padding, ("mono", "table"))
            t.insert("end", "\n", "table")
        if len(sec.rows) > MAX_ROWS:
            t.insert("end", f"… oraz {len(sec.rows) - MAX_ROWS} kolejnych wierszy – pełna lista w eksporcie.\n", "note")

    def _click_link(self, event) -> None:
        index = self.text.index(f"@{event.x},{event.y}")
        for tag in self.text.tag_names(index):
            if tag in self.links:
                webbrowser.open(self.links[tag])
                return


def _app_icon(root: tk.Tk) -> tk.PhotoImage:
    size, center = 32, 15.5
    image = tk.PhotoImage(width=size, height=size)
    for y in range(size):
        row = []
        for x in range(size):
            d = ((x - center) ** 2 + (y - center) ** 2) ** 0.5
            row.append(C["accent"] if d <= 4.5 or 9 <= d <= 12.5 else C["side"])
        image.put("{" + " ".join(row) + "}", to=(0, y))
    root.iconphoto(True, image)
    return image


def _dark_title_bar(root: tk.Tk) -> None:
    if sys.platform != "win32":
        return
    try:
        import ctypes

        root.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
        value = ctypes.c_int(1)
        for attribute in (20, 19):  # DWMWA_USE_IMMERSIVE_DARK_MODE (nowe i starsze wersje Windows 10)
            if ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attribute, ctypes.byref(value), ctypes.sizeof(value)) == 0:
                break
    except Exception:
        pass


def main() -> int:
    if sys.platform == "win32":
        try:
            import ctypes

            ctypes.windll.shcore.SetProcessDpiAwareness(1)
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("mrross.osint.gui")
        except Exception:
            pass
    root = tk.Tk()
    root.title(APP_NAME)
    app = OsintApp(root)
    root._icon = _app_icon(root)  # referencja, żeby obraz nie został usunięty przez GC
    width, height = app.px(1240), app.px(800)
    x = max(0, (root.winfo_screenwidth() - width) // 2)
    y = max(0, (root.winfo_screenheight() - height) // 2 - app.px(20))
    root.geometry(f"{width}x{height}+{x}+{y}")
    root.minsize(app.px(940), app.px(620))
    _dark_title_bar(root)
    root.mainloop()
    return 0
