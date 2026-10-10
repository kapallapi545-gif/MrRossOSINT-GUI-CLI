"""Model raportu oraz eksport do JSON / Markdown / HTML."""
from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from string import Template

from . import APP_NAME, __version__

# Style wartości – interpretowane przez CLI, GUI i eksport HTML
OK, BAD, WARN, MUTED = "ok", "bad", "warn", "muted"

URL_RE = re.compile(r"https?://[^\s<>\"']+")


def to_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "tak" if value else "nie"
    if isinstance(value, (list, tuple, set)):
        return ", ".join(t for t in (to_text(v) for v in value) if t)
    if isinstance(value, float):
        return f"{value:g}"
    return str(value).strip()


@dataclass
class Field:
    key: str
    value: str
    style: str | None = None


@dataclass
class Section:
    title: str
    fields: list[Field] = field(default_factory=list)
    headers: list[str] = field(default_factory=list)
    rows: list[list[str]] = field(default_factory=list)
    row_styles: list[str | None] = field(default_factory=list)
    text: str | None = None
    note: str | None = None
    error: str | None = None

    def add(self, key: str, value, style: str | None = None) -> Section:
        """Dodaje pole klucz–wartość; puste wartości są pomijane."""
        text = to_text(value)
        if text:
            self.fields.append(Field(key, text, style))
        return self

    def table(self, *headers: str) -> Section:
        self.headers = list(headers)
        return self

    def row(self, *cells, style: str | None = None) -> Section:
        self.rows.append([to_text(c) for c in cells])
        self.row_styles.append(style)
        return self

    @property
    def empty(self) -> bool:
        return not (self.fields or self.rows or self.text or self.note or self.error)

    def to_dict(self) -> dict:
        data: dict = {"title": self.title}
        if self.fields:
            merged: dict[str, str] = {}
            for f in self.fields:
                merged[f.key] = f"{merged[f.key]}; {f.value}" if f.key in merged else f.value
            data["fields"] = merged
        if self.rows:
            if self.headers:
                data["rows"] = [dict(zip(self.headers, row)) for row in self.rows]
            else:
                data["rows"] = self.rows
        for name in ("text", "note", "error"):
            if getattr(self, name):
                data[name] = getattr(self, name)
        return data


@dataclass
class Report:
    tool: str
    target: str
    title: str = ""
    sections: list[Section] = field(default_factory=list)
    created: datetime = field(default_factory=lambda: datetime.now().replace(microsecond=0))
    duration: float = 0.0

    def section(self, title: str) -> Section:
        sec = Section(title)
        self.sections.append(sec)
        return sec

    def merge(self, other: Report) -> None:
        self.sections.extend(other.sections)

    @property
    def heading(self) -> str:
        return self.title or self.tool

    @property
    def visible_sections(self) -> list[Section]:
        return [s for s in self.sections if not s.empty]

    # --- eksport ---------------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "title": self.heading,
            "target": self.target,
            "created": self.created.isoformat(),
            "duration_s": round(self.duration, 2),
            "sections": [s.to_dict() for s in self.visible_sections],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    def to_markdown(self) -> str:
        def esc(text: str) -> str:
            return text.replace("|", "\\|").replace("\n", " ")

        out = [
            f"# {self.heading}: {self.target}",
            "",
            f"_Wygenerowano {self.created:%Y-%m-%d %H:%M:%S} · czas {self.duration:.1f} s · {APP_NAME} {__version__}_",
        ]
        for sec in self.visible_sections:
            out += ["", f"## {sec.title}", ""]
            if sec.error:
                out.append(f"> **Błąd:** {sec.error}\n")
            if sec.note:
                out.append(f"> {sec.note}\n")
            for f in sec.fields:
                out.append(f"- **{f.key}:** {f.value}")
            if sec.rows:
                if sec.fields:
                    out.append("")
                headers = sec.headers or [""] * len(sec.rows[0])
                out.append("| " + " | ".join(esc(h) for h in headers) + " |")
                out.append("|" + "---|" * len(headers))
                for row in sec.rows:
                    out.append("| " + " | ".join(esc(c) for c in row) + " |")
            if sec.text:
                out += ["", "```", sec.text, "```"]
        return "\n".join(out) + "\n"

    def to_html(self) -> str:
        def rich(text: str) -> str:
            escaped = html.escape(text)
            return URL_RE.sub(lambda m: f'<a href="{m.group(0)}" target="_blank" rel="noopener">{m.group(0)}</a>', escaped)

        def cls(style: str | None) -> str:
            return f' class="{style}"' if style else ""

        parts = []
        for sec in self.visible_sections:
            body = [f"<h2>{html.escape(sec.title)}</h2>"]
            if sec.error:
                body.append(f'<p class="error">✗ {html.escape(sec.error)}</p>')
            if sec.note:
                body.append(f'<p class="note">{html.escape(sec.note)}</p>')
            if sec.fields:
                items = "".join(
                    f"<dt>{html.escape(f.key)}</dt><dd{cls(f.style)}>{rich(f.value)}</dd>" for f in sec.fields
                )
                body.append(f"<dl>{items}</dl>")
            if sec.rows:
                head = "".join(f"<th>{html.escape(h)}</th>" for h in sec.headers)
                rows = "".join(
                    f"<tr{cls(style)}>" + "".join(f"<td>{rich(c)}</td>" for c in row) + "</tr>"
                    for row, style in zip(sec.rows, sec.row_styles)
                )
                body.append(f"<table>{'<thead><tr>' + head + '</tr></thead>' if head else ''}<tbody>{rows}</tbody></table>")
            if sec.text:
                body.append(f"<pre>{html.escape(sec.text)}</pre>")
            parts.append("<section>" + "".join(body) + "</section>")

        meta = f"{self.created:%Y-%m-%d %H:%M:%S} · czas {self.duration:.1f} s"
        return _HTML.substitute(
            title=html.escape(f"{self.heading}: {self.target}"),
            heading=html.escape(self.heading),
            target=html.escape(self.target),
            meta=html.escape(meta),
            sections="\n".join(parts),
            app=APP_NAME,
            version=__version__,
        )

    def save(self, path: str | Path) -> Path:
        path = Path(path)
        suffix = path.suffix.lower()
        if suffix == ".json":
            content = self.to_json()
        elif suffix in (".html", ".htm"):
            content = self.to_html()
        elif suffix in (".md", ".markdown", ".txt"):
            content = self.to_markdown()
        else:
            raise ValueError("Obsługiwane formaty raportu: .html, .json, .md")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path.resolve()


_HTML = Template("""<!doctype html>
<html lang="pl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$title</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--text:#e6edf3;--muted:#8b949e;--accent:#2dd4bf;
--ok:#3fb950;--bad:#f85149;--warn:#d29922;--link:#58a6ff}
@media (prefers-color-scheme: light){:root{--bg:#f6f8fa;--panel:#fff;--border:#d0d7de;--text:#1f2328;
--muted:#656d76;--accent:#0f766e;--ok:#1a7f37;--bad:#cf222e;--warn:#9a6700;--link:#0969da}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 "Segoe UI",system-ui,-apple-system,sans-serif}
main{max-width:1100px;margin:0 auto;padding:32px 16px 64px}
header .tool{color:var(--accent);font-weight:600;letter-spacing:.04em;text-transform:uppercase;font-size:13px}
header h1{margin:4px 0 0;font-size:28px;word-break:break-all}
header p{margin:6px 0 0;color:var(--muted)}
section{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:16px 20px;margin-top:18px;overflow-x:auto}
h2{margin:0 0 12px;font-size:16px;color:var(--accent)}
dl{display:grid;grid-template-columns:minmax(140px,max-content) 1fr;gap:6px 20px;margin:0}
dt{color:var(--muted)}
dd{margin:0;word-break:break-word}
table{border-collapse:collapse;width:100%;font-size:14px}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top;word-break:break-word}
th{color:var(--muted);font-weight:600}
pre{white-space:pre-wrap;font:12.5px/1.5 Consolas,"Cascadia Mono",monospace;color:var(--muted);margin:0}
.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}.muted{color:var(--muted)}
tr.muted td{color:var(--muted)}tr.ok td:first-child{color:var(--ok)}tr.bad td{color:var(--bad)}tr.warn td{color:var(--warn)}
.error{color:var(--bad);margin:0 0 10px}.note{color:var(--warn);margin:0 0 10px}
a{color:var(--link)}
footer{margin-top:28px;color:var(--muted);font-size:13px}
@media (max-width:640px){dl{grid-template-columns:1fr}dd{margin-bottom:8px}}
</style>
</head>
<body>
<main>
<header><div class="tool">$heading</div><h1>$target</h1><p>$meta</p></header>
$sections
<footer>Raport wygenerowany przez $app $version · dane z publicznych źródeł</footer>
</main>
</body>
</html>
""")
