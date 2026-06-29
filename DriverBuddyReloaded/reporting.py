"""
reporting.py: shared findings model and output spine for Driver Buddy Reloaded.

Analysis modules emit Finding objects into a single Reporter, which mirrors
human-readable lines to the console and a log file and, at the end of a run,
can render the findings as a clickable results window, JSON and HTML.

This replaces the old pattern of pairing every `print(x)` with a matching
`log_file.write(x + "\\n")`, which was duplicated throughout the plugin.
"""

import html
import json
from dataclasses import asdict, dataclass, field

import ida_kernwin
import idaapi

from DriverBuddyReloaded import config

BADADDR = idaapi.BADADDR

# Tracks the last shown ResultsChooser so it can be refreshed after row deletion.
_last_results_chooser = None


@dataclass
class Finding:
    """A single analysis result. `data` carries category-specific payload
    (e.g. decoded IOCTL fields) and is what JSON/HTML/PoC consume."""
    category: str
    title: str
    ea: int = BADADDR
    func: str = ""
    severity: int = config.SEV_INFO
    detail: str = ""
    data: dict = field(default_factory=dict)


# Light row backgrounds for the results window, keyed by severity (BGR).
_SEVERITY_COLORS = {
    config.SEV_CRITICAL: 0xCCCCFF,
    config.SEV_HIGH: 0xCCE5FF,
    config.SEV_MEDIUM: 0xCCFFFF,
    config.SEV_LOW: 0xE5FFE5,
}


class Reporter:
    """Console + log spine and accumulator of Finding objects."""

    def __init__(self, log_path=None):
        self.findings = []
        # Identity keys of findings already recorded, so a byte-identical finding
        # emitted twice (e.g. an import xref that resolves to the same call site
        # via more than one xref kind) is not duplicated in the report.
        self._seen_keys = set()
        self.log_path = log_path
        self._log = None
        self._json_path = None
        self._html_path = None
        if log_path:
            try:
                self._log = open(log_path, "w", encoding="utf-8")
            except OSError as e:
                print("[!] Could not open log file \"{}\": {}".format(log_path, e))

    # ---- emit --------------------------------------------------------------
    def info(self, msg):
        """A plain progress/status line, echoed to console and log verbatim."""
        self._write(msg)

    @staticmethod
    def _finding_key(f):
        return (f.category, f.title, f.ea, f.severity, f.detail)

    def add(self, finding):
        """Record a Finding and echo a one-line summary.

        A finding identical to one already recorded (same category, title, ea,
        severity and detail) is dropped: such exact repeats are always noise
        (e.g. an import referenced by two xref kinds at one call site), never two
        distinct results, since genuinely separate findings differ at least in ea.
        """
        key = self._finding_key(finding)
        if key in self._seen_keys:
            return finding
        self._seen_keys.add(key)
        self.findings.append(finding)
        self._write(self._format_line(finding))
        return finding

    def add_finding(self, category, title, ea=BADADDR, func="",
                    severity=config.SEV_INFO, detail="", **data):
        return self.add(Finding(category=category, title=title, ea=ea, func=func,
                                severity=severity, detail=detail, data=data))

    def remove_findings_at(self, ea):
        """Remove all findings whose ea matches (used after marking IOCTL invalid)."""
        self.findings = [f for f in self.findings if f.ea != ea]
        # Rebuild the dedup index so a later re-add of a removed finding is allowed.
        self._seen_keys = {self._finding_key(f) for f in self.findings}

    def re_save(self):
        """Re-write JSON and HTML output files using the paths from the original run."""
        if self._json_path:
            self.to_json(self._json_path)
        if self._html_path:
            self.to_html(self._html_path)

    # ---- queries -----------------------------------------------------------
    def by_category(self, category):
        return [f for f in self.findings if f.category == category]

    def counts_by_severity(self):
        counts = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    # ---- internals ---------------------------------------------------------
    @staticmethod
    def _loc(ea):
        return "0x{:08x}".format(ea) if ea not in (None, BADADDR) else "-"

    def _format_line(self, f):
        where = " in {}".format(f.func) if f.func else ""
        loc = (" at " + self._loc(f.ea)) if f.ea not in (None, BADADDR) else ""
        extra = " :: {}".format(f.detail) if f.detail else ""
        return "\t- [{}] {}{}{}{}".format(
            config.severity_name(f.severity), f.title, where, loc, extra)

    def _write(self, line):
        print(line)
        if self._log:
            try:
                self._log.write(line + "\n")
            except OSError:  # pragma: no cover
                pass

    def close(self):
        if self._log:
            self._log.close()
            self._log = None

    # ---- renderers ---------------------------------------------------------
    @staticmethod
    def _finding_to_dict(f):
        d = asdict(f)
        d["severity"] = config.severity_name(f.severity)
        d["ea"] = "0x{:x}".format(f.ea) if f.ea not in (None, BADADDR) else None
        return d

    def to_json(self, path):
        self._json_path = path
        payload = {
            "tool": "DriverBuddyReloaded",
            "driver": config.driver_name(),
            "sha256": config.input_sha256(),
            "generated": config.run_stamp(),
            "severity_counts": {config.severity_name(k): v
                                for k, v in self.counts_by_severity().items()},
            "findings": [self._finding_to_dict(f) for f in self.findings],
        }
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, default=str)
            self.info("[>] Saved JSON findings to \"{}\"".format(path))
        except OSError as e:
            self.info("[!] Could not write JSON to \"{}\": {}".format(path, e))

    def to_html(self, path):
        self._html_path = path
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self._render_html())
            self.info("[>] Saved HTML report to \"{}\"".format(path))
        except OSError as e:
            self.info("[!] Could not write HTML to \"{}\": {}".format(path, e))

    def _render_html(self):
        esc = html.escape
        counts = self.counts_by_severity()
        summary = " ".join(
            "<span class='sev s{0}'>{1}: {2}</span>".format(
                k, config.severity_name(k), counts[k])
            for k in sorted(counts, reverse=True))
        rows = []
        for f in sorted(self.findings, key=lambda x: -x.severity):
            rows.append(
                "<tr class='s{sev}'><td>{sevname}</td><td>{cat}</td>"
                "<td><code>{loc}</code></td><td>{func}</td><td>{title}</td>"
                "<td>{detail}</td></tr>".format(
                    sev=f.severity,
                    sevname=config.severity_name(f.severity),
                    cat=esc(f.category),
                    loc=self._loc(f.ea),
                    func=esc(f.func),
                    title=esc(f.title),
                    detail=esc(f.detail)))
        return _HTML_TEMPLATE.format(
            driver=esc(config.driver_name()),
            sha256=esc(config.input_sha256()),
            generated=esc(config.run_stamp()),
            summary=summary,
            rows="\n".join(rows) or "<tr><td colspan='6'>No findings.</td></tr>")

    def show_window(self):
        global _last_results_chooser
        if not self.findings:
            return
        _last_results_chooser = ResultsChooser(self.findings, rep=self)
        _last_results_chooser.Show()


_HTML_TEMPLATE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Driver Buddy Reloaded - {driver}</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;margin:2em;color:#222}}
h1{{margin-bottom:0}} .meta{{color:#666;font-size:.9em;margin:.3em 0 1.2em}}
table{{border-collapse:collapse;width:100%}} th,td{{border:1px solid #ddd;padding:6px 8px;text-align:left;font-size:.9em}}
th{{background:#f4f4f4}} code{{font-family:Consolas,monospace}}
.sev{{padding:2px 8px;border-radius:3px;margin-right:6px;font-size:.85em}}
.s4,tr.s4 td{{background:#ffd6d6}} .s3,tr.s3 td{{background:#ffe6cc}}
.s2,tr.s2 td{{background:#ffffcc}} .s1,tr.s1 td{{background:#e6ffe6}}
</style></head><body>
<h1>Driver Buddy Reloaded</h1>
<div class="meta">Driver: <b>{driver}</b> &middot; SHA-256: <code>{sha256}</code> &middot; Generated: {generated}</div>
<div class="meta">{summary}</div>
<table><thead><tr><th>Severity</th><th>Category</th><th>Address</th><th>Function</th>
<th>Title</th><th>Detail</th></tr></thead><tbody>
{rows}
</tbody></table></body></html>
"""


class ResultsChooser(ida_kernwin.Choose):
    """Clickable results window listing all findings; double-click jumps to the EA."""

    def __init__(self, findings, rep=None, title="Driver Buddy Reloaded - Findings"):
        ida_kernwin.Choose.__init__(
            self,
            title,
            [["Severity", 8], ["Category", 10], ["Address", 12],
             ["Function", 24], ["Title", 40], ["Detail", 40]],
            flags=(getattr(ida_kernwin.Choose, "CH_CAN_REFRESH", 0) |
                   getattr(ida_kernwin.Choose, "CH_CAN_DEL", 0)))
        # Highest severity first.
        self.items = sorted(findings, key=lambda f: -f.severity)
        self._rep = rep

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        f = self.items[n]
        loc = "0x{:08x}".format(f.ea) if f.ea not in (None, BADADDR) else ""
        return [config.severity_name(f.severity), f.category, loc, f.func, f.title, f.detail]

    def OnSelectLine(self, n):
        f = self.items[n]
        if f.ea not in (None, BADADDR):
            ida_kernwin.jumpto(f.ea)

    def OnDeleteLine(self, n):
        removed = self.items.pop(n)
        if self._rep is not None:
            self._rep.findings = [f for f in self._rep.findings if f is not removed]
            self._rep.re_save()
        return [ida_kernwin.Choose.ALL_CHANGED, 0]

    def OnGetLineAttr(self, n):
        color = _SEVERITY_COLORS.get(self.items[n].severity)
        if color is not None:
            return [color, 0]
        return None
