"""
exports_audit.py: audit kernel driver export table for unexpectedly unreachable exports.

Most kernel drivers export only DriverEntry (which IDA renames to `start` or leaves
unnamed) and possibly a small number of known callbacks.  An export with zero internal
CodeRefsTo is suspicious: it may be a hidden entry point that is called directly by an
attacker without going through any IRP dispatch path, bypassing normal access checks.

Only zero-xref exports are reported (excluding the canonical entry-point names) to
avoid flooding the results window with expected exports.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from DriverBuddyReloaded.reporting import Reporter

import idautils

from DriverBuddyReloaded import config
from DriverBuddyReloaded.reporting import Finding

# Entry-point names that are expected to have no internal callers.
_EXPECTED_ROOTS = {
    "DriverEntry",
    "DriverEntry_0",
    "GsDriverEntry",
    "start",
    "Real_Driver_Entry",
}


def audit(rep: Reporter) -> None:
    """
    Enumerate the driver's export table.  For each export that has zero internal
    CodeRefsTo (and is not a known entry-point root), emit a LOW Finding.

    :param rep: Reporter instance
    """
    exports = list(idautils.Entries())
    if not exports:
        return

    rep.info("[>] Auditing {} export(s)...".format(len(exports)))
    hidden = 0
    for _index, ordinal, ea, name in exports:
        if not name or name in _EXPECTED_ROOTS:
            continue
        xrefs = list(idautils.CodeRefsTo(ea, 0))
        if xrefs:
            continue
        hidden += 1
        rep.add(Finding(
            category="export",
            title=name,
            ea=ea,
            severity=config.SEV_LOW,
            detail="Exported with no internal callers (ordinal {})".format(ordinal)))

    if hidden:
        rep.info("[>] Exports audit: {} unreachable export(s) flagged".format(hidden))
    else:
        rep.info("[>] Exports audit: all exports have internal callers")
