"""
device_name_finder.py: locate potential DeviceNames in the driver binary.

Two complementary search strategies are used:
  1. mmap UTF-16LE scan - fast regex over the raw file bytes.
  2. IDA Strings database scan - catches strings IDA has already decoded,
     and provides the EA where the string was found (enabling Results window
     navigation and addressing GitHub issue #30).

Both result sets are merged before filtering for device-name prefixes.
"""

from __future__ import annotations

import collections
import mmap
import re
from typing import Optional, Set, TYPE_CHECKING

if TYPE_CHECKING:
    from DriverBuddyReloaded.reporting import Reporter

import ida_bytes
import ida_nalt
import ida_segment
import ida_strlist
import idautils
import idc

from DriverBuddyReloaded import config
from DriverBuddyReloaded.reporting import Finding

ASCII_BYTE = b" !\"#\\$%&\'\\(\\)\\*\\+,-\\./0123456789:;<=>\\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\\[\\]\\^_`abcdefghijklmnopqrstuvwxyz\\{\\|\\}\\\\~\t"
UNICODE_RE_4 = re.compile(b"((?:[%s]\x00){%d,})" % (ASCII_BYTE, 4))
REPEATS = [b"A", b"\x00", b"\xfe", b"\xff"]
SLICE_SIZE = 4096

String = collections.namedtuple("String", ["s", "offset"])


def buf_filled_with(buf, character):
    """
    Returns true if the buffer is filled with the recurring character
    :param buf:
    :param character:
    :return:
    """

    dupe_chunk = character * SLICE_SIZE
    for offset in range(0, len(buf), SLICE_SIZE):
        new_chunk = buf[offset: offset + SLICE_SIZE]
        if dupe_chunk[:len(new_chunk)] != new_chunk:
            return False
    return True


def extract_unicode_strings(buf, n=4):
    """
    Extract naive UTF-16 strings from the given binary data.
    :param buf:
    :param n:
    :return:
    """

    if not buf:
        return
    if (buf[0:1] in REPEATS) and buf_filled_with(buf, buf[0:1]):
        return
    if n == 4:
        r = UNICODE_RE_4
    else:
        reg = b"((?:[%s]\x00){%d,})" % (ASCII_BYTE, n)
        r = re.compile(reg)
    for match in r.finditer(buf):
        try:
            yield String(match.group().decode("utf-16"), match.start())
        except UnicodeDecodeError:
            pass


# All device-name prefixes we recognise (including Win32 namespace \??\)
_DEVICE_PREFIXES = ('\\Device\\', '\\DosDevices\\', '\\??\\')


def get_unicode_device_names() -> Set[str]:
    """
    mmap-based UTF-16LE scan of the raw file bytes.
    Returns possible device-name strings (no EAs available via this path).
    """
    path = idc.get_input_file_path() or ida_nalt.get_root_filename()
    possible: Set[str] = set()
    try:
        with open(path, "rb") as f:
            b = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            for s in extract_unicode_strings(b, n=4):
                s_str = str(s.s)
                if any(s_str.startswith(p) for p in _DEVICE_PREFIXES):
                    possible.add(s_str)
    except (OSError, ValueError):
        pass
    return possible


def get_strings_device_names() -> dict:
    """
    IDA Strings database scan.  Returns {name: ea} for strings that start with
    a recognised device-name prefix.  Provides EAs for Results-window navigation
    (GitHub issue #30).
    """
    result: dict = {}
    try:
        sc = ida_strlist.string_info_t()
        for i in range(ida_strlist.get_strlist_qty()):
            if not ida_strlist.get_strlist_item(sc, i):
                continue
            try:
                s = idc.get_strlit_contents(sc.ea, sc.length, sc.type)
                if not s:
                    continue
                decoded = s.decode("utf-16-le", errors="ignore").rstrip("\x00")
            except Exception:
                continue
            if any(decoded.startswith(p) for p in _DEVICE_PREFIXES):
                result[decoded] = sc.ea
    except Exception:
        pass
    return result


def _scan_segments_for_device_names() -> dict:
    """
    Last-resort: walk every IDA segment's byte array for UTF-16LE device-name strings.
    Used when the input file is not accessible on disk and IDA's string list missed the literal.
    Returns {name: ea}.
    """
    result: dict = {}
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if not seg or seg.size() == 0 or seg.size() > 0x200000:
            continue
        buf = ida_bytes.get_bytes(seg_ea, seg.size())
        if not buf:
            continue
        for s in extract_unicode_strings(buf, n=4):
            if any(s.s.startswith(p) for p in _DEVICE_PREFIXES):
                result[s.s] = seg_ea + s.offset
    return result


def find_unicode_device_name(rep: Reporter) -> bool:
    """
    Find and report potential DeviceNames, emitting a Finding per full path.

    Merges the mmap scan and the IDA Strings DB scan, preferring the Strings DB
    entry when both find the same name (because it carries an EA).
    :param rep: Reporter instance
    :return bool: True if at least one full DeviceName was found
    """
    mmap_names = get_unicode_device_names()
    strings_names = get_strings_device_names()  # {name: ea}

    all_names: dict = {name: None for name in mmap_names}
    all_names.update(strings_names)  # Strings DB wins (has EA)

    # Enrich None-EA entries (mmap found the name but not its address) and run as
    # primary fallback when both the file scan and the string-list came up empty.
    if not all_names or any(ea is None for ea in all_names.values()):
        for name, ea in _scan_segments_for_device_names().items():
            if all_names.get(name) is None:
                all_names[name] = ea

    # Keep only full paths; bare prefixes mean the real name is built elsewhere.
    real = {n: ea for n, ea in all_names.items()
            if any(n.startswith(p) and len(n) > len(p) for p in _DEVICE_PREFIXES)}
    if real:
        for name, ea in sorted(real.items()):
            from DriverBuddyReloaded.reporting import BADADDR
            rep.add(Finding(
                category="device_name",
                title=name,
                ea=ea if ea is not None else BADADDR,
                severity=config.SEV_INFO))
        return True
    if all_names:
        rep.info("[!] The Device prefix was found but no full Device Paths; "
                 "the DeviceName is likely obfuscated or created on the stack.")
        return False
    rep.info("[!] No potential DeviceNames found; it may be obfuscated or created on the stack in some way.")
    return False


def search(rep):
    """
    Attempts to find potential DeviceNames in the currently opened binary by
    searching for Unicode DeviceNames; if that fails, suggests using FLOSS to
    recover stack-based and obfuscated strings.
    :param rep: Reporter instance
    """

    if not find_unicode_device_name(rep):
        rep.info("[!] Unicode DeviceName not found; try using FLOSS in order to recover "
                 "obfuscated and stack based strings.")
