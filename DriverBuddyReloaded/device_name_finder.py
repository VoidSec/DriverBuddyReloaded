"""
DeviceName finding functions. Using a Unicode string search
"""
import collections
import mmap
import re

import ida_nalt

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


def get_unicode_device_names():
    """
    Returns all Unicode strings within the binary currently being analysed in IDA which might be DeviceNames
    """

    path = ida_nalt.get_root_filename()
    min_length = 4
    possible_names = set()
    with open(path, "rb") as f:
        b = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

        for s in extract_unicode_strings(b, n=min_length):
            s_str = str(s.s)
            if s_str.startswith('\\Device\\') or s_str.startswith('\\DosDevices\\'):
                possible_names.add(str(s.s))
    return possible_names


def find_unicode_device_name(rep):
    """
    Find and report potential DeviceNames, emitting a Finding per full path.
    :param rep: Reporter instance
    :return boolean: True if at least one full DeviceName was found, else False
    """

    possible_names = get_unicode_device_names()
    # Keep only full paths; bare prefixes mean the real name is built elsewhere.
    real = sorted(n for n in possible_names if n not in ('\\Device\\', '\\DosDevices\\'))
    if real:
        for name in real:
            rep.add(Finding(category="device_name", title=name, severity=config.SEV_INFO))
        return True
    if possible_names:
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
