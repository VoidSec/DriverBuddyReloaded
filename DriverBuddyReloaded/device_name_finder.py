"""
Device name finding functions. Using a Unicode string search
"""
import collections
import mmap
import re

import ida_nalt

ASCII_BYTE = b" !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"
UNICODE_RE_4 = re.compile(b"((?:[%s]\x00){%d,})" % (ASCII_BYTE, 4))
REPEATS = ["A", "\x00", "\xfe", "\xff"]
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
    if (buf[0] in REPEATS) and buf_filled_with(buf, buf[0]):
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
    Returns all Unicode strings within the binary currently being analysed in IDA which might be device names
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


def find_unicode_device_name():
    """
    Attempts to find and output potential device names - returning False if none are found so further analysis can be done
    """

    possible_names = get_unicode_device_names()
    if len(possible_names) == 1 or len(possible_names) == 2:
        if '\\Device\\' in possible_names or '\\DosDevices\\' in possible_names:
            if len(possible_names) == 1:
                print(
                    "[!] The Device prefix was found but no full Device Paths; the Device Name is likely obfuscated or created on the stack.")
                return False
            elif '\\Device\\' in possible_names and '\\DosDevices\\' in possible_names:
                print(
                    "[!] The Device prefix was found but no full Device Paths; the Device Name is likely obfuscated or created on the stack.")
                return False
            else:
                # print("Potential device name: ")
                for i in possible_names:
                    if i != '\\Device\\' and i != '\\DosDevices\\':
                        print("\t- {}".format(i))
            return True
        else:
            # print("Potential device names: ")
            for i in possible_names:
                print("\t- {}".format(i))
            return True
    elif len(possible_names) > 2:
        # print("Possible devices names found:")
        for i in possible_names:
            print("\t- {}".format(i))
        return True
    else:
        print("[!] No potential device names found; it may be obfuscated or created on the stack in some way.")
        return False


def search():
    """
    Attempts to find potential device names in the currently opened binary.
    It starts by searching for Unicode device names, if this fails then it suggests the analyst to use FLOSS
    in order to search for stack based and obfuscated strings.
    """

    if not find_unicode_device_name():
        print(
            "[!] Unicode Device Name not found; try using FLOSS in order to recover obfuscated and stack based strings.")
