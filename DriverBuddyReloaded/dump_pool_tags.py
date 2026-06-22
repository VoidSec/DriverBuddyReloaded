"""
dump_pool_tags.py: extract pool allocation tags from kernel driver imports.

Walks every import of the ExAllocatePool* / ExFreePool* family, scans backwards
from each call site up to POOLTAG_LOOKBACK instructions for an IDA-annotated 'Tag'
immediate, decodes the 4-byte big-endian tag, and collects a tag -> callers mapping.
The result is emitted as findings and written to a WinDbg-compatible pooltags.txt.
"""

from typing import Dict, Set

import ida_nalt
import idautils
import idc

from DriverBuddyReloaded import config
from DriverBuddyReloaded.reporting import Finding

# Pool allocation/free APIs whose call sites carry a pool 'Tag' immediate,
# including the newer Win11 ExAllocatePool2/3 family.
POOL_TAG_FUNCS = [
    "ExAllocatePoolWithTag",
    "ExFreePoolWithTag",
    "ExAllocatePool2",
    "ExFreePool2",
    "ExAllocatePool3",
    "ExAllocatePoolWithTagPriority",
    "ExAllocatePoolWithQuotaTag",
    "ExAllocatePoolZero",
    "ExAllocatePoolQuotaZero",
    "ExAllocatePoolQuotaUninitialized",
    "ExAllocatePoolPriorityZero",
    "ExAllocatePoolPriorityUninitialized",
    "ExAllocatePoolUninitialized",
]


def _is_valid_pool_tag(tag_raw: int) -> bool:
    """Return True if the 4-byte immediate looks like a printable pool tag
    (all bytes in printable ASCII range, at least 2 alphanumeric bytes)."""
    alnum = 0
    for i in range(4):
        b = (tag_raw >> (8 * i)) & 0xFF
        if b < 0x20 or b > 0x7E:
            return False
        if (0x30 <= b <= 0x39) or (0x41 <= b <= 0x5A) or (0x61 <= b <= 0x7A):
            alnum += 1
    return alnum >= 2


def _decode_tag(tag_raw: int) -> str:
    """Decode a 4-byte pool-tag immediate to a string (high byte first)."""
    return "".join(chr((tag_raw >> (8 * i)) & 0xFF) for i in range(3, -1, -1))


def find_pool_tags() -> Dict[str, Set[str]]:
    """
    Find references to pool functions then the 'Tag' immediate marked at the call
    site, mapping each tag to the functions that use it.
    :return dict: tag -> set of caller function names
    """

    tags = {}

    def imp_cb(ea, name, ord):
        if name in POOL_TAG_FUNCS:
            for xref in idautils.XrefsTo(ea):
                call_addr = xref.frm
                caller_name = idc.get_func_name(call_addr)
                prev = idc.prev_head(call_addr)
                for _ in range(config.POOLTAG_LOOKBACK):
                    if idc.get_cmt(prev, 0) == 'Tag' and idc.get_operand_type(prev, 1) == 5:
                        tag_raw = idc.get_operand_value(prev, 1)
                        tags.setdefault(_decode_tag(tag_raw), set()).add(caller_name)
                        break
                    prev = idc.prev_head(prev)
        return True

    for i in range(ida_nalt.get_import_module_qty()):
        if not ida_nalt.get_import_module_name(i):
            continue
        ida_nalt.enum_import_names(i, imp_cb)
    return tags


def collect_fallback() -> Dict[str, Set[str]]:
    """
    Register-propagated pool tag scanner (GitHub issue #16).

    When the pool tag is staged in a register (e.g. `mov r8d, 'ABCD'; call ExAllocatePoolWithTag`)
    IDA does not apply the 'Tag' comment and find_pool_tags() misses it.

    This scanner walks back POOLTAG_LOOKBACK instructions from every pool-alloc call site
    and treats any immediate operand that passes the printable/alphanumeric heuristic as a
    candidate pool tag.  Less precise than the primary scanner -- de-duplicate against
    already-found tags at the call site.

    :return dict: tag -> set of caller function names
    """
    tags: Dict[str, Set[str]] = {}

    def imp_cb(ea, name, ord):
        if name not in POOL_TAG_FUNCS:
            return True
        for xref in idautils.XrefsTo(ea):
            call_addr = xref.frm
            caller_name = idc.get_func_name(call_addr)
            prev = idc.prev_head(call_addr)
            for _ in range(config.POOLTAG_LOOKBACK):
                if idc.get_operand_type(prev, 1) == 5:
                    tag_raw = idc.get_operand_value(prev, 1)
                    if _is_valid_pool_tag(tag_raw):
                        tags.setdefault(_decode_tag(tag_raw), set()).add(caller_name)
                        break
                prev = idc.prev_head(prev)
        return True

    for i in range(ida_nalt.get_import_module_qty()):
        if not ida_nalt.get_import_module_name(i):
            continue
        ida_nalt.enum_import_names(i, imp_cb)
    return tags


def collect(rep: "Reporter") -> str:
    """
    Find pool tags, emit a Finding per tag, and return a 'pooltags.txt'-formatted
    string ('tag - driver - functions which use it') for WinDbg.
    :param rep: Reporter instance
    :return string: pooltags.txt content (empty if none found)
    """

    tags = find_pool_tags()
    if not tags and config.Feature.POOLTAG_FALLBACK:
        rep.info("[>] No import-annotated tags; trying register-propagated fallback...")
        tags = collect_fallback()
        if tags:
            rep.info("[>] Fallback found {} tag candidate(s) via immediate heuristic".format(len(tags)))
    if not tags:
        rep.info("[!] No Pooltags found")
        return ""
    file_name = ida_nalt.get_root_filename()
    out = ''
    for tag in sorted(tags.keys()):
        callers = ', '.join(sorted(tags[tag]))
        out += '{} - {} - Called by: {}\n'.format(tag, file_name, callers)
        rep.add(Finding(category="pooltag", title=tag, severity=config.SEV_INFO,
                        detail="Called by: " + callers))
    rep.info("[>] Found {} Pooltag(s)".format(len(tags)))
    return out
