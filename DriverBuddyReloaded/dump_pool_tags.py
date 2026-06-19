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
                        tag = ''
                        for i in range(3, -1, -1):
                            tag += chr((tag_raw >> 8 * i) & 0xFF)
                        tags.setdefault(tag, set()).add(caller_name)
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
