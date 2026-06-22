"""
irp_mj.py: create and apply an IRP_MJ_FUNCTION IDA enum for WDM dispatch tables.

When a WDM driver is identified this module:

  1. Defines the 28 IRP_MJ_* constants as a Python dict.
  2. Creates (or refreshes) an IDA enum named IRP_MJ_FUNCTION in the local type DB.
  3. Annotates every MajorFunction dispatch-table assignment in DriverEntry:
       - Disassembly view: sets a repeatable comment (idc.set_cmt) on each MOV.
       - Decompiler view: if HexRays is available, sets an end-of-line pseudocode
         comment via cfunc.set_user_cmt() so the output reads:
           DriverObject->MajorFunction[0] = ...; // IRP_MJ_CREATE

Gated on config.Feature.IRP_MJ_ENUM.
"""

from __future__ import annotations

import re
from typing import Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from DriverBuddyReloaded.reporting import Reporter

import idaapi
import idc

from DriverBuddyReloaded import ida_compat

# All 28 IRP major function codes from wdm.h (index -> name).
IRP_MJ_NAMES: Dict[int, str] = {
    0x00: "IRP_MJ_CREATE",
    0x01: "IRP_MJ_CREATE_NAMED_PIPE",
    0x02: "IRP_MJ_CLOSE",
    0x03: "IRP_MJ_READ",
    0x04: "IRP_MJ_WRITE",
    0x05: "IRP_MJ_QUERY_INFORMATION",
    0x06: "IRP_MJ_SET_INFORMATION",
    0x07: "IRP_MJ_QUERY_EA",
    0x08: "IRP_MJ_SET_EA",
    0x09: "IRP_MJ_FLUSH_BUFFERS",
    0x0A: "IRP_MJ_QUERY_VOLUME_INFORMATION",
    0x0B: "IRP_MJ_SET_VOLUME_INFORMATION",
    0x0C: "IRP_MJ_DIRECTORY_CONTROL",
    0x0D: "IRP_MJ_FILE_SYSTEM_CONTROL",
    0x0E: "IRP_MJ_DEVICE_CONTROL",
    0x0F: "IRP_MJ_INTERNAL_DEVICE_CONTROL",
    0x10: "IRP_MJ_SHUTDOWN",
    0x11: "IRP_MJ_LOCK_CONTROL",
    0x12: "IRP_MJ_CLEANUP",
    0x13: "IRP_MJ_CREATE_MAILSLOT",
    0x14: "IRP_MJ_QUERY_SECURITY",
    0x15: "IRP_MJ_SET_SECURITY",
    0x16: "IRP_MJ_POWER",
    0x17: "IRP_MJ_SYSTEM_CONTROL",
    0x18: "IRP_MJ_DEVICE_CHANGE",
    0x19: "IRP_MJ_QUERY_QUOTA",
    0x1A: "IRP_MJ_SET_QUOTA",
    0x1B: "IRP_MJ_PNP",
}

_ENUM_NAME = "IRP_MJ_FUNCTION"


def _create_enum() -> Optional[int]:
    """Create (or refresh) the IRP_MJ_FUNCTION enum.  Returns the enum id, or None."""
    if ida_compat.IS_IDA9:
        return _create_enum_typeinf()
    return _create_enum_legacy()


def _create_enum_legacy() -> Optional[int]:
    """IDA < 9.0 path: use idc.add_enum / idc.add_enum_member."""
    eid = idc.get_enum(_ENUM_NAME)
    if eid != idc.BADADDR:
        idc.del_enum(eid)
    eid = idc.add_enum(-1, _ENUM_NAME, 0)
    if eid == idc.BADADDR:
        return None
    for value, name in IRP_MJ_NAMES.items():
        idc.add_enum_member(eid, name, value, -1)
    return eid


def _create_enum_typeinf() -> Optional[int]:
    """IDA 9.0+ path: parse a C enum declaration into the local type DB."""
    import ida_typeinf
    members = "\n".join("  %s = 0x%02X," % (n, v) for v, n in sorted(IRP_MJ_NAMES.items()))
    decl = "enum %s {\n%s\n};" % (_ENUM_NAME, members)
    til = ida_typeinf.get_idati()
    try:
        existing = ida_typeinf.tinfo_t()
        if existing.get_named_type(til, _ENUM_NAME):
            ida_typeinf.del_named_type(til, _ENUM_NAME, ida_typeinf.NTF_TYPE)
    except Exception:
        pass
    htidcl = getattr(ida_typeinf, "HTI_DCL", 0)
    errs = ida_typeinf.parse_decls(til, decl, None, htidcl)
    if errs:
        return None
    return ida_compat.get_type_tid(_ENUM_NAME)


def _majorfunction_offset(ptr_sz: int) -> int:
    """
    Return the byte offset of MajorFunction in _DRIVER_OBJECT by querying the
    live type DB.  Falls back to the well-known constants (0x70 on x64, 0x38 on
    x86) if the struct is unavailable.
    """
    try:
        import ida_typeinf
        til = ida_typeinf.get_idati()
        ti = ida_typeinf.tinfo_t()
        if ti.get_named_type(til, "_DRIVER_OBJECT"):
            udt = ida_typeinf.udt_type_data_t()
            if ti.get_udt_details(udt):
                for i in range(udt.size()):
                    mbr = udt[i]
                    if mbr.name == "MajorFunction":
                        return mbr.offset // 8  # tinfo stores offsets in bits
    except Exception:
        pass
    return 0x70 if ptr_sz == 8 else 0x38


def _apply_hexrays_comments(driver_entry_addr: int, mf_offset: int,
                             rep: Reporter) -> int:
    """
    Decompile *driver_entry_addr* and attach an IRP_MJ name end-of-line comment
    to every MajorFunction dispatch-table assignment in the HexRays pseudocode.

    Requires the HexRays decompiler (ida_hexrays).  Returns the number of
    comments added, or 0 if HexRays is unavailable or no assignments are found.
    """
    try:
        import ida_hexrays
    except ImportError:
        return 0

    try:
        cfunc = ida_hexrays.decompile(driver_entry_addr)
    except Exception:
        return 0
    if cfunc is None:
        return 0

    # Pull constants with fallbacks for API stability across IDA versions.
    CV_FAST  = getattr(ida_hexrays, 'CV_FAST',  8)
    ITP_SEMI = getattr(ida_hexrays, 'ITP_SEMI', 14)
    cot_asg  = getattr(ida_hexrays, 'cot_asg',  None)
    cot_idx  = getattr(ida_hexrays, 'cot_idx',  None)
    cot_num  = getattr(ida_hexrays, 'cot_num',  None)
    cot_cast = getattr(ida_hexrays, 'cot_cast', None)
    MF_OPS   = frozenset(filter(None, [
        getattr(ida_hexrays, 'cot_memptr', None),
        getattr(ida_hexrays, 'cot_memref', None),
    ]))

    if None in (cot_asg, cot_idx, cot_num) or not MF_OPS:
        return 0

    added = [0]  # mutable counter reachable from the inner class

    class _Visitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            ida_hexrays.ctree_visitor_t.__init__(self, CV_FAST)

        def visit_expr(self, expr):
            # Match:  <arr>[<idx>] = <rhs>
            if expr.op != cot_asg:
                return 0
            lhs = expr.x
            if lhs.op != cot_idx:
                return 0
            arr = lhs.x
            # arr must be a member dereference (-> or .) at the MajorFunction offset
            if arr.op not in MF_OPS or arr.m != mf_offset:
                return 0
            # Unwrap any casts on the index expression
            idx = lhs.y
            while cot_cast is not None and idx.op == cot_cast:
                idx = idx.x
            if idx.op != cot_num:
                return 0  # dynamic index, nothing to annotate
            try:
                slot = int(idx.numval())
            except Exception:
                return 0
            irp_name = IRP_MJ_NAMES.get(slot)
            if irp_name is None:
                return 0
            try:
                loc = ida_hexrays.treeloc_t()
                loc.ea = expr.ea
                loc.itp = ITP_SEMI
                cfunc.set_user_cmt(loc, irp_name)
                added[0] += 1
            except Exception:
                pass
            return 0

    try:
        _Visitor().apply_to(cfunc.body, None)
    except Exception:
        return 0

    if added[0]:
        try:
            cfunc.save_user_cmts()
        except Exception:
            pass
        try:
            ida_hexrays.mark_cfunc_dirty(driver_entry_addr, False)
        except Exception:
            pass

    return added[0]


def apply_to_driver_entry(driver_entry_addr: int, rep: Reporter) -> None:
    """
    Annotate MajorFunction dispatch-table assignments in DriverEntry:
      - Disassembly: repeatable comment on each MOV (e.g. '; IRP_MJ_DEVICE_CONTROL').
      - Decompiler: end-of-line pseudocode comment via HexRays cfunc API.

    :param driver_entry_addr: EA of (real) DriverEntry
    :param rep: Reporter instance
    """
    try:
        import idautils
    except ImportError:
        return

    eid = _create_enum()
    if eid is None:
        rep.info("[!] IRP_MJ: failed to create {} enum".format(_ENUM_NAME))
        return

    ptr_sz   = ida_compat.ptr_size()
    mf_off   = _majorfunction_offset(ptr_sz)
    _disp_re = re.compile(r'\+0*([0-9A-Fa-f]+)h')
    applied  = 0

    for ea in idautils.FuncItems(driver_entry_addr):
        if idc.print_insn_mnem(ea) != "mov":
            continue
        op0 = idc.print_operand(ea, 0)
        m = _disp_re.search(op0)
        if not m:
            continue
        disp = int(m.group(1), 16)
        if disp < mf_off or (disp - mf_off) % ptr_sz != 0:
            continue
        slot = (disp - mf_off) // ptr_sz
        irp_name = IRP_MJ_NAMES.get(slot)
        if irp_name is None:
            continue
        try:
            idc.set_cmt(ea, irp_name, 0)
            applied += 1
        except Exception:
            pass

    if applied:
        rep.info("[>] IRP_MJ: annotated {} dispatch assignment(s) in DriverEntry".format(applied))
        hx = _apply_hexrays_comments(driver_entry_addr, mf_off, rep)
        if hx:
            rep.info("[>] IRP_MJ: added {} decompiler comment(s) via HexRays".format(hx))
    else:
        rep.info("[>] IRP_MJ: {} enum created (no dispatch assignments found in DriverEntry)".format(
            _ENUM_NAME))


def run(driver_entry_addr: int, rep: Reporter) -> None:
    """
    Entry point: create the IRP_MJ_FUNCTION enum and attempt to apply it.

    :param driver_entry_addr: EA of real DriverEntry
    :param rep: Reporter instance
    """
    rep.info("[>] Creating {} IDA enum...".format(_ENUM_NAME))
    apply_to_driver_entry(driver_entry_addr, rep)
