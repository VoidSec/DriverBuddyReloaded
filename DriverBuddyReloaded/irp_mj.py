"""
irp_mj.py: create and apply an IRP_MJ_FUNCTION IDA enum for WDM dispatch tables.

When a WDM driver is identified, IDA labels the DriverObject.MajorFunction array
as pointer-sized entries but leaves the slot indices as raw integers.  This module:

  1. Defines the 28 IRP_MJ_* constants as a Python dict.
  2. Creates (or refreshes) an IDA enum named IRP_MJ_FUNCTION in the local type DB.
  3. Applies that enum to operands that reference MajorFunction array slots so the
     disassembly shows e.g. [rcx+IRP_MJ_DEVICE_CONTROL*8+70h] instead of
     [rcx+0E0h].

Gated on config.Feature.IRP_MJ_ENUM.
"""

from __future__ import annotations

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


def apply_to_driver_entry(driver_entry_addr: int, rep: Reporter) -> None:
    """
    Apply the IRP_MJ_FUNCTION enum to MajorFunction array assignment operands
    within the DriverEntry function.

    IDA typically shows these as `mov [rcx+0E0h], rax` for IRP_MJ_DEVICE_CONTROL.
    With the enum applied the second operand becomes the slot constant, making the
    dispatch table much easier to audit.

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

    ptr_sz = ida_compat.ptr_size()
    applied = 0
    for ea in idautils.FuncItems(driver_entry_addr):
        if idc.print_insn_mnem(ea) != "mov":
            continue
        op0 = idc.print_operand(ea, 0)
        # Match [reg+XXXh] writes into the MajorFunction array (+70h base, each slot is ptr_sz)
        if "+70h" not in op0 and not any(
                "+%02Xh" % (0x70 + i * ptr_sz) in op0 for i in range(len(IRP_MJ_NAMES))):
            continue
        # Attempt to apply enum to the immediate second operand (the function pointer)
        # or as an array index comment.  Best-effort; silently skip on failure.
        try:
            idc.op_enum(ea, 1, eid, 0)
            applied += 1
        except Exception:
            pass

    if applied:
        rep.info("[>] IRP_MJ: applied {} enum to {} operand(s) in DriverEntry".format(
            _ENUM_NAME, applied))
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
