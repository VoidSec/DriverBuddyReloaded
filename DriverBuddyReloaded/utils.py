"""
utils.py: function enumeration, cross-reference gathering, driver-type detection,
and the AnalysisContext dataclass that scopes per-run state.

The module-level mutable dicts that previously accumulated global state across
plugin re-runs have been replaced by AnalysisContext.  Analysis code creates one
instance per run_analysis() invocation and threads it through every function that
needs to read or write the maps.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from DriverBuddyReloaded.reporting import Reporter

import ida_funcs
import ida_nalt
import ida_segment
import ida_strlist
import idautils
import idc

from DriverBuddyReloaded import config, signatures as sig
from DriverBuddyReloaded.reporting import Finding
from .find_opcodes import find
from .wdf import populate_wdf
from .wdm import check_for_fake_driver_entry, define_ddc, find_dispatch_function, locate_ddc


@dataclass
class AnalysisContext:
    """
    Per-run analysis state: the function maps built by populate_data_structures()
    and consumed by get_xrefs(), get_driver_id(), and callchain.trace().

    Create one instance at the start of each run_analysis() call so that
    re-running the plugin in the same IDA session always starts from a clean slate.
    """

    functions_map: dict = field(default_factory=dict)
    imports_map: dict = field(default_factory=dict)
    c_map: dict = field(default_factory=dict)
    winapi_map: dict = field(default_factory=dict)
    driver_map: dict = field(default_factory=dict)
    # Addresses of identified WDM dispatch handlers; populated by get_driver_id().
    ddc_addresses: list = field(default_factory=list)
    # Real DriverEntry EA after resolving GsDriverEntry / fake-entry wrappers.
    real_entry_addr: int = 0
    # Symbolic link paths discovered by find_symbolic_links() (N4).
    symbolic_links: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Import-enumeration callback factory
# ---------------------------------------------------------------------------

def _make_import_cb(ctx):
    """Return a callback compatible with ida_nalt.enum_import_names that
    writes into *ctx* instead of into module-level globals."""
    def _cb(address, name, ord):
        ctx.imports_map[name] = address
        ctx.functions_map[name] = address
        return True
    return _cb


# ---------------------------------------------------------------------------
# Map builders
# ---------------------------------------------------------------------------

def populate_function_map(ctx: AnalysisContext) -> bool:
    """
    Load all known functions (subs + imports) into ctx.functions_map.
    Imports also populate ctx.imports_map for driver-type detection.
    Returns True when at least one function was added.
    """
    result = False
    for address in idautils.Functions():
        func_name = idc.get_func_name(address)
        ctx.functions_map[func_name] = address
        result = True

    cb = _make_import_cb(ctx)
    for index in range(0, ida_nalt.get_import_module_qty()):
        ida_nalt.enum_import_names(index, cb)
        result = True

    return result


def populate_c_map(ctx: AnalysisContext) -> bool:
    """
    Scan functions_map for known-vulnerable C/C++ functions into ctx.c_map.
    Returns True when at least one match was found.
    """
    result = False
    for name, address in ctx.functions_map.items():
        if name in sig.C_FUNCTIONS:
            ctx.c_map[name] = address
            result = True
    return result


def populate_winapi_map(ctx: AnalysisContext) -> bool:
    """
    Scan functions_map for dangerous Windows API functions (exact matches
    and prefix matches) into ctx.winapi_map.
    Returns True when at least one match was found.
    """
    result = False
    for name, address in ctx.functions_map.items():
        if name in sig.WINAPI_FUNCTIONS:
            ctx.winapi_map[name] = address
            result = True
        else:
            for prefix in sig.WINAPI_FUNCTION_PREFIXES:
                if name.lower().startswith(prefix.lower()):
                    ctx.winapi_map[name] = address
                    result = True
                    break
    return result


def populate_driver_map(ctx: AnalysisContext) -> bool:
    """
    Scan functions_map for user-defined driver-specific functions into
    ctx.driver_map.  Returns True when at least one match was found.
    """
    result = False
    for name, address in ctx.functions_map.items():
        if name in sig.DRIVER_FUNCTIONS:
            ctx.driver_map[name] = address
            result = True
    return result


def populate_data_structures(rep: Reporter, ctx: AnalysisContext) -> bool:
    """
    Enumerate all functions, search for dangerous opcodes and flagged C/WinAPI
    functions, and record cross-references as findings.
    Returns True on success, False if IDA has no functions to enumerate.
    """
    if not populate_function_map(ctx):
        rep.info("[!] ERR: Couldn't populate function_map")
        return False

    rep.info("[>] Searching for interesting opcodes...")
    for opcode in sig.OPCODES:
        find(rep, opcode, exec_only=True)

    rep.info("[>] Searching for interesting C/C++ functions...")
    if populate_c_map(ctx):
        get_xrefs(ctx.c_map, rep, "C/C++")

    rep.info("[>] Searching for interesting Windows APIs...")
    if populate_winapi_map(ctx):
        get_xrefs(ctx.winapi_map, rep, "WinAPI")

    if sig.DRIVER_FUNCTIONS:
        rep.info("[>] Searching for interesting driver functions...")
        if populate_driver_map(ctx):
            get_xrefs(ctx.driver_map, rep, "driver")

    return True


def get_xrefs(func_map: Dict[str, int], rep: Reporter, kind: str = "function") -> None:
    """
    Emit a Finding(category='flagged_function') for every cross-reference to
    a function in *func_map*.  Severity is taken from sig.DANGEROUS_SINKS
    when the function is a known high-signal sink, else SEV_LOW.
    """
    for name, address in func_map.items():
        severity = sig.DANGEROUS_SINKS.get(name, config.SEV_LOW)
        for ref in idautils.CodeRefsTo(int(address), 0):
            func_name = (ida_funcs.get_func_name(ref)
                         or ida_segment.get_segm_name(ida_segment.getseg(ref)))
            rep.add(Finding(
                category="flagged_function",
                title=name,
                ea=ref,
                func=func_name,
                severity=severity,
                detail="{} function".format(kind),
            ))


def get_driver_id(driver_entry_addr: int, rep: Reporter, ctx: AnalysisContext) -> str:
    """
    Classify the driver type by examining imports, then kick off type-specific
    analysis (WDF struct identification, WDM dispatch detection, etc.).
    Returns a string such as 'WDM', 'WDF', 'KMDF', 'Mini-Filter', etc.
    """
    driver_type = ""
    for name in ctx.imports_map:
        if name == "FltRegisterFilter":
            driver_type = "Mini-Filter"
            break
        if name == "WdfVersionBind":
            driver_type = populate_wdf(rep)  # returns KMDF/UMDF/WDF (issue #29)
            break
        if name == "StreamClassRegisterMinidriver":
            driver_type = "Stream Minidriver"
            break
        if name == "KsCreateFilterFactory":
            driver_type = "AVStream"
            break
        if name == "PcRegisterSubdevice":
            driver_type = "PortCls"
            break

    if not driver_type:
        rep.info("[!] Unable to determine driver type; assuming WDM")
        driver_type = "WDM"
        real_entry = check_for_fake_driver_entry(driver_entry_addr, rep)
        ctx.real_entry_addr = real_entry
        ddc_map = locate_ddc(real_entry, rep)
        if ddc_map is not None:
            for ddc in ddc_map.values():
                define_ddc(ddc, rep)
                ctx.ddc_addresses.append(ddc)
        if ddc_map is None:
            for ea in find_dispatch_function(rep):
                ctx.ddc_addresses.append(ea)

    return driver_type


def is_driver() -> Optional[int]:
    """
    Scan all segments for a DriverEntry function.
    Returns the EA of DriverEntry, DriverEntry_0, or GsDriverEntry if found, else False.
    GsDriverEntry is emitted by IDA 8.2+ for drivers compiled with /GS (issue #31).
    """
    for seg_ea in idautils.Segments():
        for func_addr in idautils.Functions(
                idc.get_segm_start(seg_ea), idc.get_segm_end(seg_ea)):
            name = idc.get_func_name(func_addr)
            if name in ("DriverEntry", "DriverEntry_0", "GsDriverEntry"):
                return func_addr
    return False


# ---------------------------------------------------------------------------
# N3: Device ACL / security descriptor analysis
# ---------------------------------------------------------------------------

# SIDs that represent broad/unauthenticated access in SDDL strings.
_WORLD_SIDS = {"WD", "S-1-1-0", "BU", "S-1-5-32-545"}
# SDDL strings start with one of these component identifiers.
_SDDL_PREFIXES = ("D:", "O:", "G:", "S:")


def _build_sddl_map() -> dict:
    """
    Scan the IDA string list for UTF-16 strings that look like SDDL descriptors.
    Returns {ea: sddl_string}.
    """
    result = {}
    try:
        sc = ida_strlist.string_info_t()
        for i in range(ida_strlist.get_strlist_qty()):
            if not ida_strlist.get_strlist_item(sc, i):
                continue
            try:
                raw = idc.get_strlit_contents(sc.ea, sc.length, sc.type)
                if not raw:
                    continue
                s = raw.decode("utf-16-le", errors="ignore").rstrip("\x00")
                if len(s) > 4 and any(s.startswith(p) for p in _SDDL_PREFIXES):
                    result[sc.ea] = s
            except Exception:
                continue
    except Exception:
        pass
    return result


def _find_sddl_in_func(func_ea: int, sddl_map: dict) -> Optional[str]:
    """
    Walk all instructions of func_ea and check whether any data xref points to a
    known SDDL string EA.  Returns the first matching SDDL string or None.
    """
    if not sddl_map:
        return None
    sddl_eas = set(sddl_map.keys())
    try:
        for head in idautils.FuncItems(func_ea):
            for ref in idautils.DataRefsFrom(head):
                if ref in sddl_eas:
                    return sddl_map[ref]
    except Exception:
        pass
    return None


# Per-API (title, detail) for the unsecured device-creation APIs.  The
# IoCreateDevice wording is kept verbatim to preserve the golden-regression baseline.
_UNSECURED_DEVICE_GUIDANCE = {
    "IoCreateDevice": (
        "IoCreateDevice: world-accessible by default",
        "IoCreateDevice assigns no security descriptor; accessible to all users. "
        "Consider IoCreateDeviceSecure with a restrictive SDDL."),
    "WdfDeviceCreate": (
        "WdfDeviceCreate: security descriptor not set inline",
        "WdfDeviceCreate carries no inline SDDL; the device DACL must be assigned via "
        "WdfDeviceInitAssignSDDLString or the INF. Verify it is restrictive."),
}


def find_device_create_calls(rep: "Reporter", ctx: "AnalysisContext") -> None:
    """
    N3: Walk xrefs to device-creation APIs and audit ACL posture.

    The unsecured APIs (sig.DEVICE_CREATE_UNSECURED_FUNCS: IoCreateDevice,
    WdfDeviceCreate) set no security descriptor on the create call itself -> LOW,
    flagged for manual ACL review.  IoCreateDeviceSecure accepts an inline SDDL
    string; if it contains a world SID -> MEDIUM, if the SDDL cannot be statically
    recovered -> LOW (needs manual review).

    Lookups use ctx.functions_map (a superset of ctx.imports_map) so WDF functions
    resolved as named subs are covered alongside the ntoskrnl imports.
    """
    sddl_map = _build_sddl_map()

    for func_name in sorted(sig.DEVICE_CREATE_UNSECURED_FUNCS):
        ea = ctx.functions_map.get(func_name)
        if not ea:
            continue
        title, detail = _UNSECURED_DEVICE_GUIDANCE.get(
            func_name,
            ("{}: security descriptor not set inline".format(func_name),
             "{} creates a device with no inline security descriptor; "
             "verify the device DACL is restrictive.".format(func_name)))
        seen_sites = set()
        for xr in idautils.XrefsTo(ea, 0):
            if xr.frm in seen_sites:
                continue  # one import can resolve via several xref kinds per call site
            seen_sites.add(xr.frm)
            fn = ida_funcs.get_func(xr.frm)
            caller_name = ida_funcs.get_func_name(fn.start_ea) if fn else ""
            rep.add(Finding(
                category="acl",
                title=title,
                ea=xr.frm,
                func=caller_name,
                severity=config.SEV_LOW,
                detail=detail))

    ea = ctx.functions_map.get("IoCreateDeviceSecure")
    if not ea:
        return
    seen_secure_sites = set()
    for xr in idautils.XrefsTo(ea, 0):
        if xr.frm in seen_secure_sites:
            continue
        seen_secure_sites.add(xr.frm)
        fn = ida_funcs.get_func(xr.frm)
        caller_name = ida_funcs.get_func_name(fn.start_ea) if fn else ""
        func_ea = fn.start_ea if fn else None
        sddl = _find_sddl_in_func(func_ea, sddl_map) if func_ea is not None else None
        if sddl:
            world_accessible = any(sid in sddl for sid in _WORLD_SIDS)
            if world_accessible:
                rep.add(Finding(
                    category="acl",
                    title="IoCreateDeviceSecure: world-accessible SDDL",
                    ea=xr.frm,
                    func=caller_name,
                    severity=config.SEV_MEDIUM,
                    data={"sddl": sddl},
                    detail="SDDL grants access to world/builtin-users SID: {}".format(sddl)))
            else:
                rep.info("[+] IoCreateDeviceSecure at 0x{:x}: SDDL appears restrictive: {}".format(
                    xr.frm, sddl))
        else:
            rep.add(Finding(
                category="acl",
                title="IoCreateDeviceSecure: SDDL could not be decoded",
                ea=xr.frm,
                func=caller_name,
                severity=config.SEV_LOW,
                detail="Could not statically recover the SDDL; "
                       "manual review required to confirm access posture."))
