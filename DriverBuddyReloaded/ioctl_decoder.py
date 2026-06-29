"""
ioctl_decoder.py: IOCTL code decoding, text-search and flow-chart-based IOCTL discovery.

Decode functions are pure Python (no IDA) and are tested offline.  The two discovery
functions -- find_ioctls() and scan_dispatchers() -- require a live IDA database.

find_ioctls() uses IDA's IoControlCode operand annotations (fast, requires struct types).
scan_dispatchers() does a flow-chart brute-force scan of identified dispatcher functions,
picking up IOCTLs that find_ioctls() misses when IDA has not applied WDM struct types.

A bulk of the original IOCTL decode code is from Satoshi Tanda's WinIoCtlDecoder:
https://github.com/tandasat/WinIoCtlDecoder/blob/master/plugins/WinIoCtlDecoder.py
"""

from __future__ import annotations

from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    from DriverBuddyReloaded.reporting import Reporter

import ida_funcs
import idaapi
import idc

from DriverBuddyReloaded import config, ida_compat
from DriverBuddyReloaded.reporting import Finding


def get_ioctl_code(ioctl_code):
    """
    Decodes Windows I/O control code.
    :param ioctl_code: Immediate value which represents a valid Windows IOCTL
    :return:
    """

    device_name_unknown = "<UNKNOWN>"
    device_names = [
        device_name_unknown,  # 0x00000000
        "FILE_DEVICE_BEEP",  # 0x00000001
        "FILE_DEVICE_CD_ROM",  # 0x00000002
        "FILE_DEVICE_CD_ROM_FILE_SYSTEM",  # 0x00000003
        "FILE_DEVICE_CONTROLLER",  # 0x00000004
        "FILE_DEVICE_DATALINK",  # 0x00000005
        "FILE_DEVICE_DFS",  # 0x00000006
        "FILE_DEVICE_DISK",  # 0x00000007
        "FILE_DEVICE_DISK_FILE_SYSTEM",  # 0x00000008
        "FILE_DEVICE_FILE_SYSTEM",  # 0x00000009
        "FILE_DEVICE_INPORT_PORT",  # 0x0000000a
        "FILE_DEVICE_KEYBOARD",  # 0x0000000b
        "FILE_DEVICE_MAILSLOT",  # 0x0000000c
        "FILE_DEVICE_MIDI_IN",  # 0x0000000d
        "FILE_DEVICE_MIDI_OUT",  # 0x0000000e
        "FILE_DEVICE_MOUSE",  # 0x0000000f
        "FILE_DEVICE_MULTI_UNC_PROVIDER",  # 0x00000010
        "FILE_DEVICE_NAMED_PIPE",  # 0x00000011
        "FILE_DEVICE_NETWORK",  # 0x00000012
        "FILE_DEVICE_NETWORK_BROWSER",  # 0x00000013
        "FILE_DEVICE_NETWORK_FILE_SYSTEM",  # 0x00000014
        "FILE_DEVICE_NULL",  # 0x00000015
        "FILE_DEVICE_PARALLEL_PORT",  # 0x00000016
        "FILE_DEVICE_PHYSICAL_NETCARD",  # 0x00000017
        "FILE_DEVICE_PRINTER",  # 0x00000018
        "FILE_DEVICE_SCANNER",  # 0x00000019
        "FILE_DEVICE_SERIAL_MOUSE_PORT",  # 0x0000001a
        "FILE_DEVICE_SERIAL_PORT",  # 0x0000001b
        "FILE_DEVICE_SCREEN",  # 0x0000001c
        "FILE_DEVICE_SOUND",  # 0x0000001d
        "FILE_DEVICE_STREAMS",  # 0x0000001e
        "FILE_DEVICE_TAPE",  # 0x0000001f
        "FILE_DEVICE_TAPE_FILE_SYSTEM",  # 0x00000020
        "FILE_DEVICE_TRANSPORT",  # 0x00000021
        "FILE_DEVICE_UNKNOWN",  # 0x00000022
        "FILE_DEVICE_VIDEO",  # 0x00000023
        "FILE_DEVICE_VIRTUAL_DISK",  # 0x00000024
        "FILE_DEVICE_WAVE_IN",  # 0x00000025
        "FILE_DEVICE_WAVE_OUT",  # 0x00000026
        "FILE_DEVICE_8042_PORT",  # 0x00000027
        "FILE_DEVICE_NETWORK_REDIRECTOR",  # 0x00000028
        "FILE_DEVICE_BATTERY",  # 0x00000029
        "FILE_DEVICE_BUS_EXTENDER",  # 0x0000002a
        "FILE_DEVICE_MODEM",  # 0x0000002b
        "FILE_DEVICE_VDM",  # 0x0000002c
        "FILE_DEVICE_MASS_STORAGE",  # 0x0000002d
        "FILE_DEVICE_SMB",  # 0x0000002e
        "FILE_DEVICE_KS",  # 0x0000002f
        "FILE_DEVICE_CHANGER",  # 0x00000030
        "FILE_DEVICE_SMARTCARD",  # 0x00000031
        "FILE_DEVICE_ACPI",  # 0x00000032
        "FILE_DEVICE_DVD",  # 0x00000033
        "FILE_DEVICE_FULLSCREEN_VIDEO",  # 0x00000034
        "FILE_DEVICE_DFS_FILE_SYSTEM",  # 0x00000035
        "FILE_DEVICE_DFS_VOLUME",  # 0x00000036
        "FILE_DEVICE_SERENUM",  # 0x00000037
        "FILE_DEVICE_TERMSRV",  # 0x00000038
        "FILE_DEVICE_KSEC",  # 0x00000039
        "FILE_DEVICE_FIPS",  # 0x0000003A
        "FILE_DEVICE_INFINIBAND",  # 0x0000003B
        device_name_unknown,  # 0x0000003C
        device_name_unknown,  # 0x0000003D
        "FILE_DEVICE_VMBUS",  # 0x0000003E
        "FILE_DEVICE_CRYPT_PROVIDER",  # 0x0000003F
        "FILE_DEVICE_WPD",  # 0x00000040
        "FILE_DEVICE_BLUETOOTH",  # 0x00000041
        "FILE_DEVICE_MT_COMPOSITE",  # 0x00000042
        "FILE_DEVICE_MT_TRANSPORT",  # 0x00000043
        "FILE_DEVICE_BIOMETRIC",  # 0x00000044
        "FILE_DEVICE_PMI",  # 0x00000045
        "FILE_DEVICE_EHSTOR",  # 0x00000046
        "FILE_DEVICE_DEVAPI",  # 0x00000047
        "FILE_DEVICE_GPIO",  # 0x00000048
        "FILE_DEVICE_USBEX",  # 0x00000049
        device_name_unknown,  # 0x0000004A
        device_name_unknown,  # 0x0000004B
        device_name_unknown,  # 0x0000004C
        device_name_unknown,  # 0x0000004D
        device_name_unknown,  # 0x0000004E
        device_name_unknown,  # 0x0000004F
        "FILE_DEVICE_CONSOLE",  # 0x00000050
        "FILE_DEVICE_NFP",  # 0x00000051
        "FILE_DEVICE_SYSENV",  # 0x00000052
        "FILE_DEVICE_VIRTUAL_BLOCK",  # 0x00000053
        "FILE_DEVICE_POINT_OF_SERVICE",  # 0x00000054
        "FILE_DEVICE_STORAGE_REPLICATION",  # 0x00000055
        "FILE_DEVICE_TRUST_ENV",  # 0x00000056
        "FILE_DEVICE_UCM",  # 0x00000057
        "FILE_DEVICE_UCMTCPCI",  # 0x00000058
        "FILE_DEVICE_PERSISTENT_MEMORY",  # 0x00000059
        "FILE_DEVICE_NVDIMM",  # 0x0000005a
        "FILE_DEVICE_HOLOGRAPHIC",  # 0x0000005b
        "FILE_DEVICE_SDFXHCI",  # 0x0000005c
        "FILE_DEVICE_UCMUCSI",  # 0x0000005d
        "FILE_DEVICE_PRM",  # 0x0000005e
        "FILE_DEVICE_EVENT_COLLECTOR",  # 0x0000005f
        "FILE_DEVICE_USB4",  # 0x00000060
        "FILE_DEVICE_SOUNDWIRE",  # 0x00000061
        "FILE_DEVICE_FABRIC_NVME",  # 0x00000062
        "FILE_DEVICE_SVM",  # 0x00000063
        "FILE_DEVICE_HARDWARE_ACCELERATOR",  # 0x00000064
        "FILE_DEVICE_I3C",  # 0x00000065
    ]

    # Non-standard device types not defined in wdm.h (sparse high codes).
    custom_devices = [
        {"name": "MOUNTMGRCONTROLTYPE", "code": 0x0000006d},
        {"name": "FILE_DEVICE_IRCLASS", "code": 0x00000f60},
    ]

    device = (ioctl_code >> 16) & 0xffff
    if device >= len(device_names):
        device_name = device_name_unknown
        for dev in custom_devices:
            if device == dev["code"]:
                device_name = dev["name"]
                break
    else:
        device_name = device_names[device]
    return device_name, device


def get_method(ioctl_code):
    """
    Returns the correct method type name for a 32 bit IOCTL code
    :param ioctl_code:
    :return:
    """

    method_names = [
        "METHOD_BUFFERED",
        "METHOD_IN_DIRECT",
        "METHOD_OUT_DIRECT",
        "METHOD_NEITHER",
    ]
    method = ioctl_code & 3
    return method_names[method], method


def get_access(ioctl_code):
    """
    Returns the correct access type name for a 32 bit IOCTL code
    :param ioctl_code:
    :return:
    """

    access_names = [
        "FILE_ANY_ACCESS",
        "FILE_READ_ACCESS",
        "FILE_WRITE_ACCESS",
        "FILE_READ_ACCESS | FILE_WRITE_ACCESS",
    ]
    access = (ioctl_code >> 14) & 3
    return access_names[access], access


def get_function(ioctl_code):
    """
    Calculates the function code from a 32 bit IOCTL code
    :param ioctl_code:
    :return:
    """

    return (ioctl_code >> 2) & 0xfff


def decode(ioctl_code):
    """
    Decode a 32-bit IOCTL into its constituent fields. Single source of truth used
    by the table printer, the auto-scanner and risk scoring.
    :param ioctl_code: immediate value representing a Windows IOCTL
    :return dict: decoded fields
    """

    device_name, device_code = get_ioctl_code(ioctl_code)
    method_name, method_code = get_method(ioctl_code)
    access_name, access_code = get_access(ioctl_code)
    return {
        "code": ioctl_code,
        "device_name": device_name,
        "device_code": device_code,
        "function": get_function(ioctl_code),
        "method_name": method_name,
        "method_code": method_code,
        "access_name": access_name,
        "access_code": access_code,
    }


def define_name(ioctl_code):
    """C identifier for an IOCTL, derived from the driver name."""
    return "%s_0x%08X" % (config.driver_name().split(".")[0], ioctl_code)


def get_define(ioctl_code):
    """
    Decodes an ioctl code and returns a C define for it using the CTL_CODE macro
    :param ioctl_code:
    :return:
    """

    d = decode(ioctl_code)
    return "#define %s CTL_CODE(0x%X, 0x%X, %s, %s)" % (
        define_name(ioctl_code), d["device_code"], d["function"], d["method_name"], d["access_name"])


IOCTL_TABLE_HEADER = "%-10s | %-10s | %-42s | %-10s | %-22s | %s" % (
    "Address", "IOCTL Code", "Device", "Function", "Method", "Access")


def format_row(addr, ioctl_code):
    """Render one IOCTL table row, matching the historical column layout."""
    d = decode(ioctl_code)
    return "0x%-8X | 0x%-8X | %-31s 0x%-8X | 0x%-8X | %-17s %-4d | %s (%d)" % (
        addr, ioctl_code, d["device_name"], d["device_code"], d["function"],
        d["method_name"], d["method_code"], d["access_name"], d["access_code"])


_ntstatus_cache = None

# Minimal fallback used when no NTSTATUS enum is loaded in the IDB.
# Covers the most common NTSTATUS values that would otherwise be
# misclassified as IOCTL codes.
_NTSTATUS_FALLBACK = {
    0x00000103,  # STATUS_PENDING
    0x40000000,  # STATUS_OBJECT_TYPE_MISMATCH (info bit set)
    0x80000001,  # STATUS_GUARD_PAGE_VIOLATION
    0x80000002,  # STATUS_DATATYPE_MISALIGNMENT
    0x80000003,  # STATUS_BREAKPOINT
    0x80000004,  # STATUS_SINGLE_STEP
    0x8000000A,  # STATUS_NO_MEMORY
    0xC0000001,  # STATUS_UNSUCCESSFUL
    0xC0000002,  # STATUS_NOT_IMPLEMENTED
    0xC0000003,  # STATUS_INVALID_INFO_CLASS
    0xC0000004,  # STATUS_INFO_LENGTH_MISMATCH
    0xC0000005,  # STATUS_ACCESS_VIOLATION
    0xC0000008,  # STATUS_INVALID_HANDLE
    0xC000000D,  # STATUS_INVALID_PARAMETER
    0xC0000010,  # STATUS_INVALID_DEVICE_REQUEST
    0xC0000017,  # STATUS_NO_MEMORY
    0xC0000022,  # STATUS_ACCESS_DENIED
    0xC000000E,  # STATUS_NO_SUCH_DEVICE
    0xC00000BB,  # STATUS_NOT_SUPPORTED
    0xC0000034,  # STATUS_OBJECT_NAME_NOT_FOUND
}


def _load_enum_values(enum_id: int) -> set:
    """Enumerate all member values from an IDA enum id."""
    values = set()
    _BADADDR = getattr(idc, "BADADDR", 0xFFFFFFFFFFFFFFFF)
    try:
        val = idc.get_first_enum_member(enum_id, -1)
        while val != _BADADDR:
            values.add(val)
            val = idc.get_next_enum_member(enum_id, val, -1)
    except Exception:
        pass
    return values


def _get_ntstatus_values() -> set:
    """
    Return the set of known NTSTATUS values used to filter IOCTL false positives.

    Strategy:
      1. Try idc.get_enum("NTSTATUS") -- loaded by default for PE drivers.
      2. Try idc.get_enum("_NTSTATUS") -- IDA 9.x may use this name.
      3. Fall back to _NTSTATUS_FALLBACK (minimal hardcoded set).

    Result is cached for the lifetime of the process.
    """
    global _ntstatus_cache
    if _ntstatus_cache is not None:
        return _ntstatus_cache

    _BADADDR = getattr(idc, "BADADDR", 0xFFFFFFFFFFFFFFFF)
    for name in ("NTSTATUS", "_NTSTATUS"):
        try:
            eid = idc.get_enum(name)
            if eid not in (None, _BADADDR, -1):
                values = _load_enum_values(eid)
                if values:
                    _ntstatus_cache = values
                    return _ntstatus_cache
        except Exception:
            pass

    _ntstatus_cache = _NTSTATUS_FALLBACK.copy()
    return _ntstatus_cache


# Sentinel values that are structurally valid CTL_CODEs but never real IOCTLs.
# 0xFFFFFFFF is the ubiquitous (DWORD)-1 / INVALID_HANDLE_VALUE comparison
# constant; it surfaces from `== -1` checks inside dispatchers (observed in
# WinRing0) and must not be reported as an IOCTL.
_SENTINEL_REJECTS = frozenset({0xFFFFFFFF})


def _is_valid_ctl_code(value: int) -> bool:
    """Return True when value is a structurally valid CTL_CODE and not a known NTSTATUS.

    CTL_CODE layout: bits[31:16]=DeviceType, bits[15:14]=Access,
    bits[13:2]=Function, bits[1:0]=Method.  A nonzero DeviceType is the
    only meaningful structural gate -- it rules out loop counters, array
    indices, and other small immediates while preserving every valid IOCTL
    including vendor-defined device types (0x8000+).  A small sentinel set and
    the NTSTATUS table strip the false positives that survive the structural
    gate (e.g. the (DWORD)-1 comparison constant and STATUS_* error codes).
    """
    value &= 0xffffffff
    device_type = (value >> 16) & 0xffff
    if device_type == 0:
        return False
    if value in _SENTINEL_REJECTS:
        return False
    return value not in _get_ntstatus_values()


def _emit_ioctl(rep: Reporter, code: int, ea: int, func_name: str,
                source: str, already_seen: set, handler_ea: int = None) -> bool:
    """Add one IOCTL Finding if `code` is a new, valid CTL_CODE.

    Returns True when a finding was added (the code was new and valid).  All
    discovery strategies funnel through here so dedup and validation are
    applied uniformly regardless of how the code was recovered.  When the
    decoder resolved which handler the dispatcher routes this code to,
    `handler_ea` carries it so risk scoring can attribute sinks per-IOCTL
    instead of per-dispatcher.
    """
    code &= 0xffffffff
    if code in already_seen or not _is_valid_ctl_code(code):
        return False
    already_seen.add(code)
    d = decode(code)
    if handler_ea is not None:
        d["handler_ea"] = handler_ea
        d["handler_name"] = ida_funcs.get_func_name(handler_ea) or ("sub_%X" % handler_ea)
    rep.add(Finding(
        category="ioctl",
        title="IOCTL 0x%08X" % code,
        ea=ea,
        func=func_name,
        severity=config.SEV_INFO,
        detail="%s / %s / %s [%s]" % (
            d["device_name"], d["method_name"], d["access_name"], source),
        data=d))
    return True


def _node_ea(node, default: int) -> int:
    """Best-effort source address for a ctree node, falling back to *default*."""
    try:
        ea = node.ea
        if ea is not None and ea != idc.BADADDR:
            return ea
    except Exception:
        pass
    return default


def _collect_immediates(func_ea: int):
    """Yield (code, ea) for cmp/sub/mov instructions with an immediate operand.

    The original brute-force strategy: catches IOCTLs that appear verbatim as
    an immediate in a comparison chain.  Misses codes encoded as jump-table
    offsets or as deltas in a compiler-generated binary search (see the
    switch-table and decompiler collectors for those).
    """
    out = []
    try:
        f = idaapi.get_func(func_ea)
        if not f:
            return out
        fc = idaapi.FlowChart(f, flags=idaapi.FC_PREDS)
        for block in fc:
            instr = block.start_ea
            while instr != idc.BADADDR and instr < block.end_ea:
                if (idc.print_insn_mnem(instr) in ('cmp', 'sub', 'mov')
                        and idc.get_operand_type(instr, 1) == idc.o_imm):
                    out.append((idc.get_operand_value(instr, 1) & 0xffffffff, instr))
                instr = idc.next_head(instr, block.end_ea)
    except Exception:
        pass
    return out


def _get_switch_info(ea: int):
    """Cross-version idaapi/ida_nalt switch-info lookup for the jump at `ea`."""
    try:
        import ida_nalt
        fn = getattr(ida_nalt, "get_switch_info", None)
        if fn is not None:
            return fn(ea)
    except Exception:
        pass
    fn = getattr(idaapi, "get_switch_info_ex", None) or getattr(idaapi, "get_switch_info", None)
    if fn is not None:
        try:
            return fn(ea)
        except Exception:
            return None
    return None


def _collect_switch_cases(func_ea: int):
    """Yield (code, ea) for every explicit case label of switches in *func_ea*.

    Uses IDA's recovered switch metadata (idaapi.calc_switch_cases), so it works
    without the decompiler.  This recovers jump-table dispatch (e.g. ALSysIO64),
    where the individual IOCTL codes never appear as immediates -- only the
    table base and bound do.  Case groups that target the default handler are
    excluded so the dense "filler" values between real cases are not reported.
    """
    out = []
    try:
        f = idaapi.get_func(func_ea)
        if not f:
            return out
        calc = getattr(idaapi, "calc_switch_cases", None)
        cur = f.start_ea
        while cur != idc.BADADDR and cur < f.end_ea:
            si = _get_switch_info(cur)
            if si is not None and getattr(si, "ncases", 0) and calc is not None:
                try:
                    defjump = int(getattr(si, "defjump", idc.BADADDR))
                    cat = calc(cur, si)
                    for i in range(cat.cases.size()):
                        if cat.targets[i] == defjump:
                            continue  # default block: skip dense filler values
                        cvec = cat.cases[i]
                        for j in range(cvec.size()):
                            out.append((int(cvec[j]) & 0xffffffff, cur))
                except Exception:
                    pass
            cur = idc.next_head(cur, f.end_ea)
    except Exception:
        pass
    return out


def _collect_hexrays_consts(func_ea: int):
    """Yield (code, ea) for IOCTL constants recovered from the decompiler ctree.

    The decompiler reconstructs both jump-table switches and compiler-generated
    binary-search comparison trees back into explicit `switch`/`==` constructs,
    so it recovers IOCTL codes that never survive as immediates in the
    disassembly (e.g. 21 of HEVD's 28 codes).  Two kinds of constant are taken:

      - switch case-label values: highest confidence.  The default case carries
        no values, so the dense filler between real cases is naturally excluded.
      - the constant operand of an == / != comparison.  These are needed both
        for drivers that dispatch via an if-chain (no switch at all, e.g. beep)
        and for the occasional case the decompiler renders as a comparison
        rather than folding it into the switch (e.g. one of HEVD's 28).

    Comparison constants are anchored to avoid false positives: when the
    function contains a switch, only == / != comparisons made against a
    switch-selector variable are kept (so a `status == STATUS_BUFFER_TOO_SMALL`
    check on an unrelated variable is ignored).  When there is no switch to
    anchor on, every comparison constant is taken and left to the structural /
    NTSTATUS / sentinel filter in _emit_ioctl.
    """
    try:
        import ida_hexrays
    except Exception:
        return []
    try:
        init = getattr(ida_hexrays, "init_hexrays_plugin", None)
        if init is not None and not init():
            return []
    except Exception:
        return []

    switch_cases = []          # [(code, ea)] -- always kept
    switch_vars = set()        # lvar indices used as a switch selector
    eq_candidates = []         # [(var_idx_or_None, code, ea)]
    try:
        cfunc = ida_hexrays.decompile(func_ea)
        if cfunc is None:
            return []

        CV_FAST = getattr(ida_hexrays, "CV_FAST", 8)
        cot_num = getattr(ida_hexrays, "cot_num", None)
        cot_var = getattr(ida_hexrays, "cot_var", None)
        cot_cast = getattr(ida_hexrays, "cot_cast", None)
        cot_eq = getattr(ida_hexrays, "cot_eq", None)
        cot_ne = getattr(ida_hexrays, "cot_ne", None)
        cot_call = getattr(ida_hexrays, "cot_call", None)
        cot_obj = getattr(ida_hexrays, "cot_obj", None)
        cit_switch = getattr(ida_hexrays, "cit_switch", None)
        if cot_num is None:
            return []
        eq_ops = frozenset(o for o in (cot_eq, cot_ne) if o is not None)

        def _case_handler_ea(case_insn):
            """Start EA of the first in-binary function a switch case calls, i.e.
            the per-IOCTL handler.  Imported callees (DbgPrintEx logging, etc.)
            resolve to no function and are skipped, so the real handler/wrapper
            wins even when logging precedes it."""
            if cot_call is None or cot_obj is None:
                return None
            box = [None]

            class _CC(ida_hexrays.ctree_visitor_t):
                def __init__(self):
                    ida_hexrays.ctree_visitor_t.__init__(self, CV_FAST)

                def visit_expr(self, e):
                    if box[0] is None and e.op == cot_call and e.x is not None and e.x.op == cot_obj:
                        try:
                            f = ida_funcs.get_func(e.x.obj_ea)
                            if f:
                                box[0] = f.start_ea
                        except Exception:
                            pass
                    return 0

            try:
                _CC().apply_to(case_insn, None)
            except Exception:
                pass
            return box[0]

        def _unwrap(node):
            while cot_cast is not None and node is not None and node.op == cot_cast:
                node = node.x
            return node

        def _var_idx(node):
            node = _unwrap(node)
            if node is not None and cot_var is not None and node.op == cot_var:
                try:
                    return node.v.idx
                except Exception:
                    return None
            return None

        class _Collector(ida_hexrays.ctree_visitor_t):
            def __init__(self):
                ida_hexrays.ctree_visitor_t.__init__(self, CV_FAST)

            def visit_expr(self, e):
                try:
                    if e.op in eq_ops:
                        x, y = e.x, e.y
                        if x.op == cot_num and y.op != cot_num:
                            const_node, other = x, y
                        elif y.op == cot_num and x.op != cot_num:
                            const_node, other = y, x
                        else:
                            return 0
                        eq_candidates.append((
                            _var_idx(other),
                            int(const_node.numval()) & 0xffffffff,
                            _node_ea(e, func_ea)))
                except Exception:
                    pass
                return 0

            def visit_insn(self, ins):
                try:
                    if cit_switch is not None and ins.op == cit_switch:
                        sw = ins.cswitch
                        sel = _var_idx(sw.expr)
                        if sel is not None:
                            switch_vars.add(sel)
                        ea = _node_ea(ins, func_ea)
                        for case in sw.cases:
                            handler_ea = _case_handler_ea(case)
                            for val in case.values:
                                switch_cases.append((int(val) & 0xffffffff, ea, handler_ea))
                except Exception:
                    pass
                return 0

        _Collector().apply_to(cfunc.body, None)
    except Exception:
        pass

    found = list(switch_cases)  # (code, ea, handler_ea) triples
    for var_idx, code, ea in eq_candidates:
        # With a switch present, only trust comparisons against the selector
        # variable; without one, accept every comparison constant.
        if not switch_vars or (var_idx is not None and var_idx in switch_vars):
            found.append((code, ea, None))  # if-chain comparison has no case body
    return found


def scan_dispatchers(rep: Reporter, ddc_addresses: List[int]) -> bool:
    """
    Multi-strategy IOCTL recovery over every identified WDM dispatch handler.

    Complements find_ioctls() (which relies on IDA's IoControlCode operand
    annotation) by running three independent collectors over each dispatcher
    and merging their results into a single deduplicated set:

      1. decompiler ctree  -- switch cases + == / != constants (most complete;
         recovers codes that never appear as immediates, e.g. binary-search
         dispatch). Gated on config.Feature.IOCTL_DECOMPILER and HexRays.
      2. IDA switch tables -- calc_switch_cases case labels minus the default
         (recovers jump-table dispatch without needing the decompiler).
      3. immediate scan    -- cmp/sub/mov immediate operands (the original
         brute-force fallback for simple comparison chains).

    Running all three maximises recall regardless of how a given driver was
    compiled or which IDA features are available.  Every candidate is validated
    and deduplicated by _emit_ioctl, so codes already recorded by find_ioctls()
    (or an earlier collector) are not double-counted.

    :param rep: Reporter instance
    :param ddc_addresses: list of function start EAs to scan
    :return bool: True if any new IOCTLs were found
    """
    if not ddc_addresses:
        return False

    already_seen = {
        f.data["code"]
        for f in rep.by_category("ioctl")
        if f.data and "code" in f.data
    }
    result = False
    ddc_list = list(ddc_addresses)

    for i, func_ea in enumerate(ddc_list):
        rep.info("  [scan] dispatcher 0x{:x} ({}/{})".format(func_ea, i + 1, len(ddc_list)))
        func_name = ida_funcs.get_func_name(func_ea) or ""

        # The structured collectors (decompiler ctree, IDA switch tables) know
        # which constants are dispatch values, so they are precise.  The raw
        # immediate scan cannot tell an IOCTL from an NTSTATUS code moved into a
        # register or a magic constant, so it is only used as a last resort when
        # the structured methods recover nothing for this dispatcher.
        structured = []
        if config.Feature.IOCTL_DECOMPILER:
            structured.append(("decompiler", _collect_hexrays_consts(func_ea)))
        structured.append(("switch table", _collect_switch_cases(func_ea)))

        emitted_here = False
        for source, candidates in structured:
            for cand in candidates:
                # decompiler collector yields (code, ea, handler_ea);
                # the switch-table collector yields (code, ea).
                code, ea = cand[0], cand[1]
                handler_ea = cand[2] if len(cand) > 2 else None
                if _emit_ioctl(rep, code, ea, func_name, source, already_seen, handler_ea):
                    result = True
                    emitted_here = True

        if not emitted_here:
            for code, ea in _collect_immediates(func_ea):
                if _emit_ioctl(rep, code, ea, func_name, "dispatcher scan", already_seen):
                    result = True
    return result


def find_ioctls(rep: Reporter) -> bool:
    """
    Attempts to locate IOCTLs in the driver automatically by scanning for
    `IoControlCode` references and decoding the associated immediate operand.
    Emits one Finding(category="ioctl") per code (severity is assigned later by
    the scoring stage).
    :param rep: Reporter instance
    :return boolean: True if any IOCTLs found, False otherwise
    """

    result = False
    rep.info("[>] Searching for IOCTLs found by IDA...")
    for ea in ida_compat.iter_text_matches("IoControlCode"):
        for opnd in (0, 1):
            if idc.get_operand_type(ea, opnd) != idc.o_imm:
                continue
            idc.op_dec(ea, opnd)
            try:
                raw = idc.print_operand(ea, opnd)
                ioctl_code = int(raw, 16) if raw.startswith(("0x", "0X")) else int(raw)
            except (TypeError, ValueError):
                continue
            if not _is_valid_ctl_code(ioctl_code):
                continue
            d = decode(ioctl_code)
            rep.add(Finding(
                category="ioctl",
                title="IOCTL 0x%08X" % ioctl_code,
                ea=ea,
                func=ida_funcs.get_func_name(ea) or "",
                severity=config.SEV_INFO,
                detail="%s / %s / %s" % (d["device_name"], d["method_name"], d["access_name"]),
                data=d))
            result = True
            break
    return result
