#!/usr/bin/env python3
"""
Self-contained regression tests for Driver Buddy Reloaded's IDA-independent logic.

These install minimal in-memory stubs for the IDA Python modules, so they run
under plain CPython with no IDA installed:

    python3 tests/test_dbr.py            # defaults to simulating IDA 8.4
    DBR_SDK=900 python3 tests/test_dbr.py  # simulate IDA 9.0 import paths

They cover the parts that can be validated outside IDA (IOCTL decoding, risk
scoring, JSON/HTML/PoC generation and full plugin import on 7.x/8.4/9.0 SDKs).
Behaviour that touches the live database must still be checked inside IDA.
"""

import json
import os
import sys
import tempfile
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_BADADDR = 0xFFFFFFFFFFFFFFFF


def _install_ida_stubs():
    """Register permissive stand-ins for the IDA Python modules in sys.modules."""

    class _Any:
        def __init__(self, *args, **kwargs):
            pass

        def __call__(self, *args, **kwargs):
            return _ANY

        def __getattr__(self, n):
            return _ANY

        def __iter__(self):
            return iter([])

        def __int__(self):
            return 0

        def __index__(self):
            return 0

        def __bool__(self):
            return False

    _ANY = _Any()

    def mod(name, **attrs):
        m = types.ModuleType(name)
        for k, v in attrs.items():
            setattr(m, k, v)
        m.__getattr__ = lambda n: _ANY  # type: ignore[attr-defined]
        sys.modules[name] = m
        return m

    class _Choose:
        CH_CAN_REFRESH = 1

        def __init__(self, *args, **kwargs):
            pass

        def Show(self, *args, **kwargs):
            return 0

    class _Plugin:
        pass

    class _ActionHandler:
        def __init__(self, *args, **kwargs):
            pass

    class _UIHooks:
        def __init__(self, *args, **kwargs):
            pass

        def hook(self):
            pass

    class _BinPat(list):
        def size(self):
            return len(self)

    sdk = int(os.environ.get("DBR_SDK", "840"))
    mod("idaapi", IDA_SDK_VERSION=sdk, BADADDR=_BADADDR,
        PLUGIN_UNL=0, PLUGIN_KEEP=1, PLUGIN_OK=0, AST_ENABLE_ALWAYS=1,
        BWN_DISASM=0x29, FC_PREDS=0x10, plugin_t=_Plugin,
        action_handler_t=_ActionHandler, UI_Hooks=_UIHooks,
        compiled_binpat_vec_t=_BinPat, get_qword=lambda ea: 0, get_dword=lambda ea: 0)
    mod("idc", BADADDR=_BADADDR, FF_DATA=0x400, FUNC_LIB=0x4,
        get_root_filename=lambda: "stub.sys",
        # NTSTATUS enum stubs -- return sentinel "not found" so the fallback path is exercised
        get_enum=lambda name: _BADADDR,
        get_first_enum_member=lambda eid, serial: _BADADDR,
        get_next_enum_member=lambda eid, val, serial: _BADADDR,
        SEGPERM_EXEC=0x4,
        get_segm_start=lambda ea: 0x1000,
        get_segm_end=lambda ea: 0x2000,
        next_head=lambda ea, end=0: ea + 4)
    mod("idautils")
    mod("ida_funcs", get_func_name=lambda ea: "")
    mod("ida_segment")
    mod("ida_nalt", get_root_filename=lambda: "stub.sys",
        retrieve_input_file_sha256=lambda: b"\xab" * 32)
    mod("ida_search")
    mod("ida_ua")
    mod("ida_xref")
    mod("ida_bytes", FF_QWORD=0x30000000, FF_DWORD=0x20000000,
        BIN_SEARCH_NOCASE=1, BIN_SEARCH_CASE=0, BIN_SEARCH_FORWARD=2)
    mod("ida_ida", inf_is_64bit=lambda: True,
        inf_get_min_ea=lambda: 0x1000, inf_get_max_ea=lambda: 0x2000)
    mod("ida_idaapi", BADADDR=_BADADDR)
    mod("ida_kernwin", Choose=_Choose, jumpto=lambda ea: True)
    mod("ida_lines", generate_disasm_line=lambda ea, f=0: "", tag_remove=lambda s: s or "",
        E_PREV=1000, E_NEXT=2000,
        get_extra_cmt=lambda ea, what: None,
        add_extra_cmt=lambda ea, isprev, line: True,
        del_extra_cmt=lambda ea, what: True)
    mod("ida_loader", PATH_TYPE_IDB=0, get_path=lambda t: "")
    mod("ida_typeinf", PT_SIL=1, HTI_DCL=1, NTF_TYPE=1, TINFO_DEFINITE=1,
        get_idati=lambda: object())
    mod("ida_strlist", get_strlist_qty=lambda: 0,
        get_strlist_item=lambda sc, i: False,
        string_info_t=_Any)


def main():
    _install_ida_stubs()
    sys.path.insert(0, ROOT)

    from DriverBuddyReloaded import config, ioctl_decoder, scoring, poc, reporting
    from DriverBuddyReloaded import device_name_finder

    failures = []
    total = [0]

    def check(cond, label):
        total[0] += 1
        print(("  PASS " if cond else "  FAIL ") + label)
        if not cond:
            failures.append(label)

    # ---- device_name_finder: REPEATS bytes fix ----
    # A null-filled buffer must short-circuit without TypeError (buf[0:1] vs buf[0]).
    check(list(device_name_finder.extract_unicode_strings(b"\x00" * 200)) == [],
          "repeat null buf exits cleanly")
    # An 'A'-filled buffer also exits cleanly via the repeat shortcut.
    check(list(device_name_finder.extract_unicode_strings(b"A" * 200)) == [],
          "repeat A buf exits cleanly")
    # A real UTF-16LE device name is found correctly.
    dev_utf16 = "\\Device\\Test".encode("utf-16-le")
    found_strings = list(device_name_finder.extract_unicode_strings(dev_utf16))
    check(any("Test" in s.s for s in found_strings), "utf16 device name found")

    # ---- IOCTL decode ----
    d = ioctl_decoder.decode(0x222000)
    check(d["device_name"] == "FILE_DEVICE_UNKNOWN", "decode device")
    check(d["method_name"] == "METHOD_BUFFERED", "decode method")
    check(d["access_name"] == "FILE_ANY_ACCESS", "decode access")
    check(d["function"] == 0x800, "decode function")
    check(ioctl_decoder.get_define(0x222000)
          == "#define stub_0x00222000 CTL_CODE(0x22, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)",
          "get_define")

    # ---- risk scoring ----
    sev_neither, _ = scoring.score_ioctl(ioctl_decoder.decode(0x222003))  # METHOD_NEITHER + ANY
    sev_buffered, _ = scoring.score_ioctl(ioctl_decoder.decode(0x222000))  # BUFFERED + ANY
    check(sev_neither == config.SEV_HIGH, "NEITHER+ANY scores HIGH")
    check(sev_buffered < config.SEV_HIGH, "BUFFERED+ANY below HIGH")

    # sink bump promotes NEITHER handler to CRITICAL
    rep = reporting.Reporter()
    rep.add_finding("device_name", r"\DosDevices\Stub")
    for code in (0x222000, 0x222003):
        rep.add_finding("ioctl", "IOCTL 0x%08X" % code, ea=0x14000000 + code,
                        func="DispatchDeviceControl", **ioctl_decoder.decode(code))
    rep.add_finding("callchain", "handler -> memcpy", func="DispatchDeviceControl",
                    severity=config.SEV_HIGH, detail="sink: memcpy", sink="memcpy")
    scoring.score(rep)
    crit = next((f for f in rep.by_category("ioctl") if f.data["code"] == 0x222003), None)
    check(crit is not None, "critical ioctl finding exists")
    if crit is not None:
        check(crit.severity == config.SEV_CRITICAL, "NEITHER + sink => CRITICAL")
        check(crit.data.get("sinks") == ["memcpy"], "sink name stored in finding data")
        check("memcpy" in crit.detail, "sink name visible in detail")

    # ---- T8: Reporter drops byte-identical duplicate findings ----
    rep_dedup = reporting.Reporter()
    for _ in range(2):
        rep_dedup.add_finding("acl", "IoCreateDevice: world-accessible by default",
                              ea=0x1234, severity=config.SEV_LOW, detail="d")
    check(len(rep_dedup.by_category("acl")) == 1,
          "T8: Reporter drops byte-identical duplicate finding")
    rep_dedup.add_finding("acl", "IoCreateDevice: world-accessible by default",
                          ea=0x5678, severity=config.SEV_LOW, detail="d")
    check(len(rep_dedup.by_category("acl")) == 2,
          "T8: finding at a distinct ea is still recorded")

    # ---- JSON / HTML / PoC ----
    out = tempfile.mkdtemp()
    json_path, html_path, poc_path = (os.path.join(out, n) for n in ("f.json", "r.html", "poc.c"))
    rep.to_json(json_path)
    rep.to_html(html_path)
    poc.generate(rep, poc_path)
    with open(json_path) as fh:
        j = json.load(fh)
    check(bool(j["findings"]) and "severity_counts" in j, "json has findings")
    with open(html_path) as fh:
        h = fh.read()
    check("stub.sys" in h, "html renders driver")
    with open(poc_path) as fh:
        c = fh.read()
    check('CreateFileW(L"\\\\\\\\.\\\\Stub"' in c, "poc has CreateFileW")
    check("DeviceIoControl(h," in c, "poc has DeviceIoControl")
    check(c.index("0x00222003") < c.index("0x00222000"), "poc CRITICAL first")

    # ---- T1: check_for_fake_driver_entry backward walk uses idc.prev_head ----
    # Set up a fake function: start=0x10000, end=0x10010.
    # Walking backwards finds "jmp real_entry" at 0x1000c after one step from 0x10010.
    idc_stub = sys.modules["idc"]
    idaapi_stub = sys.modules["idaapi"]
    idafuncs_stub = sys.modules["ida_funcs"]

    class _FakeEntryFunc:
        start_ea = 0x10000
        end_ea = 0x10010

    _mnems_t1 = {0x10010: "nop", 0x1000c: "jmp"}
    _saved_get_func = idaapi_stub.__dict__.get("get_func")
    idaapi_stub.get_func = lambda ea: _FakeEntryFunc()
    idc_stub.print_insn_mnem = lambda ea: _mnems_t1.get(ea, "nop")
    idc_stub.prev_head = lambda ea, start: (0x1000c if ea == 0x10010 else _BADADDR)
    idc_stub.print_operand = lambda ea, n: ("real_entry" if (ea == 0x1000c and n == 0) else "")
    idc_stub.get_name_ea_simple = lambda name: (0x20000 if name == "real_entry" else _BADADDR)
    idc_stub.set_name = lambda ea, name: None

    from DriverBuddyReloaded.wdm import check_for_fake_driver_entry
    rep_t1 = reporting.Reporter()
    result_t1 = check_for_fake_driver_entry(0x10000, rep_t1)
    check(result_t1 == 0x20000, "T1: fake DriverEntry walk returns real DriverEntry via prev_head")
    if _saved_get_func is not None:
        idaapi_stub.get_func = _saved_get_func

    # ---- T2: _is_valid_ctl_code boundary tests ----
    # Access the private function through the module to verify boundary behaviour.
    from DriverBuddyReloaded.ioctl_decoder import _is_valid_ctl_code
    check(_is_valid_ctl_code(0x00010000),  "T2: 0x00010000 valid (device_type=1, func=0)")
    check(not _is_valid_ctl_code(0x00000000), "T2: 0x00000000 invalid (device_type=0)")
    check(not _is_valid_ctl_code(0xC0000005), "T2: 0xC0000005 invalid (STATUS_ACCESS_VIOLATION)")
    check(_is_valid_ctl_code(0x00222003),  "T2: 0x00222003 valid (HEVD METHOD_NEITHER)")
    check(_is_valid_ctl_code(0x0022e004),  "T2: 0x0022e004 valid (vendor device type)")
    check(not _is_valid_ctl_code(0xFFFFFFFF), "T2: 0xFFFFFFFF invalid (== -1 sentinel)")
    check(_is_valid_ctl_code(0x9C402604),  "T2: 0x9C402604 valid (ALSysIO vendor IOCTL)")

    # ---- T3: check_irql emits finding when IRQL-raiser and Zw* call coexist ----
    # FuncItems returns [0x30000, 0x30004].
    # CodeRefsFrom(0x30000) -> [0x40000] (KeRaiseIrql callee).
    # CodeRefsFrom(0x30004) -> [0x50000] (ZwOpenProcess callee -- not used by _callees).
    # print_operand(0x30004, 0) -> "ZwOpenProcess" (triggers IRQL mismatch finding).
    # heuristics._callees() resolves callees by name from each call instruction
    # (import-aware), so the mock models two call sites: 0x30000 -> KeRaiseIrql
    # (raises the IRQL context) and 0x30004 -> ZwOpenProcess (the ungated op).
    idautils_stub = sys.modules["idautils"]
    _func_items_map = {0x30000: [0x30000, 0x30004]}
    _print_operand_map = {(0x30000, 0): "KeRaiseIrql", (0x30004, 0): "ZwOpenProcess"}
    _mnems_t3 = {0x30000: "call", 0x30004: "call"}

    idautils_stub.FuncItems = lambda ea: iter(_func_items_map.get(ea, []))
    idautils_stub.CodeRefsFrom = lambda ea, flow: iter([])
    idc_stub.print_insn_mnem = lambda ea: _mnems_t3.get(ea, "nop")
    idc_stub.print_operand = lambda ea, n: _print_operand_map.get((ea, n), "")

    from DriverBuddyReloaded.heuristics import check_irql
    rep_t3 = reporting.Reporter()
    check_irql(rep_t3, {0x30000})
    irql_findings = rep_t3.by_category("heuristic")
    check(any("ZwOpenProcess" in f.title for f in irql_findings),
          "T3: check_irql emits IRQL mismatch finding for ZwOpenProcess in IRQL-raised context")

    # ---- T4: scan_dispatchers dedup by code value keeps count at 1 ----
    # Pre-seed Reporter with IOCTL 0x222003 at one EA.
    # Mock FlowChart to yield a single block whose single instruction has
    # operand value 0x222003, so scan_dispatchers tries to add the same code.
    # Expect count stays at 1.
    rep_t4 = reporting.Reporter()
    d_t4 = ioctl_decoder.decode(0x222003)
    rep_t4.add_finding("ioctl", "IOCTL 0x00222003", ea=0xdeadbeef,
                       func="DispatchDeviceControl", **d_t4)

    class _FakeBlock_T4:
        start_ea = 0x1000
        end_ea = 0x1001
        def succs(self): return []

    class _FakeFC_T4:
        def __iter__(self): return iter([_FakeBlock_T4()])

    idaapi_stub.get_func = lambda ea: object()
    idaapi_stub.FlowChart = lambda f, flags=0: _FakeFC_T4()
    idc_stub.print_insn_mnem = lambda ea: "cmp"
    _O_IMM = 5
    idc_stub.o_imm = _O_IMM
    idc_stub.get_operand_type = lambda ea, n: _O_IMM
    idc_stub.get_operand_value = lambda ea, n: 0x222003

    ioctl_decoder.scan_dispatchers(rep_t4, [0x1000])
    t4_count = len(rep_t4.by_category("ioctl"))
    check(t4_count == 1, "T4: scan_dispatchers dedup by code value keeps count at 1")

    print("\n{} check(s), {} failure(s)".format(total[0], len(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
