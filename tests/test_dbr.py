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

import os
import sys
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _install_ida_stubs():
    """Register permissive stand-ins for the IDA Python modules in sys.modules."""

    class _Any:
        def __init__(self, *a, **k):
            pass

        def __call__(self, *a, **k):
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

        def __init__(self, *a, **k):
            pass

        def Show(self, *a, **k):
            return 0

    class _Plugin:
        pass

    class _ActionHandler:
        def __init__(self, *a, **k):
            pass

    class _UIHooks:
        def __init__(self, *a, **k):
            pass

        def hook(self):
            pass

    class _BinPat(list):
        def size(self):
            return len(self)

    sdk = int(os.environ.get("DBR_SDK", "840"))
    mod("idaapi", IDA_SDK_VERSION=sdk, BADADDR=0xFFFFFFFFFFFFFFFF,
        PLUGIN_UNL=0, PLUGIN_KEEP=1, PLUGIN_OK=0, AST_ENABLE_ALWAYS=1,
        BWN_DISASM=0x29, FC_PREDS=0x10, plugin_t=_Plugin,
        action_handler_t=_ActionHandler, UI_Hooks=_UIHooks,
        compiled_binpat_vec_t=_BinPat, get_qword=lambda ea: 0, get_dword=lambda ea: 0)
    mod("idc", BADADDR=0xFFFFFFFFFFFFFFFF, FF_DATA=0x400, FUNC_LIB=0x4,
        get_root_filename=lambda: "stub.sys")
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
    mod("ida_idaapi", BADADDR=0xFFFFFFFFFFFFFFFF)
    mod("ida_kernwin", Choose=_Choose, jumpto=lambda ea: True)
    mod("ida_lines", generate_disasm_line=lambda ea, f=0: "", tag_remove=lambda s: s or "")
    mod("ida_loader", PATH_TYPE_IDB=0, get_path=lambda t: "")
    mod("ida_typeinf", PT_SIL=1, HTI_DCL=1, NTF_TYPE=1, TINFO_DEFINITE=1,
        get_idati=lambda: object())


def main():
    _install_ida_stubs()
    sys.path.insert(0, ROOT)

    from DriverBuddyReloaded import config, ioctl_decoder, scoring, poc, reporting
    from DriverBuddyReloaded import device_name_finder

    failures = []

    def check(label, cond):
        print(("  PASS " if cond else "  FAIL ") + label)
        if not cond:
            failures.append(label)

    # ---- device_name_finder: REPEATS bytes fix ----
    # A null-filled buffer must short-circuit without TypeError (buf[0:1] vs buf[0]).
    check("repeat null buf exits cleanly",
          list(device_name_finder.extract_unicode_strings(b"\x00" * 200)) == [])
    # An 'A'-filled buffer also exits cleanly via the repeat shortcut.
    check("repeat A buf exits cleanly",
          list(device_name_finder.extract_unicode_strings(b"A" * 200)) == [])
    # A real UTF-16LE device name is found correctly.
    _dev_utf16 = "\\Device\\Test".encode("utf-16-le")
    _found = list(device_name_finder.extract_unicode_strings(_dev_utf16))
    check("utf16 device name found", any("Test" in s.s for s in _found))

    # ---- IOCTL decode ----
    d = ioctl_decoder.decode(0x222000)
    check("decode device", d["device_name"] == "FILE_DEVICE_UNKNOWN")
    check("decode method", d["method_name"] == "METHOD_BUFFERED")
    check("decode access", d["access_name"] == "FILE_ANY_ACCESS")
    check("decode function", d["function"] == 0x800)
    check("get_define", ioctl_decoder.get_define(0x222000)
          == "#define stub_0x00222000 CTL_CODE(0x22, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)")

    # ---- risk scoring ----
    sev_neither, _ = scoring.score_ioctl(ioctl_decoder.decode(0x222003))  # METHOD_NEITHER + ANY
    sev_buffered, _ = scoring.score_ioctl(ioctl_decoder.decode(0x222000))  # BUFFERED + ANY
    check("NEITHER+ANY scores HIGH", sev_neither == config.SEV_HIGH)
    check("BUFFERED+ANY below HIGH", sev_buffered < config.SEV_HIGH)

    # sink bump promotes NEITHER handler to CRITICAL
    rep = reporting.Reporter()
    rep.add_finding("device_name", r"\DosDevices\Stub")
    for code in (0x222000, 0x222003):
        rep.add_finding("ioctl", "IOCTL 0x%08X" % code, ea=0x14000000 + code,
                        func="DispatchDeviceControl", **ioctl_decoder.decode(code))
    rep.add_finding("callchain", "handler -> memcpy", func="DispatchDeviceControl",
                    severity=config.SEV_HIGH, detail="sink: memcpy")
    scoring.score(rep)
    crit = [f for f in rep.by_category("ioctl") if f.data["code"] == 0x222003][0]
    check("NEITHER + sink => CRITICAL", crit.severity == config.SEV_CRITICAL)

    # ---- JSON / HTML / PoC ----
    import tempfile
    out = tempfile.mkdtemp()
    jp, hp, cp = (os.path.join(out, n) for n in ("f.json", "r.html", "poc.c"))
    rep.to_json(jp)
    rep.to_html(hp)
    poc.generate(rep, cp)
    import json
    j = json.load(open(jp))
    check("json has findings", bool(j["findings"]) and "severity_counts" in j)
    check("html renders driver", "stub.sys" in open(hp).read())
    poc_src = open(cp).read()
    check("poc has CreateFileW", 'CreateFileW(L"\\\\\\\\.\\\\Stub"' in poc_src)
    check("poc has DeviceIoControl", "DeviceIoControl(h," in poc_src)
    check("poc CRITICAL first", poc_src.index("0x00222003") < poc_src.index("0x00222000"))

    print("\n{} check(s), {} failure(s)".format(
        3 + 7 + 3 + 6, len(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
