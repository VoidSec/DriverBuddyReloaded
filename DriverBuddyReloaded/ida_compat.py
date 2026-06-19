"""
ida_compat.py: IDA-Python compatibility layer for Driver Buddy Reloaded.

This module is the single choke point for every IDA-Python API that differs across
IDA 7.x, 8.x and 9.0+. No other module in the plugin should:
    * import ida_struct / ida_enum (removed in IDA 9.0)
    * call idaapi.get_inf_structure() (removed in IDA 9.0)
    * call idc.import_type / idc.SetType (removed in IDA 9.0)
    * branch on the IDA version

Instead, callers use the stable helpers defined here. The struct/type helpers are
version-branched internally: for IDA < 9.0 they use the proven legacy `idc` struct
wrappers (zero behavioural change for existing users); for IDA >= 9.0 they use the
`ida_typeinf` type system, since the legacy wrappers no longer exist.

Targets IDA 7.6 - 9.0+ on Python 3.
"""

import ida_bytes
import ida_lines
import ida_typeinf
import idaapi
import idc

try:
    import ida_ida
except ImportError:  # pragma: no cover - only on very old builds
    ida_ida = None

SDK_VERSION = idaapi.IDA_SDK_VERSION
IS_IDA9 = SDK_VERSION >= 900
BADADDR = idaapi.BADADDR

# Resolve a couple of flag constants whose names shifted between binding generations.
_PARSE_DECL_FLAGS = getattr(ida_typeinf, "PT_SIL", getattr(ida_typeinf, "PT_SILENT", 0))
_HTI_DCL = getattr(ida_typeinf, "HTI_DCL", 0)


# --------------------------------------------------------------------------- #
# Inf / architecture
# --------------------------------------------------------------------------- #
def is_64bit():
    """True if the database is 64-bit. Uses ida_ida.inf_is_64bit() (IDA 7.6+),
    falling back to the removed-in-9.0 get_inf_structure() only on ancient builds."""
    if ida_ida is not None and hasattr(ida_ida, "inf_is_64bit"):
        return ida_ida.inf_is_64bit()
    return idaapi.get_inf_structure().is_64bit()  # pragma: no cover


def ptr_size():
    """Pointer width in bytes for the current database."""
    return 8 if is_64bit() else 4


def get_ptr(ea):
    """Read a pointer-sized value at `ea`."""
    return ida_bytes.get_qword(ea) if is_64bit() else ida_bytes.get_dword(ea)


def min_ea():
    if ida_ida is not None and hasattr(ida_ida, "inf_get_min_ea"):
        return ida_ida.inf_get_min_ea()
    return idaapi.get_inf_structure().min_ea  # pragma: no cover


def max_ea():
    if ida_ida is not None and hasattr(ida_ida, "inf_get_max_ea"):
        return ida_ida.inf_get_max_ea()
    return idaapi.get_inf_structure().max_ea  # pragma: no cover


# --------------------------------------------------------------------------- #
# Binary / text search
# --------------------------------------------------------------------------- #
def bin_search(pattern, start=None, end=None, nocase=True, radix=16):
    """Cross-version binary-pattern search.

    `pattern` is a binpat string such as 'L"mdfLibrary"' or '0F 32'. Uses
    parse_binpat_str + ida_bytes.bin_search (available on 7.x+), normalising the
    scalar-ea vs (ea, idx)-tuple return shapes seen across builds.
    Returns an effective address, or BADADDR if not found.
    """
    start = min_ea() if start is None else start
    end = max_ea() if end is None else end
    binpat = idaapi.compiled_binpat_vec_t()
    ida_bytes.parse_binpat_str(binpat, start, pattern, radix)
    try:
        if binpat.size() == 0:
            return BADADDR
    except (AttributeError, TypeError):  # pragma: no cover
        pass
    flags = ida_bytes.BIN_SEARCH_NOCASE if nocase else getattr(ida_bytes, "BIN_SEARCH_CASE", 0)
    flags |= getattr(ida_bytes, "BIN_SEARCH_FORWARD", 0)
    res = ida_bytes.bin_search(start, end, binpat, flags)
    if isinstance(res, tuple):
        return res[0] if res and res[0] is not None else BADADDR
    return res if res is not None else BADADDR


def disasm_text(ea):
    """Plain-text (tag-stripped) disassembly line at `ea`."""
    line = ida_lines.generate_disasm_line(ea, 0)
    return ida_lines.tag_remove(line) if line else ""


def iter_text_matches(needle, start=None, end=None):
    """Yield head EAs whose disassembly text contains `needle`.

    Replacement for the deprecated idc.ida_search.find_text scan used by the
    "dumb" IOCTL finder; works identically across 7.x/8.x/9.0.
    """
    start = min_ea() if start is None else start
    end = max_ea() if end is None else end
    ea = start
    while ea != BADADDR and ea < end:
        if needle in disasm_text(ea):
            yield ea
        nxt = idc.next_head(ea, end)
        if nxt <= ea:
            break
        ea = nxt


# --------------------------------------------------------------------------- #
# Struct / type model (version-branched)
# --------------------------------------------------------------------------- #
def get_type_tid(name):
    """Return the tid of a named type already present in the local type library,
    or None. (IDA 9.0 type-system path.)"""
    til = ida_typeinf.get_idati()
    tif = ida_typeinf.tinfo_t()
    if tif.get_named_type(til, name):
        tid = tif.get_tid()
        if tid != BADADDR:
            return tid
    return None


def _create_named_struct_legacy(name, member_names, member_size):
    ff_ptr = ida_bytes.FF_QWORD if is_64bit() else ida_bytes.FF_DWORD
    sid = idc.get_struc_id(name)
    if sid != BADADDR:
        idc.del_struc(sid)
    idc.add_struc(-1, name, 0)
    sid = idc.get_struc_id(name)
    if sid == BADADDR:
        return None
    for nm in member_names:
        idc.add_struc_member(sid, nm, BADADDR, idc.FF_DATA | ff_ptr, -1, member_size)
    return sid


def _create_named_struct_typeinf(name, member_names):
    # Build a C declaration of pointer-sized members. Using `void *` makes each
    # member follow the database pointer width automatically and avoids the
    # udm_t offset bytes-vs-bits ambiguity entirely.
    body = "".join("  void *%s;\n" % nm for nm in member_names)
    decl = "struct %s {\n%s};" % (name, body)
    til = ida_typeinf.get_idati()
    # Replace any previous definition so re-runs are idempotent.
    try:
        existing = ida_typeinf.tinfo_t()
        if existing.get_named_type(til, name):
            ida_typeinf.del_named_type(til, name, ida_typeinf.NTF_TYPE)
    except Exception:  # pragma: no cover - defensive
        pass
    errors = ida_typeinf.parse_decls(til, decl, None, _HTI_DCL)
    if errors:
        return None
    return get_type_tid(name)


def create_named_struct(name, member_names, member_size=None):
    """Create (replacing any existing definition) a struct whose members are
    pointer-sized fields named by `member_names`.
    Returns a tid usable by op_struct_offset()/struct_size(), or None on failure.
    """
    if member_size is None:
        member_size = ptr_size()
    if IS_IDA9:
        return _create_named_struct_typeinf(name, member_names)
    return _create_named_struct_legacy(name, member_names, member_size)


def struct_size(tid):
    """Size in bytes of the struct identified by `tid`, or BADADDR."""
    if tid in (None, BADADDR):
        return BADADDR
    if IS_IDA9:
        tif = ida_typeinf.tinfo_t()
        if tif.get_type_by_tid(tid) and tif.is_udt():
            return tif.get_size()
        return BADADDR
    return idc.get_struc_size(tid)


def apply_struct_ptr(ea, name):
    """Apply a pointer-to-struct type (`<name> *`) to the data item at `ea`.
    Replacement for idc.SetType(ea, "<name> *")."""
    if IS_IDA9:
        til = ida_typeinf.get_idati()
        tif = ida_typeinf.tinfo_t()
        if ida_typeinf.parse_decl(tif, til, "%s *;" % name, _PARSE_DECL_FLAGS) is None:
            return False
        return bool(ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE))
    return bool(idc.set_type(ea, "%s *" % name))


def import_std_type(name):
    """Ensure a standard library type (IRP, IO_STACK_LOCATION, DEVICE_OBJECT, ...)
    is available and return its tid, or None. Replacement for idc.import_type(-1, name).
    """
    if not IS_IDA9:
        tid = idc.import_type(-1, name)
        if tid in (None, BADADDR, -1):
            return None
        return tid
    tid = get_type_tid(name)
    if tid is not None:
        return tid
    til = ida_typeinf.get_idati()
    try:
        r = ida_typeinf.import_type(til, -1, name)
        if r not in (None, -1, BADADDR):
            return get_type_tid(name)
    except (TypeError, AttributeError):  # pragma: no cover - signature drift
        pass
    return None


def op_struct_offset(ea, n, tid, delta=0):
    """Mark operand `n` at `ea` as an offset into the struct identified by `tid`.
    No-op (returns False) for an invalid tid so callers never crash."""
    if tid in (None, BADADDR):
        return False
    try:
        return bool(idc.op_stroff(ea, n, tid, delta))
    except Exception:  # pragma: no cover - defensive
        return False
