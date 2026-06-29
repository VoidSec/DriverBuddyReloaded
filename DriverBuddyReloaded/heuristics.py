"""
heuristics.py: vulnerability heuristic checks ported and adapted from DriverBuddyRevolutions.

Each check emits Finding(category="heuristic") entries.  The checks are best-effort signal
generators -- they produce starting points for manual review, not definitive vulnerability
reports.  All checks are gated on config.Feature.HEURISTICS.

Architecture note: handler discovery delegates to callchain.handler_seed_eas() so the exact
same set of dispatch functions found during call-chain tracing is reused here.
"""

from __future__ import annotations

import re
from typing import Set, TYPE_CHECKING

if TYPE_CHECKING:
    from DriverBuddyReloaded.reporting import Reporter
    from DriverBuddyReloaded.utils import AnalysisContext

import idaapi
import ida_funcs
import idautils
import idc

try:
    import ida_xref
except ImportError:  # pragma: no cover
    ida_xref = None

from DriverBuddyReloaded import config, ida_compat
from DriverBuddyReloaded.callchain import handler_seed_eas, transitive_callees
from DriverBuddyReloaded.reporting import Finding

# Instruction window for the copy-sink validation search (instructions before/after).
_VALID_LOOKBACK = 20
_VALID_LOOKAHEAD = 6

def _is_lib_or_thunk(ea: int) -> bool:
    """True for FLIRT library functions and thunks (memmove, memset, CRT helpers):
    they are not driver logic and only add noise to the handler scan set.
    Constants are read lazily so importing this module needs no live IDA."""
    return bool(idc.get_func_flags(ea) & (ida_funcs.FUNC_LIB | ida_funcs.FUNC_THUNK))


def _callee_name(ea: int) -> str:
    """Resolved name of the function called/jumped-to at `ea`.

    Imported functions are referenced as `call cs:__imp_<Name>`, for which both
    `print_operand` (returns "cs:__imp_<Name>") and `CodeRefsFrom`+`get_func_name`
    (returns None / "__imp_<Name>") fail to yield the clean API name.  Strip the
    segment prefix and the __imp_ decoration so a single name (e.g.
    "ExAllocatePoolWithTag", "ProbeForRead", "MmMapIoSpace") is matched against
    the config sets regardless of whether the callee is local or imported.
    """
    op = idc.print_operand(ea, 0) or ""
    name = op.split(":")[-1].strip()
    if name.startswith("__imp_"):
        name = name[len("__imp_"):]
    if name and not name.startswith(("0x", "[")):
        return name
    for ref in idautils.CodeRefsFrom(ea, 0):
        n = ida_funcs.get_func_name(ref)
        if n:
            return n[len("__imp_"):] if n.startswith("__imp_") else n
    return name


def _callees(func_ea: int) -> Set[str]:
    """Set of callee names reachable in one call/jmp step from func_ea
    (import-aware; see _callee_name)."""
    names = set()
    for head in idautils.FuncItems(func_ea):
        if idc.print_insn_mnem(head) in ("call", "jmp"):
            n = _callee_name(head)
            if n:
                names.add(n)
    return names


def _instructions_window(ea: int, lookback: int, lookahead: int):
    """Yield instruction EAs in a symmetric window around `ea`."""
    cur = ea
    back = []
    for _ in range(lookback):
        prev = idc.prev_head(cur, idc.get_segm_start(cur))
        if prev == idc.BADADDR or prev == cur:
            break
        back.append(prev)
        cur = prev
    yield from reversed(back)
    yield ea
    cur = ea
    for _ in range(lookahead):
        nxt = idc.next_head(cur, idc.get_segm_end(cur))
        if nxt == idc.BADADDR or nxt == cur:
            break
        yield nxt
        cur = nxt


def check_user_copy_validation(rep: Reporter, handler_eas: Set[int]) -> None:
    """
    Flag copy-sink calls in handler functions that lack a nearby validation call.

    Severity is HIGH when the copy is inside a known handler (direct user-mode exposure),
    MEDIUM otherwise.
    """
    for func_ea in idautils.Functions():
        func_name = ida_funcs.get_func_name(func_ea) or ""
        is_handler = func_ea in handler_eas
        for head in idautils.FuncItems(func_ea):
            callee = _callee_name(head)
            if callee not in config.COPY_SINKS:
                continue
            # Search the surrounding window for any validation call.
            validated = False
            for win_ea in _instructions_window(head, _VALID_LOOKBACK, _VALID_LOOKAHEAD):
                if _callee_name(win_ea) in config.VALIDATION_FUNCS:
                    validated = True
                    break
            if validated:
                continue
            sev = config.SEV_HIGH if is_handler else config.SEV_MEDIUM
            rep.add(Finding(
                category="heuristic",
                title="Unvalidated copy: {}".format(callee),
                ea=head,
                func=func_name,
                severity=sev,
                detail="No validation call found in {}-back/{}-forward window".format(
                    _VALID_LOOKBACK, _VALID_LOOKAHEAD)))


def check_privilege_gate(rep: Reporter, seed_eas: Set[int]) -> None:
    """
    Flag PRIVILEGED_SENSITIVE_OPS that are reachable from a dispatcher with no
    privilege check (SeAccessCheck / SeSinglePrivilegeCheck / token query / ...)
    anywhere on the path.

    Path-level rather than single-function: a privileged primitive is frequently
    wrapped (WinRing0x64 `MmMapIoSpace_wrapper`, ALSysIO64 `sub_12F20`), so a
    per-function check on the dispatcher alone never saw it (false negative),
    while a per-function check on the wrapper alone would wrongly report a sink
    that a dispatcher-level gate actually protects (false positive).  For each
    dispatcher subtree we therefore: gather the transitively-reachable functions,
    skip the whole subtree when a gate appears anywhere on it, and otherwise flag
    every reachable sensitive-op call site once.
    """
    reported = set()
    for seed in seed_eas:
        reachable = [ea for ea in transitive_callees({seed}, config.HANDLER_SEED_DEPTH)
                     if not _is_lib_or_thunk(ea)]
        # A gate anywhere on the dispatcher's call tree protects everything below it.
        if any(_callees(f) & config.PRIVILEGE_GATE_FUNCS for f in reachable):
            continue
        seed_name = ida_funcs.get_func_name(seed) or "0x{:x}".format(seed)
        for func_ea in reachable:
            func_name = ida_funcs.get_func_name(func_ea) or ""
            for head in idautils.FuncItems(func_ea):
                target = _callee_name(head)
                if target in config.PRIVILEGED_SENSITIVE_OPS and head not in reported:
                    reported.add(head)
                    rep.add(Finding(
                        category="heuristic",
                        title="Ungated privileged op: {}".format(target),
                        ea=head,
                        func=func_name,
                        severity=config.SEV_HIGH,
                        detail="Reachable from dispatcher {} with no privilege check "
                               "on the path".format(seed_name)))


def check_irql(rep: Reporter, handler_eas: Set[int]) -> None:
    """
    Flag Zw* / pageable calls made in a function that also raises or queries IRQL.

    Narrowed from the clone's blanket scan: only emit when IRQL context is confirmed
    by the presence of an IRQL_RAISING_FUNCS call, reducing false positives.
    """
    for func_ea in handler_eas:
        func_name = ida_funcs.get_func_name(func_ea) or ""
        callees = _callees(func_ea)
        if not (callees & config.IRQL_RAISING_FUNCS):
            continue
        for head in idautils.FuncItems(func_ea):
            if idc.print_insn_mnem(head) not in ("call", "jmp"):
                continue
            target = _callee_name(head)
            if target.startswith("Zw") or target.startswith("MmMap"):
                disasm = ida_compat.disasm_text(head)
                rep.add(Finding(
                    category="heuristic",
                    title="Potential IRQL mismatch: {}".format(target),
                    ea=head,
                    func=func_name,
                    severity=config.SEV_MEDIUM,
                    detail=disasm))


def check_mdl(rep: Reporter, handler_eas: Set[int]) -> None:
    """
    Flag MDL_USER_FUNCS calls; severity is HIGH when 'UserMode' appears nearby in
    disassembly, MEDIUM otherwise (potential MDL misuse with user pages).
    """
    for func_ea in handler_eas:
        func_name = ida_funcs.get_func_name(func_ea) or ""
        for head in idautils.FuncItems(func_ea):
            target = _callee_name(head)
            if target not in config.MDL_USER_FUNCS:
                continue
            disasm = ida_compat.disasm_text(head)
            usermode = "UserMode" in disasm
            sev = config.SEV_HIGH if usermode else config.SEV_MEDIUM
            rep.add(Finding(
                category="heuristic",
                title="MDL user-page op: {}".format(target),
                ea=head,
                func=func_name,
                severity=sev,
                detail=disasm))


def check_alloca(rep: Reporter, handler_eas: Set[int]) -> None:
    """Flag stack-allocation intrinsic calls in handlers (LOW; requires manual triage)."""
    for func_ea in handler_eas:
        func_name = ida_funcs.get_func_name(func_ea) or ""
        for head in idautils.FuncItems(func_ea):
            target = _callee_name(head)
            if target in config.ALLOCA_FUNCS:
                rep.add(Finding(
                    category="heuristic",
                    title="Stack alloc in handler: {}".format(target),
                    ea=head,
                    func=func_name,
                    severity=config.SEV_LOW,
                    detail="Manual triage: verify size is bounded"))


_CR_DR_RE = re.compile(r'\b[cd]r[0-9]+\b')


def check_privileged_instructions(rep: Reporter, handler_eas: Set[int]) -> None:
    """
    Flag privileged CPU instructions reachable from a dispatch handler: port I/O
    (in/out/ins/outs), control/debug-register moves, descriptor-table loads, and
    cache/halt instructions.  These are inline instructions, not function calls,
    so the sink/callchain layer cannot see them -- yet `out`/`in` to an
    attacker-controlled port and `mov cr*`/`mov dr*` are the canonical BYOVD
    hardware-access primitives (WinRing0x64 __outbyte, ALSysIO64 __indword).
    """
    for func_ea in handler_eas:
        func_name = ida_funcs.get_func_name(func_ea) or ""
        for head in idautils.FuncItems(func_ea):
            mnem = idc.print_insn_mnem(head).lower()
            sev = config.PRIV_INSN_SEVERITY.get(mnem)
            title = None
            if sev is not None:
                title = "Privileged instruction: {}".format(mnem)
            elif mnem == "mov":
                op0 = idc.print_operand(head, 0).lower()
                op1 = idc.print_operand(head, 1).lower()
                if _CR_DR_RE.search(op0) or _CR_DR_RE.search(op1):
                    sev = config.SEV_HIGH
                    title = "Control/debug register access"
            if title is not None:
                rep.add(Finding(
                    category="opcode",
                    title=title,
                    ea=head,
                    func=func_name,
                    severity=sev,
                    detail=ida_compat.disasm_text(head)))


def check_pool_alloc_trust(rep: Reporter, handler_eas: Set[int]) -> None:
    """
    Flag ExAllocatePool* calls in IOCTL handlers that lack nearby safe-arithmetic
    guards.  A pool allocation whose size argument is derived from user-controlled
    data without integer-safety checks is a classic integer-overflow-before-alloc bug.
    """
    for func_ea in handler_eas:
        func_name = ida_funcs.get_func_name(func_ea) or ""
        for head in idautils.FuncItems(func_ea):
            callee = _callee_name(head)
            if callee not in config.POOL_ALLOC_FUNCS:
                continue
            validated = False
            for win_ea in _instructions_window(head, _VALID_LOOKBACK, _VALID_LOOKAHEAD):
                if _callee_name(win_ea) in config.VALIDATION_FUNCS:
                    validated = True
                    break
            if validated:
                continue
            rep.add(Finding(
                category="heuristic",
                title="Allocation without size validation: {}".format(callee),
                ea=head,
                func=func_name,
                severity=config.SEV_HIGH,
                detail="No safe-arithmetic guard near pool alloc in IOCTL handler"))


def check_physical_mem_ref(rep: Reporter, handler_eas: Set[int]) -> None:
    """
    Scan the IDA string database for '\\Device\\PhysicalMemory' and flag every
    cross-reference to that string.  References from known IOCTL handlers are HIGH;
    others MEDIUM.  This string is a canonical indicator of BYOVD physical-memory
    access via ZwOpenSection -> ZwMapViewOfSection.
    """
    try:
        s_iter = idautils.Strings()
        s_iter.setup()
    except Exception:
        return
    for s in s_iter:
        try:
            sval = str(s)
        except Exception:
            continue
        if sval != "\\Device\\PhysicalMemory":
            continue
        for xr in idautils.XrefsTo(s.ea, 0):
            fn = ida_funcs.get_func(xr.frm)
            func_ea = fn.start_ea if fn else None
            func_name = ida_funcs.get_func_name(func_ea) or "" if func_ea is not None else ""
            is_handler = func_ea in handler_eas if func_ea is not None else False
            rep.add(Finding(
                category="heuristic",
                title="\\Device\\PhysicalMemory reference",
                ea=xr.frm,
                func=func_name,
                severity=config.SEV_HIGH if is_handler else config.SEV_MEDIUM,
                detail="Reference to physical memory device object - possible BYOVD pattern"))


_MEM_LOAD_RE = re.compile(r'\[(\w+)(?:\+(\w+))?\]')
# Frame/stack registers: a re-read through these is a local variable, never a
# user-mode pointer, so it cannot be a double-fetch source.
_STACK_REGS = frozenset({"rsp", "rbp", "esp", "ebp"})


def _user_pointer_tainted(rep: "Reporter") -> Set[int]:
    """Function EAs that may dereference a user-mode pointer.

    A double-fetch/TOCTOU is only exploitable when the racing re-read comes from
    user memory.  For METHOD_BUFFERED/IN/OUT_DIRECT the input is a kernel copy
    (Irp->AssociatedIrp.SystemBuffer) and re-reading it cannot be raced; only
    METHOD_NEITHER hands the driver a raw user pointer (Type3InputBuffer /
    UserBuffer).  So the set is every dispatcher that decodes at least one
    METHOD_NEITHER IOCTL, plus everything those dispatchers transitively call
    (the per-IOCTL handlers where the actual dereference usually lives).
    """
    neither = set()
    for f in rep.by_category("ioctl"):
        if f.data and f.data.get("method_code") == 3:  # METHOD_NEITHER
            fn = ida_funcs.get_func(f.ea)
            if fn:
                neither.add(fn.start_ea)
    if not neither:
        return set()
    return transitive_callees(neither)


def _cfg_reachable(handler_ea: int, ea_from: int, ea_to: int) -> bool:
    """True if ea_to lies on a control-flow path from ea_from (same block or a
    successor).  Used to reject two reads that sit in mutually-exclusive sibling
    switch cases -- those are the same field read in different branches, not a
    re-fetch on one execution path.  Permissive (returns True) if the CFG cannot
    be built so a genuine double-fetch is never silently dropped."""
    try:
        func = ida_funcs.get_func(handler_ea)
        if not func:
            return True
        fc = idaapi.FlowChart(func, flags=idaapi.FC_PREDS)
    except Exception:
        return True
    b_from = b_to = None
    for b in fc:
        if b.start_ea <= ea_from < b.end_ea:
            b_from = b
        if b.start_ea <= ea_to < b.end_ea:
            b_to = b
    if b_from is None or b_to is None or b_from.start_ea == b_to.start_ea:
        return True
    from collections import deque
    seen, queue = set(), deque([b_from])
    while queue:
        b = queue.popleft()
        if b.start_ea in seen:
            continue
        seen.add(b.start_ea)
        try:
            for s in b.succs():
                if s.start_ea == b_to.start_ea:
                    return True
                if s.start_ea not in seen:
                    queue.append(s)
        except Exception:
            return True
    return False


def check_double_fetch(rep: "Reporter", handler_ea: int) -> None:
    """
    TOCTOU / double-fetch heuristic (N1).

    Walks the instruction stream of the handler function.  Collects all
    memory-load `mov` instructions and groups them by (src_register, offset).
    For any pair with 2+ occurrences, emits MEDIUM when (a) no
    ProbeForRead/ProbeForWrite or copy-sink call appears between the two reads
    and (b) the second read is reachable from the first on a single control-flow
    path.  The caller restricts this to user-pointer-tainted handlers (see
    _user_pointer_tainted) so METHOD_BUFFERED kernel-buffer re-reads are not
    flagged.
    """
    func_insns = list(idautils.FuncItems(handler_ea))
    func_name = ida_funcs.get_func_name(handler_ea) or ""

    loads = {}
    for ea in func_insns:
        if idc.print_insn_mnem(ea) != "mov":
            continue
        op_type = idc.get_operand_type(ea, 1)
        if op_type not in (idc.o_mem, idc.o_displ, idc.o_phrase):
            continue
        src_text = idc.print_operand(ea, 1)
        m = _MEM_LOAD_RE.search(src_text)
        if not m:
            continue
        src_reg = m.group(1)
        if src_reg.lower() in _STACK_REGS:
            continue
        offset = m.group(2) or "0"
        loads.setdefault((src_reg, offset), []).append(ea)

    for (src_reg, offset), eas in loads.items():
        if len(eas) < 2:
            continue
        ea1, ea2 = sorted(eas[:2])
        # Two reads in mutually-exclusive sibling branches are not a re-fetch.
        if not _cfg_reachable(handler_ea, ea1, ea2):
            continue
        has_probe = False
        for ea in func_insns:
            if ea <= ea1 or ea >= ea2:
                continue
            mnem = idc.print_insn_mnem(ea)
            if mnem not in ("call",):
                continue
            callee = _callee_name(ea)
            if callee in config.PROBE_FUNCS or callee in config.COPY_SINKS:
                has_probe = True
                break
        if not has_probe:
            rep.add(Finding(
                category="heuristic",
                title="TOCTOU double-fetch: [{}+{}] read at 0x{:x} and 0x{:x} without intervening ProbeForRead".format(
                    src_reg, offset, ea1, ea2),
                ea=ea1,
                func=func_name,
                severity=config.SEV_MEDIUM,
                detail="0x{:x} -> 0x{:x}; user-pointer field re-read with no ProbeForRead/ProbeForWrite between".format(
                    ea1, ea2)))


_FREE_ARG_REG_X64 = {"rcx", "ecx"}
_FREE_ARG_REG_X86 = {"ecx"}
_MOV_WRITES = {"mov", "lea", "xor", "sub", "and", "or", "not", "neg",
               "movzx", "movsx", "movsxd", "add", "imul", "inc", "dec"}


def check_use_after_free(rep: "Reporter", ctx: "AnalysisContext", handler_ea: int) -> None:
    """
    N6: Use-after-free heuristic.

    Forward-walks each basic block in the function CFG.  When a call to a
    FREE_POOL_FUNCS function is seen, records the argument register (RCX on x64,
    ECX on x86).  If any subsequent instruction in the same or a successor block
    reads that register before it is overwritten by a write instruction, emits a
    HIGH finding.

    This is a single-pass, intra-function check; it will miss UAF across function
    boundaries but catches the simple case of pool-free followed by dereference in
    the same handler.
    """
    try:
        func = ida_funcs.get_func(handler_ea)
        if not func:
            return
        fc = idaapi.FlowChart(func, flags=idaapi.FC_PREDS)
    except Exception:
        return

    func_name = ida_funcs.get_func_name(handler_ea) or ""
    is_64 = False
    try:
        from DriverBuddyReloaded.ida_compat import is_64bit
        is_64 = is_64bit()
    except Exception:
        pass

    free_regs = _FREE_ARG_REG_X64 if is_64 else _FREE_ARG_REG_X86

    # BFS over basic blocks; carry freed register sets across block boundaries.
    from collections import deque
    freed_at_block = {}
    queue = deque()
    # Seed with the entry block carrying an empty freed set.
    queue.append((next(iter(fc), None), set()))
    visited = set()

    while queue:
        bb, freed = queue.popleft()
        if bb is None:
            continue
        key = bb.start_ea
        if key in visited:
            continue
        visited.add(key)
        freed_at_block[key] = set(freed)

        current_freed = set(freed)
        ea = bb.start_ea
        while ea < bb.end_ea:
            mnem = idc.print_insn_mnem(ea).lower()
            op0_text = idc.print_operand(ea, 0).lower()
            op1_text = idc.print_operand(ea, 1).lower()

            if mnem == "call":
                callee = idc.print_operand(ea, 0)
                if callee in config.FREE_POOL_FUNCS:
                    # The first argument register is now freed.
                    current_freed.update(free_regs)
            elif current_freed:
                if mnem in _MOV_WRITES:
                    # Destination write kills the freed state for that register.
                    for reg in list(current_freed):
                        if op0_text.startswith(reg):
                            current_freed.discard(reg)
                else:
                    # Check if a freed register appears as a source operand (use).
                    for reg in current_freed:
                        if reg in op1_text or reg in op0_text:
                            rep.add(Finding(
                                category="heuristic",
                                title="Potential use-after-free: {} read after free".format(reg),
                                ea=ea,
                                func=func_name,
                                severity=config.SEV_HIGH,
                                detail="Register {} used at 0x{:x} after ExFreePool* call; "
                                       "verify pointer is nulled before reuse".format(
                                           reg, ea)))
                            current_freed.discard(reg)

            nxt = idc.next_head(ea, bb.end_ea)
            if nxt == idc.BADADDR or nxt == ea:
                break
            ea = nxt

        # Propagate freed set to successor blocks.
        try:
            for succ in bb.succs():
                if succ.start_ea not in visited:
                    queue.append((succ, set(current_freed)))
        except Exception:
            pass


_COPY_FUNC_NAMES = frozenset({
    "memmove", "memcpy", "memset", "wmemcpy", "memcpy_s", "memmove_s", "qmemcpy",
})


def _node_ea(node, default: int) -> int:
    """Best-effort source address of a ctree node, falling back to *default*."""
    try:
        ea = node.ea
        if ea is not None and ea != idc.BADADDR:
            return ea
    except Exception:
        pass
    return default


def check_write_primitives(rep: "Reporter", handler_eas: Set[int]) -> None:
    """
    Arbitrary-write (write-what-where) detection via the decompiler ctree.

    The copy-validation check only sees memcpy-family *calls*; the most direct
    write primitives are plain pointer stores the compiler never turns into a
    call.  Two high-signal shapes are flagged HIGH:

      - `*p = *q`  : a value read through one pointer stored through another
                     (HEVD TriggerArbitraryWrite `*Where = *What`; ALSysIO64
                     sub_13780 writes a user dword to mapped physical memory).
      - `*(*p) = c`: a store through a double-dereferenced (pointer-to-pointer)
                     destination (HEVD TriggerWriteNULL `*(*UserBuffer) = 0`).

    Both require a pointer *value* (not `&local`) on the destination, so ordinary
    `out_struct->field = x` stores (cot_memptr LHS) are not flagged.  Gated on
    config.Feature.IOCTL_DECOMPILER + HexRays; best-effort, fully guarded.
    """
    if not config.Feature.IOCTL_DECOMPILER:
        return
    try:
        import ida_hexrays
    except Exception:
        return
    try:
        init = getattr(ida_hexrays, "init_hexrays_plugin", None)
        if init is not None and not init():
            return
    except Exception:
        return

    cot_asg = getattr(ida_hexrays, "cot_asg", None)
    cot_ptr = getattr(ida_hexrays, "cot_ptr", None)
    cot_cast = getattr(ida_hexrays, "cot_cast", None)
    CV_FAST = getattr(ida_hexrays, "CV_FAST", 8)
    if cot_asg is None or cot_ptr is None:
        return

    def _unwrap(n):
        while cot_cast is not None and n is not None and n.op == cot_cast:
            n = n.x
        return n

    for func_ea in handler_eas:
        try:
            cfunc = ida_hexrays.decompile(func_ea)
        except Exception:
            cfunc = None
        if cfunc is None:
            continue
        fname = ida_funcs.get_func_name(func_ea) or ""
        # A bare element copy (`*p = *q`) is the body of every memcpy/memmove-style
        # routine; skip those so the check does not flag the copy primitive itself.
        if fname in config.COPY_SINKS or fname.lower() in _COPY_FUNC_NAMES:
            continue
        hits = {}

        class _W(ida_hexrays.ctree_visitor_t):
            def __init__(self):
                ida_hexrays.ctree_visitor_t.__init__(self, CV_FAST)

            def visit_expr(self, e):
                try:
                    if e.op == cot_asg and e.x is not None and e.x.op == cot_ptr:
                        dst = _unwrap(e.x.x)
                        rhs = _unwrap(e.y)
                        # Double-deref store `*(*p) = c` is the canonical, rarely
                        # benign write-what-where; single-deref `*p = *q` is a
                        # weaker controlled-copy lead (also appears in struct copies).
                        type_b = dst is not None and dst.op == cot_ptr
                        type_a = rhs is not None and rhs.op == cot_ptr
                        if type_b:
                            hits[_node_ea(e, func_ea)] = "b"
                        elif type_a:
                            hits.setdefault(_node_ea(e, func_ea), "a")
                except Exception:
                    pass
                return 0

        try:
            _W().apply_to(cfunc.body, None)
        except Exception:
            pass

        for ea, shape in hits.items():
            if shape == "b":
                rep.add(Finding(
                    category="heuristic",
                    title="Arbitrary write (write-what-where)",
                    ea=ea, func=fname, severity=config.SEV_HIGH,
                    detail="Store through a double-dereferenced (user-controlled) "
                           "pointer `*(*p) = c`; verify the destination is validated"))
            else:
                rep.add(Finding(
                    category="heuristic",
                    title="Controlled pointer write",
                    ea=ea, func=fname, severity=config.SEV_MEDIUM,
                    detail="Value read through one pointer stored through another "
                           "`*p = *q`; review whether the destination is attacker-controlled"))


def _backwalk_global_into_reg(call_ea: int, reg: str, func_start: int):
    """If the value in `reg` at `call_ea` was loaded straight from a global, return
    that global's data EA; otherwise None.  Stops at the first writer of `reg`, so a
    register-only / locally-computed argument is correctly rejected."""
    cur = call_ea
    for _ in range(16):
        prev = idc.prev_head(cur, func_start)
        if prev == idc.BADADDR or prev == cur:
            break
        cur = prev
        if idc.print_insn_mnem(cur) in ("mov", "lea") and \
                idc.print_operand(cur, 0).lower().startswith(reg):
            if idc.get_operand_type(cur, 1) == idc.o_mem:
                g = idc.get_operand_value(cur, 1)
                if g not in (idc.BADADDR, None) and g >= 0x1000:
                    return g
            return None  # reg overwritten by a non-global source
    return None


def _global_nulled_after(g_ea: int, free_ea: int, func_ea: int) -> bool:
    """True if the freeing function writes 0 to the global after the free."""
    for head in idautils.FuncItems(func_ea):
        if head <= free_ea:
            continue
        if idc.print_insn_mnem(head) == "mov" \
                and idc.get_operand_type(head, 0) == idc.o_mem \
                and idc.get_operand_value(head, 0) == g_ea \
                and idc.get_operand_type(head, 1) == idc.o_imm \
                and idc.get_operand_value(head, 1) == 0:
            return True
    return False


def _global_read_sites(g_ea: int, exclude_func: int):
    """Read references to the global from functions other than the freeing one."""
    dr_w = getattr(ida_xref, "dr_W", 2) if ida_xref else 2
    sites = []
    for xr in idautils.XrefsTo(g_ea, 0):
        if getattr(xr, "type", None) == dr_w:
            continue  # a write (e.g. the allocator storing the pointer) is not a use
        fn = ida_funcs.get_func(xr.frm)
        if not fn or fn.start_ea == exclude_func:
            continue
        sites.append(xr.frm)
    return sites


def check_use_after_free_global(rep: "Reporter", handler_eas: Set[int]) -> None:
    """
    N6b: cross-function use-after-free via a global pointer.

    The register-tracking check (check_use_after_free) is intra-function and
    cannot model the canonical driver UAF where one IOCTL frees a global object
    pointer without nulling it and a *different* IOCTL later dereferences the
    dangling global (e.g. HEVD g_UseAfterFreeObjectNonPagedPool).  This pass finds
    ExFreePool* calls whose argument is loaded directly from a global, confirms the
    global is not zeroed in the freeing function, and confirms it is read elsewhere
    -- emitting HIGH when all three hold.
    """
    try:
        from DriverBuddyReloaded.ida_compat import is_64bit
        reg = "rcx" if is_64bit() else "ecx"
    except Exception:
        reg = "rcx"

    seen_globals = {}
    for func_ea in handler_eas:
        func = ida_funcs.get_func(func_ea)
        start = func.start_ea if func else func_ea
        for head in idautils.FuncItems(func_ea):
            if idc.print_insn_mnem(head) != "call":
                continue
            if _callee_name(head) not in config.FREE_POOL_FUNCS:
                continue
            g_ea = _backwalk_global_into_reg(head, reg, start)
            if g_ea is not None:
                seen_globals.setdefault(g_ea, (head, func_ea))

    for g_ea, (free_ea, free_func) in seen_globals.items():
        if _global_nulled_after(g_ea, free_ea, free_func):
            continue
        uses = _global_read_sites(g_ea, free_func)
        if not uses:
            continue
        gname = idc.get_name(g_ea) or "0x{:x}".format(g_ea)
        rep.add(Finding(
            category="heuristic",
            title="Use-after-free: global {} freed but not cleared".format(gname),
            ea=free_ea,
            func=ida_funcs.get_func_name(free_func) or "",
            severity=config.SEV_HIGH,
            detail="{} freed at 0x{:x} without being nulled; dereferenced elsewhere at {}".format(
                gname, free_ea, ", ".join("0x{:x}".format(u) for u in uses[:3]))))


def run(rep: Reporter, ctx: AnalysisContext) -> None:
    """
    Run all heuristic checks.  Seeds handlers from callchain.handler_seed_eas()
    so handler discovery is never duplicated.
    :param rep: Reporter instance
    :param ctx: AnalysisContext (provides functions_map for seed discovery)
    """
    seed_eas = handler_seed_eas(rep, ctx)
    if not seed_eas:
        rep.info("[!] Heuristics: no handler EAs found; skipping checks")
        return
    # Expand from the dispatcher(s) to the functions they transitively call, so the
    # deep checks see the per-IOCTL handler bodies (HEVD's Trigger*/IoctlHandler
    # callees), not just the dispatcher prologue.  This is what lets double-fetch,
    # pool-trust, privilege-gate, IRQL, MDL and alloca fire on the real handler code.
    handler_eas = {
        ea for ea in transitive_callees(seed_eas, config.HANDLER_SEED_DEPTH)
        if not _is_lib_or_thunk(ea)  # skip memmove/memset/CRT leaves
    }
    rep.info("[>] Running heuristic checks on {} handler(s) ({} dispatcher seed(s))...".format(
        len(handler_eas), len(seed_eas)))
    check_user_copy_validation(rep, handler_eas)
    check_privilege_gate(rep, seed_eas)
    check_irql(rep, handler_eas)
    check_mdl(rep, handler_eas)
    check_alloca(rep, handler_eas)
    check_privileged_instructions(rep, handler_eas)
    check_write_primitives(rep, handler_eas)
    check_pool_alloc_trust(rep, handler_eas)
    check_physical_mem_ref(rep, handler_eas)
    if config.Feature.TOCTOU_CHECK:
        # Only scan handlers that can see a user-mode pointer (METHOD_NEITHER);
        # re-reading a METHOD_BUFFERED kernel copy is not a race.
        tainted = _user_pointer_tainted(rep)
        for ea in handler_eas:
            if ea in tainted:
                check_double_fetch(rep, ea)
    if config.Feature.UAF_DETECT:
        for ea in handler_eas:
            check_use_after_free(rep, ctx, ea)
        check_use_after_free_global(rep, handler_eas)
    n = len(rep.by_category("heuristic"))
    rep.info("[>] Heuristics: {} finding(s) emitted".format(n))
