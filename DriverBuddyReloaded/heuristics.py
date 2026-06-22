"""
heuristics.py: vulnerability heuristic checks ported and adapted from DriverBuddyRevolutions.

Each check emits Finding(category="heuristic") entries.  The checks are best-effort signal
generators -- they produce starting points for manual review, not definitive vulnerability
reports.  All checks are gated on config.Feature.HEURISTICS.

Architecture note: handler discovery delegates to callchain.handler_seed_eas() so the exact
same set of dispatch functions found during call-chain tracing is reused here.
"""

from __future__ import annotations

from typing import Set, TYPE_CHECKING

if TYPE_CHECKING:
    from DriverBuddyReloaded.reporting import Reporter
    from DriverBuddyReloaded.utils import AnalysisContext

import ida_funcs
import idautils
import idc

from DriverBuddyReloaded import config, ida_compat
from DriverBuddyReloaded.callchain import handler_seed_eas
from DriverBuddyReloaded.reporting import Finding

# Instruction window for the copy-sink validation search (instructions before/after).
_VALID_LOOKBACK = 20
_VALID_LOOKAHEAD = 6


def _callees(func_ea: int) -> Set[str]:
    """Set of callee names reachable in one call step from func_ea."""
    names = set()
    for head in idautils.FuncItems(func_ea):
        for ref in idautils.CodeRefsFrom(head, 0):
            n = ida_funcs.get_func_name(ref)
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
            callee = idc.print_operand(head, 0)
            if callee not in config.COPY_SINKS:
                continue
            # Search the surrounding window for any validation call.
            validated = False
            for win_ea in _instructions_window(head, _VALID_LOOKBACK, _VALID_LOOKAHEAD):
                if idc.print_operand(win_ea, 0) in config.VALIDATION_FUNCS:
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


def check_privilege_gate(rep: Reporter, handler_eas: Set[int]) -> None:
    """
    Flag handlers that invoke a PRIVILEGED_SENSITIVE_OPS member without any
    PRIVILEGE_GATE_FUNCS call in the same function.

    Computing the callee set once per function avoids the O(n^2) pattern in the clone.
    """
    for func_ea in handler_eas:
        func_name = ida_funcs.get_func_name(func_ea) or ""
        callees = _callees(func_ea)
        sensitive = callees & config.PRIVILEGED_SENSITIVE_OPS
        if not sensitive:
            continue
        gated = bool(callees & config.PRIVILEGE_GATE_FUNCS)
        if gated:
            continue
        for head in idautils.FuncItems(func_ea):
            target = idc.print_operand(head, 0)
            if target in sensitive:
                rep.add(Finding(
                    category="heuristic",
                    title="Ungated privileged op: {}".format(target),
                    ea=head,
                    func=func_name,
                    severity=config.SEV_HIGH,
                    detail="No privilege gate ({}) found in handler".format(
                        ", ".join(sorted(config.PRIVILEGE_GATE_FUNCS)[:3]))))


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
            target = idc.print_operand(head, 0)
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
            target = idc.print_operand(head, 0)
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
            target = idc.print_operand(head, 0)
            if target in config.ALLOCA_FUNCS:
                rep.add(Finding(
                    category="heuristic",
                    title="Stack alloc in handler: {}".format(target),
                    ea=head,
                    func=func_name,
                    severity=config.SEV_LOW,
                    detail="Manual triage: verify size is bounded"))


def check_pool_alloc_trust(rep: Reporter, handler_eas: Set[int]) -> None:
    """
    Flag ExAllocatePool* calls in IOCTL handlers that lack nearby safe-arithmetic
    guards.  A pool allocation whose size argument is derived from user-controlled
    data without integer-safety checks is a classic integer-overflow-before-alloc bug.
    """
    for func_ea in handler_eas:
        func_name = ida_funcs.get_func_name(func_ea) or ""
        for head in idautils.FuncItems(func_ea):
            callee = idc.print_operand(head, 0)
            if callee not in config.POOL_ALLOC_FUNCS:
                continue
            validated = False
            for win_ea in _instructions_window(head, _VALID_LOOKBACK, _VALID_LOOKAHEAD):
                if idc.print_operand(win_ea, 0) in config.VALIDATION_FUNCS:
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


def run(rep: Reporter, ctx: AnalysisContext) -> None:
    """
    Run all heuristic checks.  Seeds handlers from callchain.handler_seed_eas()
    so handler discovery is never duplicated.
    :param rep: Reporter instance
    :param ctx: AnalysisContext (provides functions_map for seed discovery)
    """
    handler_eas = handler_seed_eas(rep, ctx)
    if not handler_eas:
        rep.info("[!] Heuristics: no handler EAs found; skipping checks")
        return
    rep.info("[>] Running heuristic checks on {} handler(s)...".format(len(handler_eas)))
    check_user_copy_validation(rep, handler_eas)
    check_privilege_gate(rep, handler_eas)
    check_irql(rep, handler_eas)
    check_mdl(rep, handler_eas)
    check_alloca(rep, handler_eas)
    check_pool_alloc_trust(rep, handler_eas)
    check_physical_mem_ref(rep, handler_eas)
    n = len(rep.by_category("heuristic"))
    rep.info("[>] Heuristics: {} finding(s) emitted".format(n))
