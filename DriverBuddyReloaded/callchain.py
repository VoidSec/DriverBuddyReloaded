"""
callchain.py: name-based call-chain tracing from dispatch / IOCTL handlers to
dangerous sinks (config.DANGEROUS_SINKS).

This is a heuristic lead generator built on IDA's cross-reference database, not a
real dataflow analysis, so findings are starting points rather than ground truth.
Results feed risk scoring (a handler that reaches a sink is bumped) and the PoC
prioritisation.
"""

from __future__ import annotations

from typing import Set, TYPE_CHECKING

if TYPE_CHECKING:
    from DriverBuddyReloaded.reporting import Reporter
    from DriverBuddyReloaded.utils import AnalysisContext

import ida_funcs
import idautils

from DriverBuddyReloaded import config
from DriverBuddyReloaded.reporting import Finding

BADADDR = 0xFFFFFFFFFFFFFFFF


def _name(ea):
    return ida_funcs.get_func_name(ea) or ("0x%08x" % ea)


def _out_refs(func_ea):
    """All call/jump targets referenced from within the function at `func_ea`."""
    out = set()
    for head in idautils.FuncItems(func_ea):
        for ref in idautils.CodeRefsFrom(head, 0):  # 0 == do not include ordinary flow
            out.add(ref)
    return out


def transitive_callees(start_eas, max_depth: int = config.CALLCHAIN_MAX_DEPTH) -> Set[int]:
    """Function start EAs reachable from *start_eas* over call/jump edges, inclusive.

    Bounded BFS over CodeRefsFrom (the same edge set the sink tracer walks).
    Shared by heuristics (handler-seed expansion, user-pointer taint) so the
    notion of "the code a dispatcher actually reaches" is computed one way.
    """
    result = set()
    frontier = [ea for ea in start_eas]
    depth = 0
    while frontier and depth <= max_depth:
        nxt = []
        for fea in frontier:
            if fea in result:
                continue
            result.add(fea)
            for ref in _out_refs(fea):
                callee = ida_funcs.get_func(ref)
                if callee and callee.start_ea not in result:
                    nxt.append(callee.start_ea)
        frontier = nxt
        depth += 1
    return result


def _seed_eas(rep: Reporter, ctx: AnalysisContext) -> Set[int]:
    """Function start EAs to trace from: every IOCTL handler plus any recovered
    dispatch routine (DispatchDeviceControl / Possible_DispatchDeviceControl*)."""
    seeds = set()
    for f in rep.by_category("ioctl"):
        fn = ida_funcs.get_func(f.ea)
        if fn:
            seeds.add(fn.start_ea)
        # The per-IOCTL handler (resolved by the decoder) is also a seed, so the
        # tracer reports sinks reachable from each handler -- not just the
        # dispatcher -- and risk scoring can attribute them per IOCTL.
        handler_ea = f.data.get("handler_ea") if f.data else None
        if handler_ea:
            hfn = ida_funcs.get_func(handler_ea)
            if hfn:
                seeds.add(hfn.start_ea)
    for name, ea in ctx.functions_map.items():
        if name in ("DispatchDeviceControl", "DispatchInternalDeviceControl") \
                or name.startswith("Possible_DispatchDeviceControl"):
            fn = ida_funcs.get_func(ea)
            if fn:
                seeds.add(fn.start_ea)
    return seeds


# Public alias used by heuristics.py so dispatch-handler discovery is not duplicated.
handler_seed_eas = _seed_eas


def trace(rep: Reporter, ctx: AnalysisContext) -> None:
    """
    BFS outward from each seed handler over call edges up to CALLCHAIN_MAX_DEPTH,
    emitting a Finding(category="callchain") for each dangerous sink reached.
    :param rep: Reporter instance
    :param ctx: AnalysisContext holding functions_map (from utils.populate_data_structures)
    """

    sinks_by_ea = {}
    for name, sev in config.DANGEROUS_SINKS.items():
        ea = ctx.functions_map.get(name)
        if ea is not None:
            sinks_by_ea[ea] = (name, sev)
    if not sinks_by_ea:
        return

    seeds = _seed_eas(rep, ctx)
    if not seeds:
        return

    seeds = list(seeds)
    rep.info("[>] Tracing call chains from {} handler(s) to dangerous sinks...".format(len(seeds)))
    reported = set()
    for i, start in enumerate(seeds):
        if i > 0 and i % 10 == 0:
            rep.info("  [callchain] {}/{} handlers traced".format(i, len(seeds)))
        seed_name = _name(start)
        frontier = [(start, [seed_name])]
        visited = {start}
        depth = 0
        while frontier and depth < config.CALLCHAIN_MAX_DEPTH:
            nxt = []
            for fea, path in frontier:
                for ref in _out_refs(fea):
                    if ref in sinks_by_ea:
                        sink_name, sev = sinks_by_ea[ref]
                        key = (start, ref)
                        if key not in reported:
                            reported.add(key)
                            full = path + [sink_name]
                            rep.add(Finding(
                                category="callchain",
                                title="{} reaches {}".format(seed_name, sink_name),
                                ea=start,
                                func=seed_name,
                                severity=sev,
                                detail=" -> ".join(full),
                                data={"sink": sink_name, "path": full}))
                    callee = ida_funcs.get_func(ref)
                    if callee and callee.start_ea not in visited:
                        visited.add(callee.start_ea)
                        nxt.append((callee.start_ea, path + [_name(callee.start_ea)]))
            frontier = nxt
            depth += 1
