"""
callchain.py: name-based call-chain tracing from dispatch / IOCTL handlers to
dangerous sinks (config.DANGEROUS_SINKS).

This is a heuristic lead generator built on IDA's cross-reference database, not a
real dataflow analysis, so findings are starting points rather than ground truth.
Results feed risk scoring (a handler that reaches a sink is bumped) and the PoC
prioritisation.
"""

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


def _seed_eas(rep, functions_map):
    """Function start EAs to trace from: every IOCTL handler plus any recovered
    dispatch routine."""
    seeds = set()
    for f in rep.by_category("ioctl"):
        fn = ida_funcs.get_func(f.ea)
        if fn:
            seeds.add(fn.start_ea)
    for name, ea in functions_map.items():
        if name in ("DispatchDeviceControl", "DispatchInternalDeviceControl") \
                or name.startswith("Possible_DispatchDeviceControl"):
            fn = ida_funcs.get_func(ea)
            if fn:
                seeds.add(fn.start_ea)
    return seeds


def trace(rep, functions_map):
    """
    BFS outward from each seed handler over call edges up to CALLCHAIN_MAX_DEPTH,
    emitting a Finding(category="callchain") for each dangerous sink reached.
    :param rep: Reporter instance
    :param functions_map: dict name -> address (subs and imports), from utils
    """

    sinks_by_ea = {}
    for name, sev in config.DANGEROUS_SINKS.items():
        ea = functions_map.get(name)
        if ea is not None:
            sinks_by_ea[ea] = (name, sev)
    if not sinks_by_ea:
        return

    seeds = _seed_eas(rep, functions_map)
    if not seeds:
        return

    rep.info("[>] Tracing call chains from {} handler(s) to dangerous sinks...".format(len(seeds)))
    reported = set()
    for start in seeds:
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
