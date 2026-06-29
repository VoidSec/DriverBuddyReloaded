"""
scoring.py: heuristic risk scoring for decoded IOCTLs.

Severity is derived from the IOCTL transfer method and access mode (the fields
that map to real high-severity driver bug classes) and bumped when the handling
function is known to reach a dangerous sink (see config.DANGEROUS_SINKS and the
call-chain tracer).
"""

from __future__ import annotations

from typing import Dict, List, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from DriverBuddyReloaded.reporting import Reporter

from DriverBuddyReloaded import config

try:
    import ida_funcs
    from DriverBuddyReloaded.callchain import transitive_callees
except Exception:  # pragma: no cover - only when imported outside IDA without stubs
    ida_funcs = None
    transitive_callees = None


def _points_to_severity(points):
    if points >= 5:
        return config.SEV_HIGH
    if points >= 3:
        return config.SEV_MEDIUM
    if points >= 1:
        return config.SEV_LOW
    return config.SEV_INFO


def score_ioctl(decoded: Dict[str, object]) -> Tuple[int, List[str]]:
    """
    Compute (severity, reasons) for a decoded IOCTL dict (see ioctl_decoder.decode).
    METHOD_NEITHER + FILE_ANY_ACCESS is the canonical arbitrary-r/w shape and scores
    highest; CRITICAL is reserved for handlers that additionally reach a sink.
    """
    reasons = []
    points = 0
    method = decoded.get("method_name")
    access = decoded.get("access_name")
    m = config.METHOD_RISK.get(method, 0)
    if m:
        points += m
        reasons.append("{} (+{})".format(method, m))
    a = config.ACCESS_RISK.get(access, 0)
    if a:
        points += a
        reasons.append("{} (+{})".format(access, a))
    return _points_to_severity(points), reasons


def score(rep: Reporter) -> None:
    """
    Assign severities to every IOCTL finding in `rep`, in place, and record the
    contributing reasons under data["risk_reasons"]. Uses any call-chain findings
    to bump handlers that reach a dangerous sink.
    :param rep: Reporter instance
    """

    ioctls = rep.by_category("ioctl")
    if not ioctls:
        return

    # Highest sink severity reached per function, gathered from call-chain findings.
    sink_by_func = {}
    for f in rep.by_category("callchain"):
        if f.func:
            prev_sev, prev_names = sink_by_func.get(f.func, (0, set()))
            sink_name = f.data.get("sink", "") if f.data else ""
            sink_by_func[f.func] = (
                max(prev_sev, f.severity),
                prev_names | ({sink_name} if sink_name else set()),
            )

    # Privileged inline primitives (wrmsr/rdmsr, port I/O, mov cr*) are opcode
    # findings, not callable sinks, so the call-chain tracer never sees them.
    # Map the function that contains each to its severity so an IOCTL whose
    # handler transitively reaches it (e.g. ALSysIO64's writemsr_wrapper) is
    # scored on that primitive rather than dropping to LOW.
    opcode_sev_by_func = {}
    if ida_funcs is not None:
        for f in rep.by_category("opcode"):
            if not f.ea:
                continue
            fn = ida_funcs.get_func(f.ea)
            if fn:
                opcode_sev_by_func[fn.start_ea] = max(
                    opcode_sev_by_func.get(fn.start_ea, 0), f.severity)
    _opcode_reach_cache = {}

    def _opcode_reach_sev(handler_ea):
        if not opcode_sev_by_func or transitive_callees is None:
            return 0
        if handler_ea in _opcode_reach_cache:
            return _opcode_reach_cache[handler_ea]
        reach = transitive_callees({handler_ea})
        best = max((sev for fea, sev in opcode_sev_by_func.items() if fea in reach),
                   default=0)
        _opcode_reach_cache[handler_ea] = best
        return best

    for f in ioctls:
        sev, reasons = score_ioctl(f.data)
        # Attribute sinks to the IOCTL's own handler when the decoder resolved it,
        # so a handler that reaches no sink is not tarred with sinks that only
        # other cases of the same dispatcher reach.  Fall back to the dispatcher
        # function otherwise, and mark that attribution as imprecise.
        handler = f.data.get("handler_name")
        attrib = handler or f.func
        precise = handler is not None
        entry = sink_by_func.get(attrib)
        if entry:
            sink_sev, sink_names = entry
            if sink_sev:
                sinks_sorted = sorted(sink_names)
                reasons.extend("-> {}".format(s) for s in sinks_sorted)
                f.data["sinks"] = sinks_sorted
                f.detail = f.detail + " | sinks{}: ".format(
                    "" if precise else " (dispatcher-wide)") + ", ".join(sinks_sorted)
                sev = max(sev, sink_sev)
                # A raw-pointer IOCTL that also reaches a sink is the worst case.
                if f.data.get("method_name") == "METHOD_NEITHER":
                    sev = config.SEV_CRITICAL
        # Bump for a privileged inline primitive reachable from this handler
        # (MSR access, port I/O, control-register move).
        handler_ea = f.data.get("handler_ea")
        if handler_ea:
            opc_sev = _opcode_reach_sev(handler_ea)
            if opc_sev:
                sev = max(sev, opc_sev)
                reasons.append("-> privileged opcode/instruction")
        f.data["sink_attribution"] = "handler" if precise else "dispatcher-wide"
        f.severity = config.clamp_severity(sev)
        f.data["risk_reasons"] = reasons

    high = sum(1 for f in ioctls if f.severity >= config.SEV_HIGH)
    rep.info("[>] Risk scoring: {} IOCTL(s) scored, {} High/Critical".format(len(ioctls), high))
