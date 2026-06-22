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

    for f in ioctls:
        sev, reasons = score_ioctl(f.data)
        entry = sink_by_func.get(f.func)
        if entry:
            sink_sev, sink_names = entry
            if sink_sev:
                sinks_sorted = sorted(sink_names)
                reasons.extend("-> {}".format(s) for s in sinks_sorted)
                f.data["sinks"] = sinks_sorted
                if sinks_sorted:
                    f.detail = f.detail + " | sinks: " + ", ".join(sinks_sorted)
                sev = max(sev, sink_sev)
                # A raw-pointer IOCTL that also reaches a sink is the worst case.
                if f.data.get("method_name") == "METHOD_NEITHER":
                    sev = config.SEV_CRITICAL
        f.severity = config.clamp_severity(sev)
        f.data["risk_reasons"] = reasons

    high = sum(1 for f in ioctls if f.severity >= config.SEV_HIGH)
    rep.info("[>] Risk scoring: {} IOCTL(s) scored, {} High/Critical".format(len(ioctls), high))
