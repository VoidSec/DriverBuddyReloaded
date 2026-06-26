"""
analysis.py: core Driver Buddy Reloaded analysis pipeline.

Extracted from DriverBuddyReloaded.py so the pipeline can be invoked headless
(e.g. from tests/ida_smoke.py) without instantiating the plugin_t or UI hooks.

The caller creates and owns the Reporter; this module runs everything between
idc.auto_wait() and rep.close().
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Dict, Any

if TYPE_CHECKING:
    from DriverBuddyReloaded.reporting import Reporter

import idaapi

from DriverBuddyReloaded import (
    callchain,
    config,
    device_name_finder,
    dump_pool_tags,
    exports_audit,
    find_opcodes,
    heuristics,
    ioctl_decoder,
    irp_mj,
    poc,
    scoring,
    utils,
)
from DriverBuddyReloaded.utils import AnalysisContext


def _stage(rep: "Reporter", name: str, fn, *args, **kwargs) -> None:
    """Run an analysis stage, catching and logging any exception so the pipeline continues."""
    try:
        fn(*args, **kwargs)
    except Exception as exc:
        rep.info("[!] Stage '{}' failed: {}".format(name, exc))


def _write_pool_file(rep: Reporter, pool: str) -> None:
    """Write the pool-tag text report next to the IDB."""
    path = config.out_path("pooltags.txt")
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(pool)
        rep.info('[>] Saved Pooltags file to "{}"'.format(path))
    except OSError as e:
        rep.info('[!] Can\'t write pool file to "{}": {}'.format(path, e))


def run_analysis(rep: Reporter) -> Dict[str, Any]:
    """
    Execute the full Driver Buddy Reloaded analysis against the currently loaded IDB.

    The caller is responsible for creating *rep* before this call and closing it
    (rep.close() + optional rep.show_window()) afterwards.  This function does NOT
    call idc.auto_wait() -- the plugin's run() does that before delegating here.

    Returns a summary dict for the cross-version smoke harness:
      {
        "driver_type": str,
        "per_category": {category: count, ...},
        "severity_counts": {"HIGH": n, ...},
      }
    or {"error": reason} on early exit (not a PE / not a driver).
    """
    # Fresh per-run state; isolates this invocation from any previous run.
    ctx = AnalysisContext()

    file_type = idaapi.get_file_type_name()
    if "portable executable" not in file_type.lower():
        rep.info("[!] ERR: Loaded file is not a valid PE")
        return {"error": "not_pe"}

    driver_entry_addr = utils.is_driver()
    if not driver_entry_addr:
        rep.info("[!] ERR: Loaded file is not a Driver")
        return {"error": "not_driver"}

    rep.info("[+] `DriverEntry` found at: 0x{:08x}".format(driver_entry_addr))

    rep.info("[>] Searching for `DeviceNames`...")
    device_name_finder.search(rep)

    rep.info("[>] Searching for `Pooltags`...")
    pool = dump_pool_tags.collect(rep)
    if pool:
        _write_pool_file(rep, pool)

    driver_type = "unknown"
    if not utils.populate_data_structures(rep, ctx):
        rep.info("[!] ERR: Unable to enumerate functions; skipping analysis stages")
        return _finalize(rep, driver_type)

    driver_type = utils.get_driver_id(driver_entry_addr, rep, ctx)
    if driver_type != "WDM":
        rep.info("[+] Driver type detected: {}".format(driver_type))
    if config.Feature.IRP_MJ_ENUM and driver_type == "WDM":
        _stage(rep, "irp_mj", irp_mj.run, ctx.real_entry_addr or driver_entry_addr, rep)
    found_by_pattern = False
    found_by_dispatcher = False
    if config.Feature.IOCTL_SCAN:
        found_by_pattern = ioctl_decoder.find_ioctls(rep)
        if ctx.ddc_addresses:
            found_by_dispatcher = ioctl_decoder.scan_dispatchers(rep, ctx.ddc_addresses)
        if not found_by_pattern and not found_by_dispatcher:
            rep.info("[!] Unable to automatically find any IOCTLs")

    if config.Feature.ACL_AUDIT:
        _stage(rep, "acl_audit", utils.find_device_create_calls, rep, ctx)
    if config.Feature.CALLCHAIN:
        _stage(rep, "callchain", callchain.trace, rep, ctx)
    if config.Feature.HEURISTICS:
        _stage(rep, "heuristics", heuristics.run, rep, ctx)
    if config.Feature.EXPORTS_AUDIT:
        _stage(rep, "exports_audit", exports_audit.audit, rep)
    if config.Feature.SEGMENT_OPCODE_SCAN:
        _stage(rep, "opcode_scan", find_opcodes.linear_scan, rep)
    if config.Feature.RISK_SCORING:
        _stage(rep, "scoring", scoring.score, rep)
    if config.Feature.JSON_EXPORT:
        rep.to_json(config.out_path("findings.json"))
    if config.Feature.HTML_REPORT:
        rep.to_html(config.out_path("report.html"))
    if config.Feature.POC_HARNESS:
        poc.generate(rep, config.out_path("ioctl_pocs.c"))

    rep.info("[+] Analysis Completed!")
    rep.info("-----------------------------------------------")

    return _finalize(rep, driver_type)


def _finalize(rep: "Reporter", driver_type: str) -> Dict[str, Any]:
    """Build and return the summary dict for the smoke harness."""
    per_cat = {}
    for f in rep.findings:
        per_cat[f.category] = per_cat.get(f.category, 0) + 1

    return {
        "driver_type": driver_type,
        "per_category": per_cat,
        "severity_counts": {
            config.severity_name(k): v
            for k, v in rep.counts_by_severity().items()
        },
    }
