"""
analysis.py: core Driver Buddy Reloaded analysis pipeline.

Extracted from DriverBuddyReloaded.py so the pipeline can be invoked headless
(e.g. from tests/ida_smoke.py) without instantiating the plugin_t or UI hooks.

The caller creates and owns the Reporter; this module runs everything between
idc.auto_wait() and rep.close().
"""

import idaapi

from DriverBuddyReloaded import (
    callchain,
    config,
    device_name_finder,
    dump_pool_tags,
    ioctl_decoder,
    poc,
    scoring,
    utils,
)


def _write_pool_file(rep, pool):
    """Write the pool-tag text report next to the IDB."""
    path = config.out_path("pooltags.txt")
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(pool)
        rep.info('[>] Saved Pooltags file to "{}"'.format(path))
    except IOError as e:
        rep.info('[!] Can\'t write pool file to "{}": {}'.format(path, e))


def run_analysis(rep):
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
    file_type = idaapi.get_file_type_name()
    if "portable executable" not in file_type.lower():
        rep.info("[!] ERR: Loaded file is not a valid PE")
        return {"error": "not_pe"}

    driver_entry_addr = utils.is_driver()
    if driver_entry_addr is False:
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
    if utils.populate_data_structures(rep) is True:
        driver_type = utils.get_driver_id(driver_entry_addr, rep)
        rep.info("[+] Driver type detected: {}".format(driver_type))
        if ioctl_decoder.find_ioctls(rep) is False:
            rep.info("[!] Unable to automatically find any IOCTLs")
    else:
        rep.info("[!] ERR: Unable to enumerate functions")

    if config.Feature.CALLCHAIN:
        callchain.trace(rep, utils.functions_map)
    if config.Feature.RISK_SCORING:
        scoring.score(rep)
    if config.Feature.JSON_EXPORT:
        rep.to_json(config.out_path("findings.json"))
    if config.Feature.HTML_REPORT:
        rep.to_html(config.out_path("report.html"))
    if config.Feature.POC_HARNESS:
        poc.generate(rep, config.out_path("ioctl_pocs.c"))

    rep.info("[+] Analysis Completed!")
    rep.info("-----------------------------------------------")

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
