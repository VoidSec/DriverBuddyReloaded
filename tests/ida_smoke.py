"""
ida_smoke.py - Headless smoke test for Driver Buddy Reloaded.

Run inside IDA in autonomous batch mode:

    idat64.exe -A -Lida.log "-Stests\\ida_smoke.py result.json" driver.sys

The script runs the full analysis pipeline against the loaded binary and writes a
JSON summary to the path given as idc.ARGV[1].  Exit code 0 = success, 1 = error.

Extended modes (T5-T7):

    # T5: golden comparison -- compare findings against a reference JSON
    idat64.exe -A -Lida.log "-Stests\\ida_smoke.py result.json --golden ref.json" driver.sys

    # T6/T7: IOCTL count assertion (optionally also check for a heuristic pattern)
    idat64.exe -A -Lida.log "-Stests\\ida_smoke.py result.json --ioctl-count 17" driver.sys
    idat64.exe -A -Lida.log "-Stests\\ida_smoke.py result.json --ioctl-count 28 --expect-heuristic TOCTOU" driver.sys

See tests/run_cross_version.ps1 for the cross-version matrix runner.
"""

import json
import os
import sys
import time
import traceback

# Add the repo root to sys.path so the package is importable regardless of
# IDA's working directory.  IDA auto-loads any *installed* DriverBuddyReloaded
# plugin at startup, caching its modules in sys.modules; drop those and put the
# repo first so the smoke test exercises this working tree, not a stale install.
_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_TESTS_DIR)
for _m in [m for m in list(sys.modules)
           if m == "DriverBuddyReloaded" or m.startswith("DriverBuddyReloaded.")]:
    del sys.modules[_m]
if sys.path[:1] != [_REPO_ROOT]:
    sys.path.insert(0, _REPO_ROOT)

import idc          # noqa: E402 (must follow sys.path setup)
import idaapi       # noqa: E402

from DriverBuddyReloaded import analysis, reporting  # noqa: E402


def _parse_argv(argv):
    """
    Parse idc.ARGV into (result_path, opts).
    opts keys: golden_path, ioctl_count, expect_heuristic
    """
    opts = {}
    result_path = os.path.join(_TESTS_DIR, "smoke_result.json")
    i = 1
    # First positional arg (if not a flag) is the result path.
    if len(argv) > 1 and not argv[1].startswith("--"):
        result_path = argv[1]
        i = 2
    while i < len(argv):
        arg = argv[i]
        if arg == "--golden" and i + 1 < len(argv):
            opts["golden_path"] = argv[i + 1]
            i += 2
        elif arg == "--ioctl-count" and i + 1 < len(argv):
            try:
                opts["ioctl_count"] = int(argv[i + 1])
            except ValueError:
                pass
            i += 2
        elif arg == "--expect-heuristic" and i + 1 < len(argv):
            opts["expect_heuristic"] = argv[i + 1]
            i += 2
        else:
            i += 1
    return result_path, opts


def _golden_check(rep, golden_path):
    """
    T5: compare findings against a reference JSON file.

    Fields compared order-insensitively per finding: category, title, severity.
    For IOCTL findings: also code, method_name, access_name from data.
    Returns a dict with 'passed' bool and 'detail' string.
    """
    try:
        with open(golden_path, encoding="utf-8") as fh:
            ref = json.load(fh)
    except Exception as exc:
        return {"passed": False, "detail": "Cannot read golden file: {}".format(exc)}

    ref_findings = ref.get("findings", [])

    def _key(f_dict):
        d = f_dict.get("data") or {}
        return (
            f_dict.get("category", ""),
            f_dict.get("title", ""),
            f_dict.get("severity", ""),
            d.get("code", ""),
            d.get("method_name", ""),
            d.get("access_name", ""),
        )

    from DriverBuddyReloaded.config import SEVERITY_NAMES
    actual_dicts = [
        {
            "category": f.category,
            "title": f.title,
            "severity": SEVERITY_NAMES.get(f.severity, str(f.severity)),
            "data": f.data or {},
        }
        for f in rep.findings
    ]
    ref_keys = sorted(_key(f) for f in ref_findings)
    act_keys = sorted(_key(f) for f in actual_dicts)

    if ref_keys == act_keys:
        return {"passed": True, "detail": "Golden match: {} finding(s)".format(len(ref_keys))}

    missing = sorted(set(ref_keys) - set(act_keys))
    extra = sorted(set(act_keys) - set(ref_keys))
    detail_parts = []
    if missing:
        detail_parts.append("Missing: {}".format(missing[:5]))
    if extra:
        detail_parts.append("Extra: {}".format(extra[:5]))
    return {"passed": False, "detail": "; ".join(detail_parts)}


def _ioctl_count_check(rep, expected_count):
    """
    T6/T7: assert that the number of unique IOCTL codes equals expected_count.
    Returns a dict with 'passed' bool and 'detail' string.
    """
    ioctls = rep.by_category("ioctl")
    seen_codes = {f.data["code"] for f in ioctls if f.data and "code" in f.data}
    actual = len(seen_codes)
    passed = actual == expected_count
    return {
        "passed": passed,
        "detail": "IOCTL count: {} (expected {})".format(actual, expected_count),
        "actual_count": actual,
    }


def _heuristic_check(rep, pattern):
    """
    T7: assert that at least one heuristic finding title contains `pattern`.
    Returns a dict with 'passed' bool and 'detail' string.
    """
    heuristics = rep.by_category("heuristic")
    matches = [f for f in heuristics if pattern.lower() in f.title.lower()]
    passed = len(matches) > 0
    return {
        "passed": passed,
        "detail": "Heuristic '{}': {} match(es) in {} finding(s)".format(
            pattern, len(matches), len(heuristics)),
    }


def main() -> None:
    # ---------------------------------------------------------------------------
    # Wait for IDA's own auto-analysis before doing anything.
    # ---------------------------------------------------------------------------
    idc.auto_wait()

    result_path, opts = _parse_argv(list(idc.ARGV))

    start_time = time.time()
    result = {
        "status": "started",
        "driver": idc.get_root_filename(),
        "ida_sdk_version": idaapi.IDA_SDK_VERSION,
    }

    try:
        rep = reporting.Reporter(None)
        summary = analysis.run_analysis(rep)
        rep.close()

        checks = {}

        if "golden_path" in opts:
            checks["golden"] = _golden_check(rep, opts["golden_path"])

        if "ioctl_count" in opts:
            checks["ioctl_count"] = _ioctl_count_check(rep, opts["ioctl_count"])

        if "expect_heuristic" in opts:
            checks["heuristic"] = _heuristic_check(rep, opts["expect_heuristic"])

        all_passed = all(c.get("passed", True) for c in checks.values())

        result.update({
            "status": "ok" if all_passed else "checks_failed",
            "elapsed": round(time.time() - start_time, 2),
            "summary": summary,
            "checks": checks,
        })
    except Exception:
        result.update({
            "status": "error",
            "elapsed": round(time.time() - start_time, 2),
            "traceback": traceback.format_exc(),
        })

    # Write JSON result file for the outer runner to parse.
    try:
        with open(result_path, "w", encoding="utf-8") as result_file:
            json.dump(result, result_file, indent=2, default=str)
    except Exception as exc:
        print('[!] Could not write result file: {}'.format(exc), file=sys.stderr)

    exit_code = 0 if result.get("status") == "ok" else 1
    try:
        idc.qexit(exit_code)
    except AttributeError:
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
