"""
ida_smoke.py - Headless smoke test for Driver Buddy Reloaded.

Run inside IDA in autonomous batch mode:

    idat64.exe -A -Lida.log "-Stests\\ida_smoke.py result.json" driver.sys

The script runs the full analysis pipeline against the loaded binary and writes a
JSON summary to the path given as idc.ARGV[1].  Exit code 0 = success, 1 = error.

See tests/run_cross_version.ps1 for the cross-version matrix runner.
"""

import json
import os
import sys
import time
import traceback

# Add the repo root to sys.path so the package is importable regardless of
# IDA's working directory.
_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_TESTS_DIR)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import idc          # noqa: E402 (must follow sys.path setup)
import idaapi       # noqa: E402

from DriverBuddyReloaded import analysis, reporting  # noqa: E402


def main() -> None:
    # ---------------------------------------------------------------------------
    # Wait for IDA's own auto-analysis before doing anything.
    # ---------------------------------------------------------------------------
    idc.auto_wait()

    result_path = idc.ARGV[1] if len(idc.ARGV) > 1 else os.path.join(_TESTS_DIR, "smoke_result.json")

    start_time = time.time()
    result = {
        "status": "started",
        "driver": idc.get_root_filename(),
        "ida_sdk_version": idaapi.IDA_SDK_VERSION,
    }

    try:
        # Run the full pipeline. No log file -- output goes to IDA's console/log
        # only (callers redirect via -L so we don't need a separate file here).
        rep = reporting.Reporter(None)
        summary = analysis.run_analysis(rep)
        rep.close()
        result.update({
            "status": "ok",
            "elapsed": round(time.time() - start_time, 2),
            "summary": summary,
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
