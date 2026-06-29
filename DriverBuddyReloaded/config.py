"""
config.py: feature flags, analysis tuning constants, severity model, IOCTL risk
weights, and output-path helpers for Driver Buddy Reloaded.

Function-name sets, opcode lists, and severity maps for individual instructions
live in signatures.py, not here.

Output paths are derived lazily against the IDA database directory (not the
process working directory), fixing the long-standing mismatch where files were
written to os.getcwd() while the docs promised the IDB directory.
"""

import os
import time
from datetime import date

import ida_nalt

try:
    import ida_loader
except ImportError:  # pragma: no cover
    ida_loader = None


# --------------------------------------------------------------------------- #
# Feature toggles
# Flip a flag to False to disable a stage without touching pipeline logic.
# --------------------------------------------------------------------------- #
class Feature:
    RISK_SCORING        = True
    RESULTS_WINDOW      = True
    JSON_EXPORT         = True
    HTML_REPORT         = True
    CALLCHAIN           = True
    HEURISTICS          = True
    EXPORTS_AUDIT       = True
    POOLTAG_FALLBACK    = True
    SEGMENT_OPCODE_SCAN = False  # noisy; opt-in only
    IRP_MJ_ENUM         = True
    IOCTL_SCAN          = True
    IOCTL_DECOMPILER    = True   # HexRays ctree in scan_dispatchers -- recovers
    #                              codes hidden by jump tables / binary-search dispatch
    TOCTOU_CHECK        = True
    ACL_AUDIT           = True
    SYMLINK_TRACK       = True
    UAF_DETECT          = True

    @classmethod
    def validate(cls):
        """Raise ValueError if the current feature-flag combination is incoherent."""
        if cls.CALLCHAIN and not cls.IOCTL_SCAN:
            raise ValueError("Feature.CALLCHAIN requires Feature.IOCTL_SCAN")
        if cls.IOCTL_DECOMPILER and not cls.IOCTL_SCAN:
            raise ValueError("Feature.IOCTL_DECOMPILER requires Feature.IOCTL_SCAN")


# --------------------------------------------------------------------------- #
# Analysis tuning constants
# --------------------------------------------------------------------------- #

# Call-graph traversal depths.
CALLCHAIN_MAX_DEPTH = 6   # BFS depth for name-based call-chain sink tracing
HANDLER_SEED_DEPTH  = 4   # expansion depth from dispatcher to per-IOCTL handler
#                           bodies (e.g. HEVD's Trigger* functions are 1-2 calls
#                           below DispatchDeviceControl; without expansion the deep
#                           checks only saw the dispatcher prologue)

# Instruction-window sizes used by the heuristic engine.
POOLTAG_LOOKBACK          = 10  # instructions to scan back for a pool-tag immediate
COPY_VALIDATION_LOOKBACK  = 20  # instructions before a copy/alloc sink to search for a guard
COPY_VALIDATION_LOOKAHEAD =  6  # instructions after  a copy/alloc sink to search for a guard

# UAF global-pointer back-walk: how many instructions before an ExFreePool* call
# to scan when checking whether the freed pointer came straight from a global.
UAF_GLOBAL_BACKWALK = 16

# Symbolic-link decode back-walk: how many instructions before an
# IoCreateSymbolicLink call to scan for the RtlInitUnicodeString load.
# Must be generous -- HEVD initialises the link name ~38 instructions before the
# call (the whole IoCreateDevice + MajorFunction[] setup sits in between).
SYMLINK_DECODE_LOOKBACK = 64


# --------------------------------------------------------------------------- #
# Severity model
# --------------------------------------------------------------------------- #
SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_HIGH, SEV_CRITICAL = range(5)
SEVERITY_NAMES = {
    SEV_INFO:     "INFO",
    SEV_LOW:      "LOW",
    SEV_MEDIUM:   "MEDIUM",
    SEV_HIGH:     "HIGH",
    SEV_CRITICAL: "CRITICAL",
}


def severity_name(sev):
    return SEVERITY_NAMES.get(sev, str(sev))


def clamp_severity(sev):
    return max(SEV_INFO, min(SEV_CRITICAL, sev))


# --------------------------------------------------------------------------- #
# IOCTL risk weights
# --------------------------------------------------------------------------- #
# METHOD_NEITHER hands raw, unvalidated user-mode pointers to the driver and is
# the classic source of arbitrary read/write primitives.
METHOD_RISK = {
    "METHOD_BUFFERED":  0,
    "METHOD_IN_DIRECT": 1,
    "METHOD_OUT_DIRECT": 1,
    "METHOD_NEITHER":   3,
}
# FILE_ANY_ACCESS means the IOCTL can be issued without any access-rights check.
ACCESS_RISK = {
    "FILE_ANY_ACCESS":                2,
    "FILE_READ_ACCESS":               0,
    "FILE_WRITE_ACCESS":              1,
    "FILE_READ_ACCESS | FILE_WRITE_ACCESS": 1,
}


# --------------------------------------------------------------------------- #
# Output paths (lazy, resolved against the IDB directory at runtime)
# --------------------------------------------------------------------------- #
def _db_dir():
    if ida_loader is not None:
        try:
            p = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
            if p:
                return os.path.dirname(p)
        except Exception:  # pragma: no cover - defensive
            pass
    return os.getcwd()


def driver_name():
    return ida_nalt.get_root_filename() or "driver"


_run_stamp = None


def run_stamp():
    """Single timestamp shared by every output file of one analysis run."""
    global _run_stamp
    if _run_stamp is None:
        _run_stamp = "{}-{}".format(date.today(), int(time.time()))
    return _run_stamp


def out_path(suffix):
    """Absolute path for an output artefact, e.g. out_path('findings.json')."""
    return os.path.join(_db_dir(), "{}-{}-{}".format(driver_name(), run_stamp(), suffix))


def input_sha256():
    try:
        h = ida_nalt.retrieve_input_file_sha256()
        return h.hex() if h else ""
    except Exception:  # pragma: no cover
        return ""
