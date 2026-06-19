"""
config.py: tunables, output-path helpers and the risk/severity model for
Driver Buddy Reloaded.

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
# Feature toggles (flip to False to disable a stage without touching the flow)
# --------------------------------------------------------------------------- #
class Feature:
    RISK_SCORING = True
    RESULTS_WINDOW = True
    JSON_EXPORT = True
    HTML_REPORT = True
    POC_HARNESS = True
    CALLCHAIN = True


# Depth (in call edges) the name-based call-chain tracer walks out from a handler.
CALLCHAIN_MAX_DEPTH = 6


# --------------------------------------------------------------------------- #
# Severity model
# --------------------------------------------------------------------------- #
SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_HIGH, SEV_CRITICAL = range(5)
SEVERITY_NAMES = {
    SEV_INFO: "INFO",
    SEV_LOW: "LOW",
    SEV_MEDIUM: "MEDIUM",
    SEV_HIGH: "HIGH",
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
    "METHOD_BUFFERED": 0,
    "METHOD_IN_DIRECT": 1,
    "METHOD_OUT_DIRECT": 1,
    "METHOD_NEITHER": 3,
}
# FILE_ANY_ACCESS means the IOCTL can be issued without any access-rights check.
ACCESS_RISK = {
    "FILE_ANY_ACCESS": 2,
    "FILE_READ_ACCESS": 0,
    "FILE_WRITE_ACCESS": 1,
    "FILE_READ_ACCESS | FILE_WRITE_ACCESS": 1,
}

# Curated high-signal sinks. When one of these is reachable from a dispatch /
# IOCTL handler it bumps the handler's severity and is reported as a call-chain
# finding. (The broader vulnerable_functions_lists are still flagged separately.)
DANGEROUS_SINKS = {
    # arbitrary copy primitives
    "memcpy": SEV_HIGH,
    "memmove": SEV_HIGH,
    "RtlCopyMemory": SEV_HIGH,
    "RtlMoveMemory": SEV_HIGH,
    # physical / mapped memory -> BYOVD read/write primitives
    "MmMapIoSpace": SEV_CRITICAL,
    "MmGetPhysicalAddress": SEV_HIGH,
    "MmMapLockedPagesSpecifyCache": SEV_HIGH,
    "ZwMapViewOfSection": SEV_HIGH,
    "ZwOpenSection": SEV_MEDIUM,
    # model-specific register access -> CPU control primitives
    "__writemsr": SEV_CRITICAL,
    "__readmsr": SEV_HIGH,
    # process manipulation
    "ZwTerminateProcess": SEV_HIGH,
    "PsLookupProcessByProcessId": SEV_MEDIUM,
    "ZwOpenProcess": SEV_MEDIUM,
}

# Severity attached to interesting opcodes when they appear in a driver.
OPCODE_SEVERITY = {
    "wrmsr": SEV_CRITICAL,
    "rdmsr": SEV_HIGH,
    "rdpmc": SEV_MEDIUM,
}


# --------------------------------------------------------------------------- #
# Output paths (lazy, against the IDB directory)
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
    """A single timestamp shared by every output file of one analysis run."""
    global _run_stamp
    if _run_stamp is None:
        _run_stamp = "{}-{}".format(date.today(), int(time.time()))
    return _run_stamp


def out_path(suffix):
    """Absolute path for an output artefact, e.g. out_path('IOCTLs.txt')."""
    return os.path.join(_db_dir(), "{}-{}-{}".format(driver_name(), run_stamp(), suffix))


def input_sha256():
    try:
        h = ida_nalt.retrieve_input_file_sha256()
        return h.hex() if h else ""
    except Exception:  # pragma: no cover
        return ""