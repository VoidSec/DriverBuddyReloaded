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
    CALLCHAIN = True
    HEURISTICS = True
    EXPORTS_AUDIT = True
    POOLTAG_FALLBACK = True
    SEGMENT_OPCODE_SCAN = False  # noisy with existing find(x=True); opt-in only
    IRP_MJ_ENUM = True
    IOCTL_SCAN = True
    IOCTL_DECOMPILER = True  # use HexRays ctree in scan_dispatchers (recovers
    #                          codes hidden by jump tables / binary-search dispatch)
    TOCTOU_CHECK = True
    ACL_AUDIT = True
    SYMLINK_TRACK = True
    UAF_DETECT = True

    @classmethod
    def validate(cls):
        """Raise ValueError if the current feature-flag combination is incoherent."""
        if cls.CALLCHAIN and not cls.IOCTL_SCAN:
            raise ValueError("Feature.CALLCHAIN requires Feature.IOCTL_SCAN")
        if cls.IOCTL_DECOMPILER and not cls.IOCTL_SCAN:
            raise ValueError("Feature.IOCTL_DECOMPILER requires Feature.IOCTL_SCAN")


# Depth (in call edges) the name-based call-chain tracer walks out from a handler.
CALLCHAIN_MAX_DEPTH = 6

# Depth the heuristic engine expands from each dispatcher to reach the per-IOCTL
# handler bodies it calls (e.g. HEVD's Trigger* functions live one-to-two calls
# below DispatchDeviceControl).  Without this expansion the deep checks
# (double-fetch, UAF, pool-trust, privilege-gate, IRQL, MDL, alloca) only ever
# saw the dispatcher prologue and missed every callee-resident bug.
HANDLER_SEED_DEPTH = 4


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
    # PCI configuration-space access -> arbitrary device config read/write
    "HalGetBusDataByOffset": SEV_HIGH,
    "HalSetBusDataByOffset": SEV_CRITICAL,
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

# Privileged CPU instructions flagged when reachable from a dispatch handler.
# Port I/O (in/out) and descriptor-table loads are the inline primitives (not
# function calls) behind most BYOVD hardware-access drivers; an `out` to an
# arbitrary port is a direct write primitive, so it is rated highest.
PRIV_INSN_SEVERITY = {
    "out": SEV_CRITICAL, "outs": SEV_CRITICAL, "outsb": SEV_CRITICAL,
    "outsw": SEV_CRITICAL, "outsd": SEV_CRITICAL,
    "in": SEV_HIGH, "ins": SEV_HIGH, "insb": SEV_HIGH, "insw": SEV_HIGH, "insd": SEV_HIGH,
    "invd": SEV_HIGH, "wbinvd": SEV_MEDIUM,
    "lgdt": SEV_HIGH, "lidt": SEV_HIGH, "lldt": SEV_HIGH, "ltr": SEV_HIGH, "lmsw": SEV_HIGH,
    "cli": SEV_MEDIUM, "sti": SEV_MEDIUM, "hlt": SEV_MEDIUM,
}

# ---------------------------------------------------------------------------
# Heuristic function-name sets (used by heuristics.py)
# ---------------------------------------------------------------------------

# Pointer-validation and safe-arithmetic helpers that constitute an acceptable
# guard before a copy-sink call.  Covers ProbeFor* memory probes, MmSecure*,
# and the full ntintsafe.h safe-arithmetic family.
VALIDATION_FUNCS = {
    # Memory range validation
    "ProbeForRead",
    "ProbeForWrite",
    "MmIsAddressValid",
    "MmIsNonPagedSystemAddressValid",
    "MmSecureVirtualMemory",
    "MmSecureVirtualMemoryEx",
    "MmUnsecureVirtualMemory",
    # Safe arithmetic (ntintsafe.h / RtlSafeInt variants)
    "RtlULongAdd",
    "RtlULongSub",
    "RtlULongMult",
    "RtlULongLongAdd",
    "RtlULongLongSub",
    "RtlULongLongMult",
    "RtlSizeTAdd",
    "RtlSizeTSub",
    "RtlSizeTMult",
    "RtlUShortAdd",
    "RtlUShortSub",
    "RtlUShortMult",
    "RtlDWordPtrAdd",
    "RtlDWordPtrSub",
    "RtlDWordPtrMult",
    "RtlUIntPtrAdd",
    "RtlUIntPtrSub",
    "RtlUIntPtrMult",
    "RtlIntPtrAdd",
    "RtlIntPtrSub",
    "RtlIntPtrMult",
    # Safe string copy (replacement for unsafe sprintf / strcpy family)
    "RtlCopyMemory_safe",
    "RtlStringCchCopyA",
    "RtlStringCchCopyW",
    "RtlStringCbCopyA",
    "RtlStringCbCopyW",
    "RtlStringCchCatA",
    "RtlStringCchCatW",
    "RtlStringCchPrintfA",
    "RtlStringCchPrintfW",
    "RtlStringCbPrintfA",
    "RtlStringCbPrintfW",
}

# Functions whose presence in a function demonstrates a privilege gate.
# If none of these appear but PRIVILEGED_SENSITIVE_OPS are called, it is
# a strong indicator of a missing access-control check.
PRIVILEGE_GATE_FUNCS = {
    "SeSinglePrivilegeCheck",
    "SePrivilegeCheck",
    "SeAccessCheck",
    "SeAccessCheckAndAuditAlarm",
    "SeTokenIsAdmin",
    "SeTokenIsWriteRestricted",
    "PsIsProtectedProcess",
    "PsIsProtectedProcessLight",
    "ZwOpenProcessToken",
    "ZwOpenProcessTokenEx",
    "ZwOpenThreadToken",
    "ZwOpenThreadTokenEx",
    "ZwQueryInformationToken",
    "SeQueryInformationToken",
    "PsGetCurrentProcessToken",
    "RtlCheckTokenMembership",
    "SeCaptureSubjectContext",
    "SeReleaseSubjectContext",
}

# High-value kernel operations that should be gated by a privilege check.
# Presence without a corresponding PRIVILEGE_GATE_FUNCS call is HIGH severity.
PRIVILEGED_SENSITIVE_OPS = {
    # Process / thread control
    "ZwOpenProcess",
    "ZwTerminateProcess",
    "PsCreateSystemThread",
    "PsTerminateSystemThread",
    # Virtual memory manipulation (common exploit primitives)
    "ZwAllocateVirtualMemory",
    "ZwFreeVirtualMemory",
    "ZwWriteVirtualMemory",
    "ZwReadVirtualMemory",
    "ZwProtectVirtualMemory",
    "NtCopyVirtualMemory",
    # Section / shared-memory mapping
    "ZwCreateSection",
    "ZwOpenSection",
    "ZwMapViewOfSection",
    "ZwUnmapViewOfSection",
    # Physical memory and I/O space access (BYOVD primitives)
    "MmMapIoSpace",
    "MmMapIoSpaceEx",
    "MmGetPhysicalAddress",
    # PCI configuration-space access (BYOVD primitives)
    "HalGetBusDataByOffset",
    "HalSetBusDataByOffset",
    # Driver loading / system modification
    "ZwLoadDriver",
    "NtLoadDriver",
    "ZwSetSystemInformation",
    "ZwSystemDebugControl",
    "ZwUnloadDriver",
}

# Functions that raise, lower, or query IRQL; their presence marks an
# IRQL-sensitive context where pageable operations become dangerous.
IRQL_RAISING_FUNCS = {
    "KeRaiseIrql",
    "KeRaiseIrqlToDpcLevel",
    "KeLowerIrql",
    "KeGetCurrentIrql",
    "KeAcquireSpinLock",
    "KeReleaseSpinLock",
    "KeAcquireSpinLockRaiseToDpc",
    "KeReleaseSpinLockFromDpcLevel",
    "KeAcquireSpinLockAtDpcLevel",
    "KeAcquireInStackQueuedSpinLock",
    "KeReleaseInStackQueuedSpinLock",
    "KeAcquireInStackQueuedSpinLockRaiseToDpc",
    "KeSynchronizeExecution",
    "KeFlushQueuedDpcs",
    "KeTryToAcquireSpinLockAtDpcLevel",
}

# MDL operations that can create user-accessible kernel mappings; HIGH when
# UserMode context is detected nearby, MEDIUM otherwise.
MDL_USER_FUNCS = {
    "MmProbeAndLockPages",
    "MmProbeAndLockSelectedPages",
    "MmMapLockedPagesSpecifyCache",
    "MmMapLockedPages",
    "MmUnmapLockedPages",
    "IoBuildPartialMdl",
    "MmGetSystemAddressForMdlSafe",
    "MmGetSystemAddressForMdl",
    "MmAllocatePagesForMdl",
    "MmAllocatePagesForMdlEx",
    "MmFreePagesFromMdl",
    "MmBuildMdlForNonPagedPool",
    "IoAllocateMdl",
    "IoFreeMdl",
}

# Copy primitives that may operate on unvalidated, user-controlled data.
# Does not duplicate c_functions (strcpy/sprintf family) since those are
# already flagged as flagged_function findings by utils.get_xrefs().
COPY_SINKS = {
    "memcpy",
    "memmove",
    "wmemcpy",
    "RtlCopyMemory",
    "RtlMoveMemory",
    "RtlCopyBytes",
    "RtlCopyUnicodeString",
    "RtlCopyString",
    "RtlAppendUnicodeStringToString",
    "RtlAppendUnicodeToString",
    "MmCopyMemory",
    "ZwReadVirtualMemory",
    "ZwWriteVirtualMemory",
    "NtCopyVirtualMemory",
    "RtlFillMemory",
    "RtlZeroMemory",
}

# Stack-allocation intrinsics; presence in a dispatch handler warrants triage
# to ensure the allocation size is bounded (LOW severity, needs manual review).
ALLOCA_FUNCS = {
    "_alloca",
    "alloca",
    "_malloca",
    "_chkstk",
    "_alloca_probe",
    "__alloca_probe",
    "__alloca_probe_16",
}

# Pool-allocation functions.  Presence in an IOCTL handler without nearby
# safe-arithmetic guards is the canonical integer-overflow-in-allocation pattern.
POOL_ALLOC_FUNCS = {
    "ExAllocatePool",
    "ExAllocatePoolWithTag",
    "ExAllocatePool2",
    "ExAllocatePool3",
    "ExAllocatePoolWithTagPriority",
    "ExAllocatePoolWithQuotaTag",
    "ExAllocatePoolZero",
    "ExAllocatePoolQuotaZero",
    "ExAllocatePoolQuotaUninitialized",
    "ExAllocatePoolPriorityZero",
    "ExAllocatePoolPriorityUninitialized",
    "ExAllocatePoolUninitialized",
}

# Memory-range probe functions used by TOCTOU check (N1).
PROBE_FUNCS = {
    "ProbeForRead",
    "ProbeForWrite",
}

# Device-creation APIs audited by the ACL check (N3).
DEVICE_CREATE_FUNCS = {
    "IoCreateDevice",
    "IoCreateDeviceSecure",
    "WdfDeviceCreate",
}

# Symbolic-link APIs tracked for exposure analysis (N4).
SYMLINK_FUNCS = {
    "IoCreateSymbolicLink",
    "IoDeleteSymbolicLink",
}

# Pool-free APIs whose freed-pointer register is tracked by the UAF check (N6).
FREE_POOL_FUNCS = {
    "ExFreePool",
    "ExFreePoolWithTag",
    "ExFreePool2",
}

# ---------------------------------------------------------------------------
# Analysis tuning constants
# ---------------------------------------------------------------------------

# How many instructions before a pool-allocation call site to scan backwards
# when searching for the 'Tag' immediate operand.
POOLTAG_LOOKBACK = 10

# Instruction window (instructions before, instructions after) around a copy-sink
# or pool-allocation call that the heuristic engine scans for a nearby validation
# call (ProbeFor* / ntintsafe safe-arithmetic).
COPY_VALIDATION_LOOKBACK = 20
COPY_VALIDATION_LOOKAHEAD = 6

# How many instructions to walk back from an ExFreePool* call when checking
# whether its freed-pointer argument was loaded straight from a global (the
# cross-function use-after-free check, N6b).
UAF_GLOBAL_BACKWALK = 16

# How many instructions to walk back from an IoCreateSymbolicLink call looking for
# the RtlInitUnicodeString string load.  Must be generous: HEVD initialises the
# link name ~38 instructions before the call (the whole IoCreateDevice +
# MajorFunction[] setup sits in between).  Walking back, the nearest
# backslash-prefixed string is always the symbolic-link name, so a wider window
# only ever helps.
SYMLINK_DECODE_LOOKBACK = 64


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
    """Absolute path for an output artefact, e.g. out_path('findings.json')."""
    return os.path.join(_db_dir(), "{}-{}-{}".format(driver_name(), run_stamp(), suffix))


def input_sha256():
    try:
        h = ida_nalt.retrieve_input_file_sha256()
        return h.hex() if h else ""
    except Exception:  # pragma: no cover
        return ""