"""
signatures.py: all function-name and opcode-name knowledge for DriverBuddyReloaded.

Single source of truth for:
  - Surface-scan lists (C/C++, WinAPI, opcodes, user-custom) consumed by utils.get_xrefs()
  - Heuristic function-name sets (copy sinks, validation guards, privilege gates, etc.)
    consumed by heuristics.py, callchain.py, and scoring.py
  - Severity maps for named opcodes and privileged CPU instructions

User customization: add driver-specific function names to
custom.py -- that file is the intended extension point and
is imported here as DRIVER_FUNCTIONS.
"""

from DriverBuddyReloaded.config import SEV_MEDIUM, SEV_HIGH, SEV_CRITICAL  # noqa: F401
from DriverBuddyReloaded.custom import driver_functions as DRIVER_FUNCTIONS

# ---------------------------------------------------------------------------
# Surface-scan lists (utils.populate_data_structures / get_xrefs)
# ---------------------------------------------------------------------------

# C/C++ functions commonly vulnerable or facilitating buffer-overflow conditions.
C_FUNCTIONS: frozenset = frozenset({
    # -- String Copy --
    "strcpy", "strcpyA", "strcpyW", "StrCpy", "StrCpyA", "StrCpyW",
    "wcscpy", "_ftcscpy", "_mbccpy", "_mbccpy_l", "_mbscpy", "_tccpy", "_tcscpy",
    "lstrcpy", "lstrcpyA", "lstrcpyW", "_fstrcpy", "_ftccpy", "ualstrcpyW",
    # "n" variants: no null-termination on overflow, no error return
    "StrCpyN", "StrCpyNA", "strcpynA", "StrCpyNW", "StrNCpy", "strncpy",
    "_strncpy_l", "StrNCpyA", "StrNCpyW", "lstrcpyn", "lstrcpynA", "lstrcpynW",
    "wcsncpy", "_wcsncpy_l", "_mbsncpy", "_mbsncpy_l", "_mbsnbcpy", "_mbsnbcpy_l",
    "_tcsncpy", "_fstrncpy",
    # -- String Concatenation --
    "lstrcat", "lstrcatA", "lstrcatW", "strcat", "StrCat", "strcatA", "StrCatA",
    "StrCatBuff", "StrCatBuffA", "StrCatBuffW", "strcatW", "StrCatW", "StrCatChainW",
    "wcscat", "_mbccat", "_mbscat", "_tccat", "_tcscat", "_ftcscat", "_fstrcat", "_ftccat",
    "lstrcatnA", "lstrcatn", "lstrcatnW", "lstrncat", "strncat", "_strncat_l",
    "StrCatN", "StrCatNA", "StrCatNW", "StrNCat", "StrNCatA", "StrNCatW",
    "wcsncat", "_wcsncat_l", "_mbsncat", "_mbsncat_l", "_mbsnbcat", "_mbsnbcat_l",
    "_tcsncat", "_fstrncat",
    # -- String Tokenizing --
    "strtok", "_strtok_l", "wcstok", "_wcstok_l", "_mbstok", "_mbstok_l", "_tcstok",
    # -- Makepath / Splitpath --
    "makepath", "_makepath", "_splitpath", "_tmakepath", "_tsplitpath",
    "_wmakepath", "_wsplitpath",
    # -- Numeric Conversion (signed/unsigned confusion) --
    "_itoa", "_i64toa", "_i64tow", "_itow", "_ui64toa", "_ui64tot",
    "_ui64tow", "_ultoa", "_ultot", "_ultow",
    # -- Scanf family --
    "scanf", "cscanf", "_cscanf", "_cscanf_l", "_cwscanf", "_cwscanf_l",
    "_sntscanf", "_stscanf", "_tscanf", "fscanf", "_fscanf_l", "fwscanf",
    "_fwscanf_l", "snscanf", "snwscanf", "sscanf", "_sscanf_l", "swscanf",
    "_swscanf_l", "wscanf", "vscanf", "vwscanf", "vsscanf", "vswscanf",
    "vfscanf", "vfwscanf", "_snscanf", "_snscanf_l", "_snwscanf", "_snwscanf_l",
    # -- Gets family --
    "_getts", "_gettws", "gets", "_getws", "cgets", "_cgets", "_cgetws",
    # -- String Length (integer overflow / wrap) --
    "strlen", "_mbslen", "_mbslen_l", "_mbstrlen", "_mbstrlen_l",
    "lstrlen", "StrLen", "wcslen",
    # -- Memory Copy --
    "CopyMemory", "RtlCopyMemory", "memcpy", "wmemcpy", "memccpy", "_memccpy",
    # -- Stack Allocation --
    "_alloca", "alloca", "_malloca",
    # -- Unrestricted Memory Manipulation --
    "memmove", "wmemmove", "realloc", "_realloc_dbg", "_recalloc", "_recalloc_dbg",
    "_aligned_offset_realloc", "_aligned_offset_realloc_dbg",
    "_aligned_offset_recalloc", "_aligned_offset_recalloc_dbg",
    "_aligned_realloc", "_aligned_realloc_dbg",
    "_aligned_recalloc", "_aligned_recalloc_dbg",
    # -- Printf family (format string bugs) --
    "_snprintf", "_snwprintf", "_stprintf", "_sntprintf", "_swprintf",
    "nsprintf", "sprintf", "sprintfA", "sprintfW", "swprintf", "std_strlprintf",
    "wnsprintf", "wnsprintfA", "wnsprintfW", "wsprintf", "wsprintfA", "wsprintfW",
    "wvnsprintf", "wvnsprintfA", "wvnsprintfW", "wvsprintf", "wvsprintfA", "wvsprintfW",
    "vsprintf", "vsnprintf", "vswprintf", "_vsnprintf", "_vsntprintf",
    "_vsnwprintf", "_vstprintf",
    # -- File Handling --
    "fopen", "_wfopen", "fopen_s", "_wfopen_s", "freopen", "_wfreopen",
    "freopen_s", "_wfreopen_s", "_fsopen", "_wfsopen", "open", "_open",
    "_wopen", "sopen", "_sopen", "_wsopen", "_sopen_s", "_wsopen_s",
    # -- Deprecated / Considered Harmful --
    "rewind",
    "strlwr", "wcslwr", "_strlwr", "_strlwr_l", "_wcslwr", "_wcslwr_l",
    "_mbslwr", "_mbslwr_l",
    "strupr", "wcsupr", "_strupr", "_strupr_l", "_wcsupr", "_wcsupr_l",
    "_mbsupr", "_mbsupr_l",
    "assert", "_assert", "_wassert",
    "catgets",
    "getenv", "_wgetenv", "getenv_s", "_wgetenv_s", "_dupenv_s", "_wdupenv_s",
    "_dupenv_s_dbg", "_wdupenv_s_dbg", "_searchenv", "_wsearchenv",
    "_searchenv_s", "_wsearchenv_s",
    "gethostbyname",
    "setbuf", "umask", "_umask", "_umask_s",
})

# Windows API prefix-match list (e.g. "IsBad" matches IsBadReadPtr).
WINAPI_FUNCTION_PREFIXES = [
    "IsBad",       # can mask pointer-assignment errors
    "ProbeFor",    # ProbeForRead / ProbeForWrite
    "CharToOem",   # dangerous encoding translators
    "OemToChar",   # dangerous encoding translators
    "LoadLibrary", # DLL planting / injection vector
    "SeAccessCheck",  # improper use can bypass ACL enforcement
]

# Windows API exact-match list.
WINAPI_FUNCTIONS = [
    "ChangeWindowMessageFilter",
    "EnterCriticalSection",
    "IofCallDriver",               # calls next driver in IRP stack; misuse -> UAF/double-complete
    "IoRegisterDeviceInterface",   # registers device interface; improper use exposes attack surface
    "HalGetBusDataByOffset",       # arbitrary PCI config-space read (BYOVD primitive)
    "HalSetBusDataByOffset",       # arbitrary PCI config-space write (BYOVD primitive)
    "PsCreateSystemThread",
    "SeQueryAuthenticationIdToken",
    "ObReferenceObjectByHandle",   # can access arbitrary kernel objects
    "ObRegisterCallbacks",         # installs object operation callbacks (DKOM technique)
    "ObOpenObjectByPointer",       # opens handle to arbitrary kernel object
    "RtlCopyMemory",               # arbitrary memory copy
    "RtlMoveMemory",               # arbitrary memory move
    "RtlQueryRegistryValues",      # registry read (exploitable via callbacks)
    "RtlWriteRegistryValue",       # registry write
    "RtlSetSaclSecurityDescriptor",
    "RtlCreateRegistryKey",
    "MmMapIoSpace",                # maps physical memory into kernel VA
    "MmMapIoSpaceEx",
    "MmMapLockedPages",            # maps locked MDL pages into any address space
    "MmMapLockedPagesSpecifyCache",
    "MmProbeAndLockPages",         # locks user pages (required before MDL map)
    "MmGetSystemRoutineAddress",   # dynamic function resolution (KASLR bypass)
    "MmAllocateContiguousMemory",
    "MmAllocateContiguousMemorySpecifyCache",
    "MmCopyMemory",                # reads arbitrary physical or virtual memory
    "ZwCreateSection",             # creates section object (shared memory primitive)
    "ZwMapViewOfSection",          # maps section into a process (cross-process inject)
    "ZwLoadDriver",                # loads a kernel driver
    "ZwUnloadDriver",              # unloads a kernel driver
    "ZwTerminateProcess",          # terminates any process
    "ZwCreateFile",                # creates/opens any file (can open raw devices)
    "ZwWriteFile",                 # writes to any file handle
    "ZwSetInformationFile",
    "ZwSetSystemInformation",      # modifies system-wide configuration
]

# Opcodes to search for in the binary.
OPCODES = [
    "rdpmc",
    "wrmsr",
    "rdmsr",
]

# ---------------------------------------------------------------------------
# Heuristic severity maps
# ---------------------------------------------------------------------------

# Severity attached to interesting named opcodes when they appear in a driver.
OPCODE_SEVERITY = {
    "wrmsr": SEV_CRITICAL,
    "rdmsr": SEV_HIGH,
    "rdpmc": SEV_MEDIUM,
}

# Privileged CPU instructions flagged when reachable from a dispatch handler.
# Port I/O (in/out) and descriptor-table loads are the inline primitives behind
# most BYOVD hardware-access drivers.
PRIV_INSN_SEVERITY = {
    "out": SEV_CRITICAL, "outs": SEV_CRITICAL, "outsb": SEV_CRITICAL,
    "outsw": SEV_CRITICAL, "outsd": SEV_CRITICAL,
    "in": SEV_HIGH, "ins": SEV_HIGH, "insb": SEV_HIGH, "insw": SEV_HIGH, "insd": SEV_HIGH,
    "invd": SEV_HIGH, "wbinvd": SEV_MEDIUM,
    "lgdt": SEV_HIGH, "lidt": SEV_HIGH, "lldt": SEV_HIGH, "ltr": SEV_HIGH, "lmsw": SEV_HIGH,
    "cli": SEV_MEDIUM, "sti": SEV_MEDIUM, "hlt": SEV_MEDIUM,
}

# ---------------------------------------------------------------------------
# Heuristic function-name sets
# ---------------------------------------------------------------------------

# Curated high-signal sinks. Reaching one from a dispatch/IOCTL handler bumps
# severity and is reported as a call-chain finding.
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

# Pointer-validation and safe-arithmetic helpers that constitute an acceptable
# guard before a copy-sink or pool-allocation call.
VALIDATION_FUNCS = {
    "ProbeForRead",
    "ProbeForWrite",
    "MmIsAddressValid",
    "MmIsNonPagedSystemAddressValid",
    "MmSecureVirtualMemory",
    "MmSecureVirtualMemoryEx",
    "MmUnsecureVirtualMemory",
    # Safe arithmetic (ntintsafe.h / RtlSafeInt variants)
    "RtlULongAdd", "RtlULongSub", "RtlULongMult",
    "RtlULongLongAdd", "RtlULongLongSub", "RtlULongLongMult",
    "RtlSizeTAdd", "RtlSizeTSub", "RtlSizeTMult",
    "RtlUShortAdd", "RtlUShortSub", "RtlUShortMult",
    "RtlDWordPtrAdd", "RtlDWordPtrSub", "RtlDWordPtrMult",
    "RtlUIntPtrAdd", "RtlUIntPtrSub", "RtlUIntPtrMult",
    "RtlIntPtrAdd", "RtlIntPtrSub", "RtlIntPtrMult",
    # Safe string copy
    "RtlCopyMemory_safe",
    "RtlStringCchCopyA", "RtlStringCchCopyW",
    "RtlStringCbCopyA", "RtlStringCbCopyW",
    "RtlStringCchCatA", "RtlStringCchCatW",
    "RtlStringCchPrintfA", "RtlStringCchPrintfW",
    "RtlStringCbPrintfA", "RtlStringCbPrintfW",
}

# Functions whose presence on a dispatcher subtree constitutes a privilege gate.
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
PRIVILEGED_SENSITIVE_OPS = {
    "ZwOpenProcess", "ZwTerminateProcess",
    "PsCreateSystemThread", "PsTerminateSystemThread",
    "ZwAllocateVirtualMemory", "ZwFreeVirtualMemory",
    "ZwWriteVirtualMemory", "ZwReadVirtualMemory",
    "ZwProtectVirtualMemory", "NtCopyVirtualMemory",
    "ZwCreateSection", "ZwOpenSection",
    "ZwMapViewOfSection", "ZwUnmapViewOfSection",
    "MmMapIoSpace", "MmMapIoSpaceEx", "MmGetPhysicalAddress",
    "HalGetBusDataByOffset", "HalSetBusDataByOffset",
    "ZwLoadDriver", "NtLoadDriver",
    "ZwSetSystemInformation", "ZwSystemDebugControl", "ZwUnloadDriver",
}

# Functions that raise, lower, or query IRQL.
IRQL_RAISING_FUNCS = {
    "KeRaiseIrql", "KeRaiseIrqlToDpcLevel", "KeLowerIrql", "KeGetCurrentIrql",
    "KeAcquireSpinLock", "KeReleaseSpinLock",
    "KeAcquireSpinLockRaiseToDpc", "KeReleaseSpinLockFromDpcLevel",
    "KeAcquireSpinLockAtDpcLevel",
    "KeAcquireInStackQueuedSpinLock", "KeReleaseInStackQueuedSpinLock",
    "KeAcquireInStackQueuedSpinLockRaiseToDpc",
    "KeSynchronizeExecution", "KeFlushQueuedDpcs",
    "KeTryToAcquireSpinLockAtDpcLevel",
}

# MDL operations that can create user-accessible kernel mappings.
MDL_USER_FUNCS = {
    "MmProbeAndLockPages", "MmProbeAndLockSelectedPages",
    "MmMapLockedPagesSpecifyCache", "MmMapLockedPages", "MmUnmapLockedPages",
    "IoBuildPartialMdl", "MmGetSystemAddressForMdlSafe", "MmGetSystemAddressForMdl",
    "MmAllocatePagesForMdl", "MmAllocatePagesForMdlEx", "MmFreePagesFromMdl",
    "MmBuildMdlForNonPagedPool", "IoAllocateMdl", "IoFreeMdl",
}

# Copy primitives that may operate on unvalidated, user-controlled data.
COPY_SINKS = {
    "memcpy", "memmove", "wmemcpy",
    "RtlCopyMemory", "RtlMoveMemory", "RtlCopyBytes",
    "RtlCopyUnicodeString", "RtlCopyString",
    "RtlAppendUnicodeStringToString", "RtlAppendUnicodeToString",
    "MmCopyMemory",
    "ZwReadVirtualMemory", "ZwWriteVirtualMemory", "NtCopyVirtualMemory",
    "RtlFillMemory", "RtlZeroMemory",
}

# Stack-allocation intrinsics.
ALLOCA_FUNCS = {
    "_alloca", "alloca", "_malloca",
    "_chkstk", "_alloca_probe", "__alloca_probe",
    "__alloca_probe_16",
}

# Pool-allocation functions.
POOL_ALLOC_FUNCS = {
    "ExAllocatePool", "ExAllocatePoolWithTag",
    "ExAllocatePool2", "ExAllocatePool3",
    "ExAllocatePoolWithTagPriority", "ExAllocatePoolWithQuotaTag",
    "ExAllocatePoolZero", "ExAllocatePoolQuotaZero",
    "ExAllocatePoolQuotaUninitialized", "ExAllocatePoolPriorityZero",
    "ExAllocatePoolPriorityUninitialized", "ExAllocatePoolUninitialized",
}

# Memory-range probe functions used by the TOCTOU check.
PROBE_FUNCS = {
    "ProbeForRead",
    "ProbeForWrite",
}

# Pool-free APIs whose freed-pointer register is tracked by the UAF check.
FREE_POOL_FUNCS = {
    "ExFreePool",
    "ExFreePoolWithTag",
    "ExFreePool2",
}

# Device-creation APIs that set no security descriptor inline on the create call,
# audited by utils.find_device_create_calls (each call site flagged for manual ACL
# review).  IoCreateDeviceSecure, which carries an inline SDDL the check decodes
# and rates, is handled separately in that function rather than listed here.
DEVICE_CREATE_UNSECURED_FUNCS = {
    "IoCreateDevice",     # WDM: no security descriptor -> world-accessible by default
    "WdfDeviceCreate",    # KMDF: DACL set out-of-band (WdfDeviceInitAssignSDDLString / INF)
}

# Symbolic-link creation APIs tracked for device-exposure analysis by
# device_name_finder.find_symbolic_links.  Deletion APIs are intentionally
# excluded: removing a link reduces exposure, it does not create it.
SYMLINK_CREATE_FUNCS = {
    "IoCreateSymbolicLink",
    "IoCreateUnprotectedSymbolicLink",  # NULL-DACL link: any user can delete/redirect it
    "WdfDeviceCreateSymbolicLink",      # KMDF symbolic-link creation
}
