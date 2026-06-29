# List of Windows API functions that are interesting
# Will partial match to start of function name, ie, IsBad will match IsBadReadPtr
winapi_function_prefixes = [
    # IsBad* Functions -- can mask errors during pointer assignment, resulting in
    # memory leaks, crashes and unstable behaviour.
    # See MSDN: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-isbadreadptr
    "IsBad",
    # ProbeFor* -- ProbeForRead / ProbeForWrite: validate user-mode buffer accessibility.
    # See MSDN: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-probeforread
    "ProbeFor",
    # CharToOem* -- dangerous encoding-translating functions.
    # See MSDN: https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-chartooema
    "CharToOem",
    # OemToChar* -- dangerous encoding-translating functions.
    # See MSDN: https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-oemtochara
    "OemToChar",
    # LoadLibrary* -- dynamic library loading; can be abused for DLL planting / injection.
    # See MSDN: https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya
    "LoadLibrary",
    # SeAccessCheck* -- security access check routines; improper use can bypass ACL enforcement.
    # See MSDN: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-seaccesscheck
    "SeAccessCheck",
]

# Exact matches only
winapi_functions = [
    # Using the ChangeWindowMessageFilter function is not recommended, as it has process-wide scope.
    # Instead, use the ChangeWindowMessageFilterEx function to control access to specific windows as needed.
    # ChangeWindowMessageFilter may not be supported in future versions of Windows.
    "ChangeWindowMessageFilter",
    ######################################################
    # These functions can throw exceptions when limited memory is available,
    # resulting in unstable behaviour and potential DoS conditions.
    # Use the safer InitializeCriticalSectionAndSpinCount function.
    "EnterCriticalSection",
    "IofCallDriver",              # calls next driver in IRP stack; misuse leads to UAF/double-complete
    "IoRegisterDeviceInterface",  # registers device interface; improper use exposes attack surface
    "HalGetBusDataByOffset",      # arbitrary PCI config-space read (BYOVD hardware-access primitive)
    "HalSetBusDataByOffset",      # arbitrary PCI config-space write (BYOVD hardware-access primitive)
    "PsCreateSystemThread",
    "SeQueryAuthenticationIdToken",
    ######################################################
    # Object Manager routines -- high-value targets for DKOM and handle abuse.
    # See MSDN: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/
    "ObReferenceObjectByHandle",  # can access arbitrary kernel objects
    "ObRegisterCallbacks",        # installs object operation callbacks (DKOM technique)
    "ObOpenObjectByPointer",      # opens handle to arbitrary kernel object
    ######################################################
    # Rtl* memory and registry routines -- selected high-risk subset.
    # See MSDN: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/
    "RtlCopyMemory",              # arbitrary memory copy
    "RtlMoveMemory",              # arbitrary memory move
    "RtlQueryRegistryValues",     # registry read (can be exploited via callbacks)
    "RtlWriteRegistryValue",      # registry write
    "RtlSetSaclSecurityDescriptor",  # security descriptor manipulation
    "RtlCreateRegistryKey",       # creates registry keys
    ######################################################
    # Mm* physical and virtual memory mapping routines -- selected high-risk subset.
    # See MSDN: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/
    "MmMapIoSpace",               # maps physical memory into kernel VA
    "MmMapIoSpaceEx",             # extended version
    "MmMapLockedPages",           # maps locked MDL pages into any address space
    "MmMapLockedPagesSpecifyCache",  # same with cache control
    "MmProbeAndLockPages",        # locks user pages (required before MDL map)
    "MmGetSystemRoutineAddress",  # dynamic function resolution (KASLR bypass)
    "MmAllocateContiguousMemory", # allocates contiguous physical memory
    "MmAllocateContiguousMemorySpecifyCache",  # extended version
    "MmCopyMemory",               # reads arbitrary physical or virtual memory
    ######################################################
    # Zw* system call wrappers -- selected high-risk subset.
    # See MSDN: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/
    "ZwCreateSection",            # creates section object (shared memory primitive)
    "ZwMapViewOfSection",         # maps section into a process (cross-process inject)
    "ZwLoadDriver",               # loads a kernel driver
    "ZwUnloadDriver",             # unloads a kernel driver
    "ZwTerminateProcess",         # terminates any process
    "ZwCreateFile",               # creates/opens any file (can open raw devices)
    "ZwWriteFile",                # writes to any file handle
    "ZwSetInformationFile",       # changes file metadata/attributes
    "ZwSetSystemInformation",     # modifies system-wide configuration
]
