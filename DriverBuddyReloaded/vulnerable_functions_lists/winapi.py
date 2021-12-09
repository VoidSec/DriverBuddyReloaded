# List of Windows API functions that are interesting
# Will partial match to start of function name, ie, Zw will match ZwClose
winapi_functions = [
    # IsBad* Functions
    # can mask errors during pointer assignment, resulting in memory leaks, crashes and unstable behaviour
    "IsBad",
    # IsBadCodePtr
    # IsBadHugeReadPtr
    # IsBadHugeWritePtr
    # IsBadReadPtr
    # IsBadStringPtr
    # IsBadWritePtr
    ######################################################
    # This functions can throw exceptions when limited memory is available,
    # resulting in unstable behaviour and potential DoS conditions.
    # Use the safer InitialCriticalSectionAndSpinCount function
    "EnterCriticalSection",
    "LoadLibrary",
    "IofCallDriver",
    "IoRegisterDeviceInterface",
    "Ob",
    "ProbeFor",
    "PsCreateSystemThread",
    "SeAccessCheck",
    "SeQueryAuthenticationIdToken",
    "Zw",
    ######################################################
    # These functions can allow arbitrary memory read/write
    "MmMapIoSpace",
]
