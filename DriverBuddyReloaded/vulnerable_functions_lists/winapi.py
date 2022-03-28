# List of Windows API functions that are interesting
# Will partial match to start of function name, ie, Zw will match ZwClose
winapi_function_prefixes = [
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
    ######################################################
    # Dangerous encoding-translating functions, see MSDN for details
    "CharToOem",
    # CharToOemA
    # CharToOemBuffA
    # CharToOemBuffW
    # CharToOemW
    "OemToChar",
    # OemToCharA
    # OemToCharW

]

# Exact matches only
winapi_functions = [
    # Using the ChangeWindowMessageFilter function is not recommended, as it has process-wide scope.
    # Instead, use the ChangeWindowMessageFilterEx function to control access to specific windows as needed.
    # ChangeWindowMessageFilter may not be supported in future versions of Windows.
    "ChangeWindowMessageFilter",
]