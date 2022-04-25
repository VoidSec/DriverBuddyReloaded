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
    "Ob",
    # ObCloseHandle
    # ObDereferenceObjectDeferDelete
    # ObDereferenceObjectDeferDeleteWithTag
    # ObfReferenceObject
    # ObGetObjectSecurity
    # ObReferenceObjectByHandle
    # ObReferenceObjectByHandleWithTag
    # ObReferenceObjectByPointer
    # ObReferenceObjectByPointerWithTag
    # ObReferenceObjectSafe
    # ObRegisterCallbacks
    # ObReleaseObjectSecurity
    # ObUnRegisterCallbacks
    "ProbeFor",
    # ProbeForRead
    # ProbeForWrite
    "Zw",
    # ZwClose
    # ZwCommitComplete
    # ZwCommitEnlistment
    # ZwCommitTransaction
    # ZwCreateDirectoryObject
    # ZwCreateEnlistment
    # ZwCreateFile
    # ZwCreateKey
    # ZwCreateKeyTransacted
    # ZwCreateResourceManager
    # ZwCreateSection
    # ZwCreateTransaction
    # ZwCreateTransactionManager
    # ZwDeleteKey
    # ZwDeleteValueKey
    # ZwEnumerateKey
    # ZwEnumerateTransactionObject
    # ZwEnumerateValueKey
    # ZwFlushKey
    # ZwGetNotificationResourceManager
    # ZwLoadDriver
    # ZwMakeTemporaryObject
    # ZwMapViewOfSection
    # ZwOpenEnlistment
    # ZwOpenEvent
    # ZwOpenFile
    # ZwOpenKey
    # ZwOpenKeyEx
    # ZwOpenKeyTransacted
    # ZwOpenKeyTransactedEx
    # ZwOpenResourceManager
    # ZwOpenSection
    # ZwOpenSymbolicLinkObject
    # ZwOpenTransaction
    # ZwOpenTransactionManager
    # ZwPrepareComplete
    # ZwPrepareEnlistment
    # ZwPrePrepareComplete
    # ZwPrePrepareEnlistment
    # ZwQueryFullAttributesFile
    # ZwQueryInformationByName
    # ZwQueryInformationEnlistment
    # ZwQueryInformationFile
    # ZwQueryInformationResourceManager
    # ZwQueryInformationTransaction
    # ZwQueryInformationTransactionManager
    # ZwQueryKey
    # ZwQuerySymbolicLinkObject
    # ZwQueryValueKey
    # ZwReadFile
    # ZwReadOnlyEnlistment
    # ZwRecoverEnlistment
    # ZwRecoverResourceManager
    # ZwRecoverTransactionManager
    # ZwRollbackComplete
    # ZwRollbackEnlistment
    # ZwRollbackTransaction
    # ZwRollforwardTransactionManager
    # ZwSetInformationEnlistment
    # ZwSetInformationFile
    # ZwSetInformationResourceManager
    # ZwSetInformationTransaction
    # ZwSetValueKey
    # ZwSinglePhaseReject
    # ZwUnloadDriver
    # ZwUnmapViewOfSection
    # ZwWriteFile
    # Dangerous encoding-translating functions, see MSDN for details
    "CharToOem",
    # CharToOemA
    # CharToOemBuffA
    # CharToOemBuffW
    # CharToOemW
    "OemToChar",
    # OemToCharA
    # OemToCharW
    ######################################################
    # These functions can allow arbitrary memory read/write
    "MmMapIoSpace",
    ######################################################
    # These functions can throw exceptions when limited memory is available,
    # resulting in unstable behaviour and potential DoS conditions.
    # Use the safer InitialCriticalSectionAndSpinCount function
    "LoadLibrary",
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
    # Use the safer InitialCriticalSectionAndSpinCount function
    "EnterCriticalSection",
    "IofCallDriver",
    "IoRegisterDeviceInterface",
    "PsCreateSystemThread",
    "SeQueryAuthenticationIdToken",
]
