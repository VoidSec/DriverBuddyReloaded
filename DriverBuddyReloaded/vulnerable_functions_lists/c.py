# List of C/C++ functions that are commonly vulnerable or that can facilitate buffer overflow conditions
c_functions = [
    # String Copy Functions
    "strcpy",
    "strcpyA",
    "strcpyW",
    "StrCpy",
    "StrCpyA",
    "StrCpyW",
    "wcscpy",
    "_ftcscpy",
    "_mbccpy",
    "_mbccpy_l",
    "_mbscpy",
    "_tccpy",
    "_tcscpy",
    "lstrcpy",
    "lstrcpyA",
    "lstrcpyW",
    # While 'safer', "n" functions include non-null termination of overflowed buffers; no error returns on overflow
    "StrCpyN",
    "StrCpyNA",
    "strcpynA",
    "StrCpyNW",
    "StrNCpy",
    "strncpy",
    "_strncpy_l",
    "StrNCpyA",
    "StrNCpyW",
    "lstrcpyn",
    "lstrcpynA",
    "lstrcpynW",
    "wcsncpy",
    "_wcsncpy_l",
    "_mbsncpy",
    "_mbsncpy_l",
    "_mbsnbcpy",
    "_mbsnbcpy_l",
    "_tcsncpy",
    ######################################################
    # String Concatenation Functions
    "lstrcat",
    "lstrcatA",
    "lstrcatW",
    "strcat",
    "StrCat",
    "strcatA",
    "StrCatA",
    "StrCatBuff",
    "StrCatBuffA",
    "StrCatBuffW",
    "strcatW",
    "StrCatW",
    "StrCatChainW",
    "wcscat",
    "_mbccat",
    "_mbscat",
    "_tccat",
    "_tcscat",
    "_ftcscat",
    # While 'safer', "n" functions include non-null termination of overflowed buffers; no error returns on overflow
    "lstrcatnA",
    "lstrcatn",
    "lstrcatnW",
    "lstrncat",
    "strncat",
    "_strncat_l",
    "StrCatN",
    "StrCatNA",
    "StrCatNW",
    "StrNCat",
    "StrNCatA",
    "StrNCatW",
    "wcsncat",
    "_wcsncat_l",
    "_mbsncat",
    "_mbsncat_l",
    "_mbsnbcat",
    "_mbsnbcat_l",
    "_tcsncat",
    ######################################################
    # String Tokenizing Functions
    "strtok",  # not always thread-safe
    "_strtok_l",
    "wcstok",
    "_wcstok_l",
    "_mbstok",
    "_mbstok_l",
    "_tcstok",
    ######################################################
    # Makepath/Splitpath Functions
    # Use the safer alternative: _makepath_s, _splitpath_s
    "makepath",
    "_makepath",
    "_splitpath",
    "_tmakepath",
    "_tsplitpath",
    "_wmakepath",
    "_wsplitpath",
    ######################################################
    # Numeric Conversion Functions
    # do not perform a safe conversion on account of a failure to distinguish between 'signed' and 'unsigned'
    "_itoa",
    "_i64toa",
    "_i64tow",
    "_itow",
    "_ui64toa",
    "_ui64tot",
    "_ui64tow",
    "_ultoa",
    "_ultot",
    "_ultow",
    ######################################################
    # Scanf Functions
    # directs user defined input to a buffer, can facilitate buffer overflows
    "scanf",
    "_sntscanf",
    "_stscanf",
    "_tscanf",
    "fscanf",
    "snscanf",
    "snwscanf",
    "sscanf",
    "swscanf",
    "wscanf",
    ######################################################
    # Gets Functions
    # reads characters from STDIN and writes to buffer until EOL, can facilitate buffer overflows
    "_getts",
    "_gettws",
    "gets",
    "_getws",
    "cgets",
    "_cgets",
    "_cgetws",
    ######################################################
    # String Length functions
    # can become victims of integer overflow or 'wraparound' errors
    "strlen",
    "_mbslen",
    "_mbslen_l",
    "_mbstrlen",
    "_mbstrlen_l",
    "lstrlen",
    "StrLen",
    "wcslen",
    ######################################################
    # Memory Copy Functions
    # can facilitate buffer overflow conditions and other memory mis-management situations
    "CopyMemory",
    "memcpy",
    "RtlCopyMemory",
    "wmemcpy",
    ######################################################
    # Stack Dynamic Memory Allocation Functions
    # can facilitate buffer overflow conditions and other memory mis-management situations
    "_alloca",
    "alloca",
    "_malloca",
    ######################################################
    # Unrestricted Memory Manipulation
    # can facilitate buffer overflow conditions and other memory mis-management situations
    "memmove",
    "realloc",
    # can expose residual memory contents or render existing buffers impossible to securely erase.
    # do not use realloc on memory intended to be secure as the old structure will not be zeroed out
    ######################################################
    # *printf Family
    # can facilitate format string bugs
    "_snprintf",
    "_snwprintf",
    "_stprintf",
    "_sntprintf",
    "_swprintf",
    "nsprintf",
    "sprintf",
    "sprintfA",
    "sprintfW",
    "swprintf",
    "std_strlprintf",
    "wnsprintf",
    "wnsprintfA",
    "wnsprintfW",
    "wsprintf",
    "wsprintfA",
    "wsprintfW",
    "wvnsprintf",
    "wvnsprintfA",
    "wvnsprintfW",
    "wvsprintf",
    "wvsprintfA",
    "wvsprintfW",
    # is generally safe but will result in buffer overflows if destination is not checked for zero length
    "vsprintf",
    "vsnprintf",
    "vswprintf",
    "_vsnprintf",
    "_vsntprintf",
    "_vsnwprintf",
    "_vstprintf",
    ######################################################
    # File Handling
    # verify that user cannot modify filename for malicious purposes
    # and that file is not 'opened' more than once simultaneously
    "_wfopen",
    "_open",
    "_wopen",
    "fopen",
    ######################################################
    # Considered Harmful
    "rewind",
    # The 'rewind' function is considered unsafe and obsolete.
    # Rewind() makes it impossible to determine if the file position indicator was set back to the beginning of the file,
    # potentially resulting in improper control flow. fseek() is considered a safer alternative
    "_strlwr",  # Function is deprecated. Use the safer version, _strlwr_s
    "_strupr",  # Function is deprecated. Use the safer version, _strupr_s
    "assert",
    # The 'assert' macro usually only exists for code in the debug build.
    # In general, no check will take place in production code.
    # Verify that this check does not perform any critical function and is not being used in place of error handling
    "catgets",
    # These functions may use the NLSPATH environment variable.
    # Environment variables may be within the control of the end user and should be handled with caution.
    "getenv",
    "_wgetenv",
    "getenv_s",
    "_wgetenv_s",
    "_dupenv_s",
    "_wdupenv_s",
    "_dupenv_s_dbg",
    "_wdupenv_s_dbg",
    "_searchenv",
    "_wsearchenv",
    "_searchenv_s",
    "_wsearchenv_s",
    "gethostbyname",
    # Allows data to be read from a file/stream. Use with caution and do not allow user defined streams where possible.
    # Conduct a manual check to ensure data is handled in a safe manner
    "setbuf",
    # Manually check this function to ensure that safe privilege levels are being applied
    "umask",
    ######################################################
]
