import math

import ida_nalt
import idautils
import idc
from .find_opcodes import find
from .wdf import populate_wdf
from .wdm import check_for_fake_driver_entry, locate_ddc, define_ddc, find_dispatch_function

# List of C/C++ functions that are commonly vulnerable or that can facilitate buffer overflow conditions
c_functions = [
    # String Copy Functions
    "strcpy",
    "strcpyA",
    "strcpyW",
    # While 'safer', "n" functions include non-null termination of overflowed buffers; no error returns on overflow
    "StrCpyN",
    "StrCpyNA",
    "strcpynA",
    "StrCpyNW",
    "StrNCpy",
    "strncpy",
    "StrNCpyA",
    "StrNCpyW",
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
    # While 'safer', "n" functions include non-null termination of overflowed buffers; no error returns on overflow
    "lstrcatnA",
    "lstrcatn",
    "lstrcatnW",
    "lstrncat",
    "strncat",
    ######################################################
    # String Tokenizing Functions
    "strtok",  # not always thread-safe
    "wcstok",
    "_mbstok",
    "_tcstok",
    ######################################################
    # Makepath/Splitpath Functions
    # Use the safer alternative: _makepath_s, _splitpath_s
    "makepath",
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
    ######################################################
    # String Length functions
    # can become victims of integer overflow or 'wraparound' errors
    "strlen",
    "_mbslen",
    "_mbstrlen",
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
    "_sntprintf",
    "_swprintf",
    "nsprintf",
    "sprintf",
    "std_strlprintf",
    # is generally safe but will result in buffer overflows if destination is not checked for zero length
    "vsprintf",
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
    "getenv",  # Environment variables may be within the control of the end user and should be handled with caution.
    "gethostbyname",
    # Environment variables may be within the control of the end user and should be handled with caution.
    "setbuf",
    # Allows data to be read from a file/stream. Use with caution and do not allow user defined streams where possible.
    # Conduct a manual check to ensure data is handled in a safe manner
    "umask",  # Manually check this function to ensure that safe privilege levels are being applied
    ######################################################
]

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

# List of driver specific functions, modify for driver you're working on
driver_functions = []

# List of problematic opcodes to search for
opcodes = [
    "rdpmc;",
    "wrmsr;",
    "rdmsr;",
]

# Data structures needed to store addresses of functions we are interested in
functions_map = {}
imports_map = {}
c_map = {}
winapi_map = {}
driver_map = {}

# List of known NTSTATUS values to filter out from possible IOCTL codes
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
ntstatus_values = [
    0x00000000, 0x00000001, 0x00000002, 0x00000003, 0x0000003F, 0x00000080, 0x000000BF, 0x000000C0, 0x00000101,
    0x00000102, 0x00000103, 0x00000104, 0x00000105, 0x00000106, 0x00000107, 0x00000108, 0x00000109, 0x0000010A,
    0x0000010B, 0x0000010C, 0x0000010D, 0x0000010E, 0x00000110, 0x00000111, 0x00000112, 0x00000113, 0x00000114,
    0x00000115, 0x00000116, 0x00000117, 0x00000118, 0x00000119, 0x00000120, 0x00000121, 0x00000122, 0x00000123,
    0x00000124, 0x00000125, 0x00000126, 0x00000127, 0x00000128, 0x00000129, 0x0000012A, 0x0000012B, 0x00000202,
    0x00000367, 0x00010001, 0x00010002, 0x001C0001, 0x40000000, 0x40000001, 0x40000002, 0x40000003, 0x40000004,
    0x40000005, 0x40000006, 0x40000007, 0x40000008, 0x40000009, 0x4000000A, 0x4000000B, 0x4000000C, 0x4000000D,
    0x4000000E, 0x4000000F, 0x40000010, 0x40000011, 0x40000012, 0x40000013, 0x40000014, 0x40000015, 0x40000016,
    0x40000017, 0x40000018, 0x40000019, 0x4000001A, 0x4000001B, 0x4000001C, 0x4000001D, 0x4000001E, 0x4000001F,
    0x40000020, 0x40000021, 0x40000022, 0x40000023, 0x40000024, 0x40000025, 0x40000026, 0x40000027, 0x40000028,
    0x40000029, 0x4000002A, 0x4000002B, 0x4000002C, 0x4000002D, 0x4000002E, 0x4000002F, 0x40000030, 0x40000031,
    0x40000032, 0x40000033, 0x40000034, 0x40000294, 0x40000370, 0x40010001, 0x40010002, 0x40010003, 0x40010004,
    0x40010005, 0x40010006, 0x40010007, 0x40010008, 0x40010009, 0x40020056, 0x400200AF, 0x400A0004, 0x400A0005,
    0x4015000D, 0x40190034, 0x40190035, 0x401A000C, 0x401B00EC, 0x401E000A, 0x401E0117, 0x401E0307, 0x401E031E,
    0x401E034B, 0x401E034C, 0x401E0351, 0x401E042F, 0x401E0437, 0x401E0439, 0x401E043A, 0x40230001, 0x80000001,
    0x80000002, 0x80000003, 0x80000004, 0x80000005, 0x80000006, 0x80000007, 0x8000000A, 0x8000000B, 0x8000000C,
    0x8000000D, 0x8000000E, 0x8000000F, 0x80000010, 0x80000011, 0x80000012, 0x80000013, 0x80000014, 0x80000015,
    0x80000016, 0x80000017, 0x80000018, 0x8000001A, 0x8000001B, 0x8000001C, 0x8000001D, 0x8000001E, 0x8000001F,
    0x80000020, 0x80000021, 0x80000022, 0x80000023, 0x80000024, 0x80000025, 0x80000026, 0x80000027, 0x80000028,
    0x80000029, 0x8000002A, 0x8000002B, 0x8000002C, 0x8000002D, 0x80000288, 0x80000289, 0x80000803, 0x80010001,
    0x80130001, 0x80130002, 0x80130003, 0x80130004, 0x80130005, 0x80190009, 0x80190029, 0x80190031, 0x80190041,
    0x80190042, 0x801B00EB, 0x801C0001, 0x80210001, 0x80210002, 0xC0000001, 0xC0000002, 0xC0000003, 0xC0000004,
    0xC0000005, 0xC0000006, 0xC0000007, 0xC0000008, 0xC0000009, 0xC000000A, 0xC000000B, 0xC000000C, 0xC000000D,
    0xC000000E, 0xC000000F, 0xC0000010, 0xC0000011, 0xC0000012, 0xC0000013, 0xC0000014, 0xC0000015, 0xC0000016,
    0xC0000017, 0xC0000018, 0xC0000019, 0xC000001A, 0xC000001B, 0xC000001C, 0xC000001D, 0xC000001E, 0xC000001F,
    0xC0000020, 0xC0000021, 0xC0000022, 0xC0000023, 0xC0000024, 0xC0000025, 0xC0000026, 0xC0000027, 0xC0000028,
    0xC0000029, 0xC000002A, 0xC000002B, 0xC000002C, 0xC000002D, 0xC000002E, 0xC000002F, 0xC0000030, 0xC0000031,
    0xC0000032, 0xC0000033, 0xC0000034, 0xC0000035, 0xC0000037, 0xC0000038, 0xC0000039, 0xC000003A, 0xC000003B,
    0xC000003C, 0xC000003D, 0xC000003E, 0xC000003F, 0xC0000040, 0xC0000041, 0xC0000042, 0xC0000043, 0xC0000044,
    0xC0000045, 0xC0000046, 0xC0000047, 0xC0000048, 0xC0000049, 0xC000004A, 0xC000004B, 0xC000004C, 0xC000004D,
    0xC000004E, 0xC000004F, 0xC0000050, 0xC0000051, 0xC0000052, 0xC0000053, 0xC0000054, 0xC0000055, 0xC0000056,
    0xC0000057, 0xC0000058, 0xC0000059, 0xC000005A, 0xC000005B, 0xC000005C, 0xC000005D, 0xC000005E, 0xC000005F,
    0xC0000060, 0xC0000061, 0xC0000062, 0xC0000063, 0xC0000064, 0xC0000065, 0xC0000066, 0xC0000067, 0xC0000068,
    0xC0000069, 0xC000006A, 0xC000006B, 0xC000006C, 0xC000006D, 0xC000006E, 0xC000006F, 0xC0000070, 0xC0000071,
    0xC0000072, 0xC0000073, 0xC0000074, 0xC0000075, 0xC0000076, 0xC0000077, 0xC0000078, 0xC0000079, 0xC000007A,
    0xC000007B, 0xC000007C, 0xC000007D, 0xC000007E, 0xC000007F, 0xC0000080, 0xC0000081, 0xC0000082, 0xC0000083,
    0xC0000084, 0xC0000085, 0xC0000086, 0xC0000087, 0xC0000088, 0xC0000089, 0xC000008A, 0xC000008B, 0xC000008C,
    0xC000008D, 0xC000008E, 0xC000008F, 0xC0000090, 0xC0000091, 0xC0000092, 0xC0000093, 0xC0000094, 0xC0000095,
    0xC0000096, 0xC0000097, 0xC0000098, 0xC0000099, 0xC000009A, 0xC000009B, 0xC000009C, 0xC000009D, 0xC000009F,
    0xC00000A0, 0xC00000A1, 0xC00000A2, 0xC00000A3, 0xC00000A4, 0xC00000A5, 0xC00000A6, 0xC00000A7, 0xC00000A8,
    0xC00000A9, 0xC00000AA, 0xC00000AB, 0xC00000AC, 0xC00000AD, 0xC00000AE, 0xC00000AF, 0xC00000B0, 0xC00000B1,
    0xC00000B2, 0xC00000B3, 0xC00000B4, 0xC00000B5, 0xC00000B6, 0xC00000B7, 0xC00000B8, 0xC00000B9, 0xC00000BA,
    0xC00000BB, 0xC00000BC, 0xC00000BD, 0xC00000BE, 0xC00000BF, 0xC00000C0, 0xC00000C1, 0xC00000C2, 0xC00000C3,
    0xC00000C4, 0xC00000C5, 0xC00000C6, 0xC00000C7, 0xC00000C8, 0xC00000C9, 0xC00000CA, 0xC00000CB, 0xC00000CC,
    0xC00000CD, 0xC00000CE, 0xC00000CF, 0xC00000D0, 0xC00000D1, 0xC00000D2, 0xC00000D3, 0xC00000D4, 0xC00000D5,
    0xC00000D6, 0xC00000D7, 0xC00000D8, 0xC00000D9, 0xC00000DA, 0xC00000DB, 0xC00000DC, 0xC00000DD, 0xC00000DE,
    0xC00000DF, 0xC00000E0, 0xC00000E1, 0xC00000E2, 0xC00000E3, 0xC00000E4, 0xC00000E5, 0xC00000E6, 0xC00000E7,
    0xC00000E8, 0xC00000E9, 0xC00000EA, 0xC00000EB, 0xC00000EC, 0xC00000ED, 0xC00000EE, 0xC00000EF, 0xC00000F0,
    0xC00000F1, 0xC00000F2, 0xC00000F3, 0xC00000F4, 0xC00000F5, 0xC00000F6, 0xC00000F7, 0xC00000F8, 0xC00000F9,
    0xC00000FA, 0xC00000FB, 0xC00000FC, 0xC00000FD, 0xC00000FE, 0xC00000FF, 0xC0000100, 0xC0000101, 0xC0000102,
    0xC0000103, 0xC0000104, 0xC0000105, 0xC0000106, 0xC0000107, 0xC0000108, 0xC0000109, 0xC000010A, 0xC000010B,
    0xC000010C, 0xC000010D, 0xC000010E, 0xC0000117, 0xC0000118, 0xC0000119, 0xC000011A, 0xC000011B, 0xC000011C,
    0xC000011D, 0xC000011E, 0xC000011F, 0xC0000120, 0xC0000121, 0xC0000122, 0xC0000123, 0xC0000124, 0xC0000125,
    0xC0000126, 0xC0000127, 0xC0000128, 0xC0000129, 0xC000012A, 0xC000012B, 0xC000012C, 0xC000012D, 0xC000012E,
    0xC000012F, 0xC0000130, 0xC0000131, 0xC0000132, 0xC0000133, 0xC0000134, 0xC0000135, 0xC0000136, 0xC0000137,
    0xC0000138, 0xC0000139, 0xC000013A, 0xC000013B, 0xC000013C, 0xC000013D, 0xC000013E, 0xC000013F, 0xC0000140,
    0xC0000141, 0xC0000142, 0xC0000143, 0xC0000144, 0xC0000145, 0xC0000146, 0xC0000147, 0xC0000148, 0xC0000149,
    0xC000014A, 0xC000014B, 0xC000014C, 0xC000014D, 0xC000014E, 0xC000014F, 0xC0000150, 0xC0000151, 0xC0000152,
    0xC0000153, 0xC0000154, 0xC0000155, 0xC0000156, 0xC0000157, 0xC0000158, 0xC0000159, 0xC000015A, 0xC000015B,
    0xC000015C, 0xC000015D, 0xC000015E, 0xC000015F, 0xC0000160, 0xC0000161, 0xC0000162, 0xC0000163, 0xC0000164,
    0xC0000165, 0xC0000166, 0xC0000167, 0xC0000168, 0xC0000169, 0xC000016A, 0xC000016B, 0xC000016C, 0xC000016D,
    0xC000016E, 0xC0000172, 0xC0000173, 0xC0000174, 0xC0000175, 0xC0000176, 0xC0000177, 0xC0000178, 0xC000017A,
    0xC000017B, 0xC000017C, 0xC000017D, 0xC000017E, 0xC000017F, 0xC0000180, 0xC0000181, 0xC0000182, 0xC0000183,
    0xC0000184, 0xC0000185, 0xC0000186, 0xC0000187, 0xC0000188, 0xC0000189, 0xC000018A, 0xC000018B, 0xC000018C,
    0xC000018D, 0xC000018E, 0xC000018F, 0xC0000190, 0xC0000191, 0xC0000192, 0xC0000193, 0xC0000194, 0xC0000195,
    0xC0000196, 0xC0000197, 0xC0000198, 0xC0000199, 0xC000019A, 0xC000019B, 0xC000019C, 0xC000019D, 0xC000019E,
    0xC000019F, 0xC00001A0, 0xC00001A1, 0xC00001A2, 0xC00001A3, 0xC00001A4, 0xC0000201, 0xC0000202, 0xC0000203,
    0xC0000204, 0xC0000205, 0xC0000206, 0xC0000207, 0xC0000208, 0xC0000209, 0xC000020A, 0xC000020B, 0xC000020C,
    0xC000020D, 0xC000020E, 0xC000020F, 0xC0000210, 0xC0000211, 0xC0000212, 0xC0000213, 0xC0000214, 0xC0000215,
    0xC0000216, 0xC0000217, 0xC0000218, 0xC0000219, 0xC000021A, 0xC000021B, 0xC000021C, 0xC000021D, 0xC000021E,
    0xC000021F, 0xC0000220, 0xC0000221, 0xC0000222, 0xC0000223, 0xC0000224, 0xC0000225, 0xC0000226, 0xC0000227,
    0xC0000228, 0xC0000229, 0xC000022A, 0xC000022B, 0xC000022C, 0xC000022D, 0xC000022E, 0xC000022F, 0xC0000230,
    0xC0000231, 0xC0000232, 0xC0000233, 0xC0000234, 0xC0000235, 0xC0000236, 0xC0000237, 0xC0000238, 0xC0000239,
    0xC000023A, 0xC000023B, 0xC000023C, 0xC000023D, 0xC000023E, 0xC000023F, 0xC0000240, 0xC0000241, 0xC0000242,
    0xC0000243, 0xC0000244, 0xC0000245, 0xC0000246, 0xC0000247, 0xC0000248, 0xC0000249, 0xC0000250, 0xC0000251,
    0xC0000252, 0xC0000253, 0xC0000254, 0xC0000255, 0xC0000256, 0xC0000257, 0xC0000258, 0xC0000259, 0xC000025A,
    0xC000025B, 0xC000025C, 0xC000025E, 0xC000025F, 0xC0000260, 0xC0000261, 0xC0000262, 0xC0000263, 0xC0000264,
    0xC0000265, 0xC0000266, 0xC0000267, 0xC0000268, 0xC0000269, 0xC000026A, 0xC000026B, 0xC000026C, 0xC000026D,
    0xC000026E, 0xC000026F, 0xC0000270, 0xC0000271, 0xC0000272, 0xC0000273, 0xC0000275, 0xC0000276, 0xC0000277,
    0xC0000278, 0xC0000279, 0xC0000280, 0xC0000281, 0xC0000282, 0xC0000283, 0xC0000284, 0xC0000285, 0xC0000286,
    0xC0000287, 0xC000028A, 0xC000028B, 0xC000028C, 0xC000028D, 0xC000028E, 0xC000028F, 0xC0000290, 0xC0000291,
    0xC0000292, 0xC0000293, 0xC0000295, 0xC0000296, 0xC0000297, 0xC0000298, 0xC0000299, 0xC000029A, 0xC000029B,
    0xC000029C, 0xC000029D, 0xC000029E, 0xC000029F, 0xC00002A0, 0xC00002A1, 0xC00002A2, 0xC00002A3, 0xC00002A4,
    0xC00002A5, 0xC00002A6, 0xC00002A7, 0xC00002A8, 0xC00002A9, 0xC00002AA, 0xC00002AB, 0xC00002AC, 0xC00002AD,
    0xC00002AE, 0xC00002AF, 0xC00002B0, 0xC00002B1, 0xC00002B2, 0xC00002B3, 0xC00002B4, 0xC00002B5, 0xC00002B6,
    0xC00002B7, 0xC00002B8, 0xC00002B9, 0xC00002C1, 0xC00002C2, 0xC00002C3, 0xC00002C4, 0xC00002C5, 0xC00002C6,
    0xC00002C7, 0xC00002C8, 0xC00002C9, 0xC00002CA, 0xC00002CB, 0xC00002CC, 0xC00002CD, 0xC00002CE, 0xC00002CF,
    0xC00002D0, 0xC00002D1, 0xC00002D2, 0xC00002D3, 0xC00002D4, 0xC00002D5, 0xC00002D6, 0xC00002D7, 0xC00002D8,
    0xC00002D9, 0xC00002DA, 0xC00002DB, 0xC00002DC, 0xC00002DD, 0xC00002DE, 0xC00002DF, 0xC00002E0, 0xC00002E1,
    0xC00002E2, 0xC00002E3, 0xC00002E4, 0xC00002E5, 0xC00002E6, 0xC00002E7, 0xC00002E9, 0xC00002EA, 0xC00002EB,
    0xC00002EC, 0xC00002ED, 0xC00002EE, 0xC00002EF, 0xC00002F0, 0xC00002F1, 0xC00002F2, 0xC00002F3, 0xC00002F4,
    0xC00002F5, 0xC00002F6, 0xC00002F7, 0xC00002F8, 0xC00002F9, 0xC00002FA, 0xC00002FB, 0xC00002FC, 0xC00002FD,
    0xC00002FE, 0xC00002FF, 0xC0000300, 0xC0000301, 0xC0000302, 0xC0000303, 0xC0000304, 0xC0000305, 0xC0000306,
    0xC0000307, 0xC0000308, 0xC0000309, 0xC000030A, 0xC000030B, 0xC0000320, 0xC0000321, 0xC0000322, 0xC0000350,
    0xC0000351, 0xC0000352, 0xC0000353, 0xC0000354, 0xC0000355, 0xC0000356, 0xC0000357, 0xC0000358, 0xC0000359,
    0xC000035A, 0xC000035B, 0xC000035C, 0xC000035D, 0xC000035E, 0xC000035F, 0xC0000361, 0xC0000362, 0xC0000363,
    0xC0000364, 0xC0000365, 0xC0000366, 0xC0000368, 0xC0000369, 0xC000036A, 0xC000036B, 0xC000036C, 0xC000036D,
    0xC000036E, 0xC000036F, 0xC0000371, 0xC0000372, 0xC0000373, 0xC0000374, 0xC0000380, 0xC0000381, 0xC0000382,
    0xC0000383, 0xC0000384, 0xC0000385, 0xC0000386, 0xC0000387, 0xC0000388, 0xC0000389, 0xC000038A, 0xC000038B,
    0xC000038C, 0xC000038D, 0xC000038E, 0xC000038F, 0xC0000401, 0xC0000402, 0xC0000403, 0xC0000404, 0xC0000405,
    0xC0000406, 0xC0000407, 0xC0000408, 0xC0000409, 0xC000040A, 0xC000040B, 0xC000040C, 0xC000040D, 0xC000040E,
    0xC000040F, 0xC0000410, 0xC0000411, 0xC0000412, 0xC0000413, 0xC0000414, 0xC0000415, 0xC0000416, 0xC0000417,
    0xC0000418, 0xC0000419, 0xC000041A, 0xC000041B, 0xC000041C, 0xC0000420, 0xC0000421, 0xC0000423, 0xC0000424,
    0xC0000425, 0xC0000426, 0xC0000427, 0xC0000428, 0xC0000429, 0xC000042A, 0xC000042B, 0xC000042C, 0xC000042D,
    0xC000042E, 0xC0000432, 0xC0000433, 0xC0000434, 0xC0000435, 0xC0000440, 0xC0000441, 0xC0000442, 0xC0000443,
    0xC0000444, 0xC0000445, 0xC0000446, 0xC0000450, 0xC0000451, 0xC0000452, 0xC0000453, 0xC0000454, 0xC0000460,
    0xC0000463, 0xC0000464, 0xC0000465, 0xC0000466, 0xC0000467, 0xC0000480, 0xC0000500, 0xC0000501, 0xC0000502,
    0xC0000503, 0xC0000602, 0xC0000603, 0xC0000700, 0xC0000701, 0xC0000702, 0xC0000703, 0xC0000704, 0xC0000705,
    0xC0000706, 0xC0000707, 0xC0000708, 0xC0000709, 0xC000070A, 0xC000070B, 0xC000070C, 0xC000070D, 0xC000070E,
    0xC000070F, 0xC0000710, 0xC0000711, 0xC0000712, 0xC0000713, 0xC0000714, 0xC0000715, 0xC0000716, 0xC0000717,
    0xC0000718, 0xC0000719, 0xC000071A, 0xC000071B, 0xC000071C, 0xC000071D, 0xC000071E, 0xC000071F, 0xC0000720,
    0xC0000721, 0xC0000800, 0xC0000801, 0xC0000802, 0xC0000804, 0xC0000805, 0xC0000806, 0xC0000901, 0xC0000902,
    0xC0000903, 0xC0000904, 0xC0000905, 0xC0000906, 0xC0000907, 0xC0000908, 0xC0000909, 0xC0009898, 0xC000A000,
    0xC000A001, 0xC000A010, 0xC000A011, 0xC000A012, 0xC000A013, 0xC000A080, 0xC000A081, 0xC000A082, 0xC000A083,
    0xC000A084, 0xC000A085, 0xC000A086, 0xC000A087, 0xC000A088, 0xC000A100, 0xC000A101, 0xC000A2A1, 0xC000A2A2,
    0xC000A2A3, 0xC000A2A4, 0xC0010001, 0xC0010002, 0xC0020001, 0xC0020002, 0xC0020003, 0xC0020004, 0xC0020005,
    0xC0020006, 0xC0020007, 0xC0020008, 0xC0020009, 0xC002000A, 0xC002000B, 0xC002000C, 0xC002000D, 0xC002000E,
    0xC002000F, 0xC0020010, 0xC0020011, 0xC0020012, 0xC0020013, 0xC0020014, 0xC0020015, 0xC0020016, 0xC0020017,
    0xC0020018, 0xC0020019, 0xC002001A, 0xC002001B, 0xC002001C, 0xC002001D, 0xC002001F, 0xC0020021, 0xC0020022,
    0xC0020023, 0xC0020024, 0xC0020025, 0xC0020026, 0xC0020028, 0xC0020029, 0xC002002A, 0xC002002B, 0xC002002C,
    0xC002002D, 0xC002002E, 0xC002002F, 0xC0020030, 0xC0020031, 0xC0020032, 0xC0020033, 0xC0020034, 0xC0020035,
    0xC0020036, 0xC0020037, 0xC0020038, 0xC0020039, 0xC002003A, 0xC002003B, 0xC002003C, 0xC002003D, 0xC002003E,
    0xC002003F, 0xC0020040, 0xC0020041, 0xC0020042, 0xC0020043, 0xC0020044, 0xC0020045, 0xC0020046, 0xC0020047,
    0xC0020048, 0xC0020049, 0xC002004A, 0xC002004B, 0xC002004C, 0xC002004D, 0xC002004F, 0xC0020050, 0xC0020051,
    0xC0020052, 0xC0020053, 0xC0020054, 0xC0020055, 0xC0020057, 0xC0020058, 0xC0020062, 0xC0020063, 0xC0020064,
    0xC0030001, 0xC0030002, 0xC0030003, 0xC0030004, 0xC0030005, 0xC0030006, 0xC0030007, 0xC0030008, 0xC0030009,
    0xC003000A, 0xC003000B, 0xC003000C, 0xC0030059, 0xC003005A, 0xC003005B, 0xC003005C, 0xC003005D, 0xC003005E,
    0xC003005F, 0xC0030060, 0xC0030061, 0xC0040035, 0xC0040036, 0xC0040037, 0xC0040038, 0xC0040039, 0xC00A0001,
    0xC00A0002, 0xC00A0003, 0xC00A0006, 0xC00A0007, 0xC00A0008, 0xC00A0009, 0xC00A000A, 0xC00A000B, 0xC00A000C,
    0xC00A000D, 0xC00A000E, 0xC00A000F, 0xC00A0010, 0xC00A0012, 0xC00A0013, 0xC00A0014, 0xC00A0015, 0xC00A0016,
    0xC00A0017, 0xC00A0018, 0xC00A0022, 0xC00A0024, 0xC00A0026, 0xC00A0027, 0xC00A0028, 0xC00A002A, 0xC00A002B,
    0xC00A002E, 0xC00A002F, 0xC00A0030, 0xC00A0031, 0xC00A0032, 0xC00A0033, 0xC00A0034, 0xC00A0035, 0xC00A0036,
    0xC00A0037, 0xC00A0038, 0xC00A0039, 0xC00B0001, 0xC00B0002, 0xC00B0003, 0xC00B0004, 0xC00B0005, 0xC00B0006,
    0xC00B0007, 0xC0130001, 0xC0130002, 0xC0130003, 0xC0130004, 0xC0130005, 0xC0130006, 0xC0130007, 0xC0130008,
    0xC0130009, 0xC013000A, 0xC013000B, 0xC013000C, 0xC013000D, 0xC013000E, 0xC013000F, 0xC0130010, 0xC0130011,
    0xC0130012, 0xC0130013, 0xC0130014, 0xC0130015, 0xC0130016, 0xC0130017, 0xC0140001, 0xC0140002, 0xC0140003,
    0xC0140004, 0xC0140005, 0xC0140006, 0xC0140007, 0xC0140008, 0xC0140009, 0xC014000A, 0xC014000B, 0xC014000C,
    0xC014000D, 0xC014000E, 0xC014000F, 0xC0140010, 0xC0140011, 0xC0140012, 0xC0140013, 0xC0140014, 0xC0140015,
    0xC0140016, 0xC0140017, 0xC0140018, 0xC0140019, 0xC0140020, 0xC0140021, 0xC0150001, 0xC0150002, 0xC0150003,
    0xC0150004, 0xC0150005, 0xC0150006, 0xC0150007, 0xC0150008, 0xC0150009, 0xC015000A, 0xC015000B, 0xC015000C,
    0xC015000E, 0xC015000F, 0xC0150010, 0xC0150011, 0xC0150012, 0xC0150013, 0xC0150014, 0xC0150015, 0xC0150016,
    0xC0150017, 0xC0150018, 0xC0150019, 0xC015001A, 0xC015001B, 0xC015001C, 0xC015001D, 0xC015001E, 0xC015001F,
    0xC0150020, 0xC0150021, 0xC0150022, 0xC0150023, 0xC0150024, 0xC0150025, 0xC0150026, 0xC0150027, 0xC0190001,
    0xC0190002, 0xC0190003, 0xC0190004, 0xC0190005, 0xC0190006, 0xC0190007, 0xC0190008, 0xC019000A, 0xC019000B,
    0xC019000C, 0xC019000F, 0xC0190010, 0xC0190011, 0xC0190012, 0xC0190013, 0xC0190014, 0xC0190015, 0xC0190016,
    0xC0190017, 0xC0190018, 0xC0190019, 0xC0190021, 0xC0190022, 0xC0190023, 0xC0190024, 0xC0190025, 0xC0190026,
    0xC0190028, 0xC0190030, 0xC0190032, 0xC0190033, 0xC0190036, 0xC0190037, 0xC0190038, 0xC0190039, 0xC019003A,
    0xC019003B, 0xC019003C, 0xC019003D, 0xC019003E, 0xC019003F, 0xC0190040, 0xC0190043, 0xC0190044, 0xC0190045,
    0xC0190046, 0xC0190047, 0xC0190048, 0xC0190049, 0xC019004A, 0xC019004B, 0xC019004C, 0xC019004D, 0xC019004E,
    0xC019004F, 0xC0190050, 0xC0190051, 0xC0190052, 0xC0190053, 0xC0190054, 0xC0190055, 0xC0190056, 0xC0190057,
    0xC0190058, 0xC0190059, 0xC019005A, 0xC019005B, 0xC0190060, 0xC0190061, 0xC01A0001, 0xC01A0002, 0xC01A0003,
    0xC01A0004, 0xC01A0005, 0xC01A0006, 0xC01A0007, 0xC01A0008, 0xC01A0009, 0xC01A000A, 0xC01A000B, 0xC01A000D,
    0xC01A000E, 0xC01A000F, 0xC01A0010, 0xC01A0011, 0xC01A0012, 0xC01A0013, 0xC01A0014, 0xC01A0015, 0xC01A0016,
    0xC01A0017, 0xC01A0018, 0xC01A0019, 0xC01A001A, 0xC01A001B, 0xC01A001C, 0xC01A001D, 0xC01A001E, 0xC01A001F,
    0xC01A0020, 0xC01A0021, 0xC01A0022, 0xC01A0023, 0xC01A0024, 0xC01A0025, 0xC01A0026, 0xC01A0027, 0xC01A0028,
    0xC01A0029, 0xC01A002A, 0xC01A002B, 0xC01A002C, 0xC01A002D, 0xC01A002E, 0xC01A002F, 0xC01A0030, 0xC01B00EA,
    0xC01C0001, 0xC01C0002, 0xC01C0003, 0xC01C0004, 0xC01C0005, 0xC01C0006, 0xC01C0007, 0xC01C0008, 0xC01C0009,
    0xC01C000A, 0xC01C000B, 0xC01C000C, 0xC01C000D, 0xC01C000E, 0xC01C000F, 0xC01C0010, 0xC01C0011, 0xC01C0012,
    0xC01C0013, 0xC01C0014, 0xC01C0015, 0xC01C0016, 0xC01C0017, 0xC01C0018, 0xC01C0019, 0xC01C001A, 0xC01C001B,
    0xC01C001C, 0xC01C0020, 0xC01D0001, 0xC01D0002, 0xC01D0003, 0xC01D0004, 0xC01D0005, 0xC01D0006, 0xC01D0007,
    0xC01D0008, 0xC01D0009, 0xC01D000A, 0xC01E0000, 0xC01E0001, 0xC01E0002, 0xC01E0003, 0xC01E0004, 0xC01E0005,
    0xC01E0006, 0xC01E0007, 0xC01E0008, 0xC01E000B, 0xC01E000C, 0xC01E0100, 0xC01E0101, 0xC01E0102, 0xC01E0103,
    0xC01E0104, 0xC01E0105, 0xC01E0106, 0xC01E0107, 0xC01E0108, 0xC01E0109, 0xC01E0110, 0xC01E0111, 0xC01E0112,
    0xC01E0113, 0xC01E0114, 0xC01E0115, 0xC01E0116, 0xC01E0200, 0xC01E0300, 0xC01E0301, 0xC01E0302, 0xC01E0303,
    0xC01E0304, 0xC01E0305, 0xC01E0306, 0xC01E0308, 0xC01E0309, 0xC01E030A, 0xC01E030B, 0xC01E030C, 0xC01E0310,
    0xC01E0311, 0xC01E0312, 0xC01E0313, 0xC01E0314, 0xC01E0315, 0xC01E0316, 0xC01E0317, 0xC01E0318, 0xC01E0319,
    0xC01E031A, 0xC01E031B, 0xC01E031C, 0xC01E031D, 0xC01E031F, 0xC01E0320, 0xC01E0321, 0xC01E0322, 0xC01E0323,
    0xC01E0324, 0xC01E0325, 0xC01E0326, 0xC01E0327, 0xC01E0328, 0xC01E0329, 0xC01E032A, 0xC01E032B, 0xC01E032C,
    0xC01E032D, 0xC01E032E, 0xC01E032F, 0xC01E0330, 0xC01E0331, 0xC01E0332, 0xC01E0333, 0xC01E0334, 0xC01E0335,
    0xC01E0336, 0xC01E0337, 0xC01E0338, 0xC01E0339, 0xC01E033A, 0xC01E033B, 0xC01E033C, 0xC01E033D, 0xC01E033E,
    0xC01E033F, 0xC01E0340, 0xC01E0341, 0xC01E0342, 0xC01E0343, 0xC01E0344, 0xC01E0345, 0xC01E0346, 0xC01E0347,
    0xC01E0348, 0xC01E0349, 0xC01E034A, 0xC01E034D, 0xC01E034E, 0xC01E034F, 0xC01E0350, 0xC01E0352, 0xC01E0353,
    0xC01E0354, 0xC01E0355, 0xC01E0356, 0xC01E0357, 0xC01E0358, 0xC01E0359, 0xC01E035A, 0xC01E035B, 0xC01E035C,
    0xC01E0400, 0xC01E0401, 0xC01E0430, 0xC01E0431, 0xC01E0432, 0xC01E0433, 0xC01E0434, 0xC01E0435, 0xC01E0436,
    0xC01E0438, 0xC01E043B, 0xC01E0500, 0xC01E0501, 0xC01E0502, 0xC01E0503, 0xC01E0504, 0xC01E0505, 0xC01E0506,
    0xC01E0507, 0xC01E0508, 0xC01E050A, 0xC01E050B, 0xC01E050C, 0xC01E050D, 0xC01E050E, 0xC01E050F, 0xC01E0510,
    0xC01E0511, 0xC01E0512, 0xC01E0513, 0xC01E0514, 0xC01E0515, 0xC01E0516, 0xC01E0517, 0xC01E0518, 0xC01E051A,
    0xC01E051B, 0xC01E051C, 0xC01E051D, 0xC01E051E, 0xC01E051F, 0xC01E0520, 0xC01E0521, 0xC01E0580, 0xC01E0581,
    0xC01E0582, 0xC01E0583, 0xC01E0584, 0xC01E0585, 0xC01E0586, 0xC01E0587, 0xC01E0588, 0xC01E0589, 0xC01E058A,
    0xC01E058B, 0xC01E058C, 0xC01E058D, 0xC01E05E0, 0xC01E05E1, 0xC01E05E2, 0xC01E05E3, 0xC01E05E4, 0xC01E05E5,
    0xC01E05E6, 0xC01E05E7, 0xC01E05E8, 0xC0210000, 0xC0210001, 0xC0210002, 0xC0210003, 0xC0210004, 0xC0210005,
    0xC0210006, 0xC0210007, 0xC0210008, 0xC0210009, 0xC021000A, 0xC021000B, 0xC021000C, 0xC021000D, 0xC021000E,
    0xC021000F, 0xC0210010, 0xC0210011, 0xC0210012, 0xC0210013, 0xC0210014, 0xC0210015, 0xC0210016, 0xC0210017,
    0xC0210018, 0xC0210019, 0xC021001A, 0xC021001B, 0xC021001C, 0xC021001D, 0xC021001E, 0xC021001F, 0xC0210020,
    0xC0210021, 0xC0210022, 0xC0210023, 0xC0210026, 0xC0210027, 0xC0210028, 0xC0210029, 0xC0210030, 0xC0220001,
    0xC0220002, 0xC0220003, 0xC0220004, 0xC0220005, 0xC0220006, 0xC0220007, 0xC0220008, 0xC0220009, 0xC022000A,
    0xC022000B, 0xC022000C, 0xC022000D, 0xC022000E, 0xC022000F, 0xC0220010, 0xC0220011, 0xC0220012, 0xC0220013,
    0xC0220014, 0xC0220015, 0xC0220016, 0xC0220017, 0xC0220018, 0xC0220019, 0xC022001A, 0xC022001B, 0xC022001C,
    0xC022001D, 0xC022001E, 0xC022001F, 0xC0220020, 0xC0220021, 0xC0220022, 0xC0220023, 0xC0220024, 0xC0220025,
    0xC0220026, 0xC0220027, 0xC0220028, 0xC0220029, 0xC022002A, 0xC022002B, 0xC022002C, 0xC022002D, 0xC022002E,
    0xC022002F, 0xC0220030, 0xC0220031, 0xC0220032, 0xC0220033, 0xC0220034, 0xC0220035, 0xC0220036, 0xC0220037,
    0xC0220038, 0xC0220039, 0xC022003C, 0xC0220100, 0xC0220101, 0xC0220102, 0xC0220103, 0xC0230002, 0xC0230004,
    0xC0230005, 0xC0230006, 0xC0230007, 0xC0230008, 0xC0230009, 0xC023000A, 0xC023000B, 0xC023000C, 0xC023000D,
    0xC023000F, 0xC0230010, 0xC0230011, 0xC0230014, 0xC0230015, 0xC0230016, 0xC0230017, 0xC0230018, 0xC0230019,
    0xC023001A, 0xC023001B, 0xC023001C, 0xC023001D, 0xC023001E, 0xC023001F, 0xC0230022, 0xC023002A, 0xC023002B,
    0xC023002C, 0xC023002D, 0xC023002E, 0xC023002F, 0xC02300BB, 0xC023100F, 0xC0231012, 0xC0231013, 0xC0232000,
    0xC0232001, 0xC0232002, 0xC0232003, 0xC0232004, 0xC0360001, 0xC0360002, 0xC0360003, 0xC0360004, 0xC0360005,
    0xC0360006, 0xC0360007, 0xC0360008, 0xC0360009, 0xC0368000, 0xC0368001, 0xC0368002, 0xC0368003, 0xC0368004,
    0xC0368005, 0xC0368006, 0xC038005B, 0xC038005C, 0xC03A0014, 0xC03A0015, 0xC03A0016, 0xC03A0017, 0xC03A0018,
    0xC03A0019, 0xE0000001, 0xE0000002, 0xE0000004
]


def cb(address, name, ord):
    """
    Callback function needed by idaapi.enum_import_names().
    Called for every function in imports section of binary.
    :param address: Address of enumerated function
    :param name: Name of enumerated function
    :param ord: Ordinal of enumerated function. Not used for imports.
    :return boolean: 1 okay, -1 on error, otherwise callback return value
    """

    imports_map[name] = address
    functions_map[name] = address
    return True


def populate_function_map():
    """
    Loads functions known to IDA from the subs and imports sections into a map.
    :return boolean: True if functions are loaded successfully, otherwise False
    """

    result = False
    # Populate function_map with sub functions
    for address in idautils.Functions():
        func_name = idc.get_func_name(address)
        functions_map[func_name] = address
        result = True
    # Populate function_map with import functions
    import_list = ida_nalt.get_import_module_qty()
    for index in range(0, import_list):
        name = ida_nalt.get_import_module_name(index)
        ida_nalt.enum_import_names(index, cb)
        result = True
    return result


def populate_c_map():
    """
    Enumerate through the list of all functions and load vulnerable C/C++ functions found into a map.
    :return boolean: True if vulnerable functions are found, False otherwise
    """

    result = False
    for name, address in functions_map.items():
        if name in c_functions:
            c_map[name] = address
            result = True
    return result


def populate_winapi_map():
    """
    Enumerate through the list of all functions and load vulnerable Win API functions found into a map.
    :return boolean: True if vulnerable functions are found, False otherwise
    """

    result = False
    for name, address in functions_map.items():
        for winapi in winapi_functions:
            if name.lower().startswith(winapi.lower()):
                winapi_map[name] = address
                result = True
    return result


def populate_driver_map():
    """
    Enumerate through the list of all functions and load vulnerable driver specific functions found into a map.
    :return boolean: True if vulnerable functions found, False otherwise
    """

    result = False
    for name, address in functions_map.items():
        if name in driver_functions:
            driver_map[name] = address
            result = True
    return result


def populate_data_structures():
    """
    Enumerate through the list of functions and load vulnerable functions found into a map.
    :return boolean: False if unable to enumerate functions, True otherwise
    """

    # print("[>] Populating IDA functions...")
    result = populate_function_map()
    # search for problematic opcodes; x=True search in executable segments only
    print("[>] Searching for interesting opcodes...")
    for opcode in opcodes:
        find(opcode, x=True)
    if result is True:
        print("[>] Searching for interesting C/C++ functions...")
        result = populate_c_map()
        if result is True:
            # Interesting C/C++ functions detected
            get_xrefs(c_map)
        # else:
        #    print("[-] No interesting C/C++ functions found")
        print("[>] Searching for interesting Windows APIs...")
        result = populate_winapi_map()
        if result is True:
            # Interesting Windows API functions detected
            get_xrefs(winapi_map)
        # else:
        #    print("[-] No interesting Windows API functions found")
        # do not search for custom driver's functions if the list is empty
        if len(driver_functions) > 0:
            print("[>] Searching for interesting driver functions...")
            result = populate_driver_map()
            if result is True:
                # Interesting driver functions detected
                get_xrefs(driver_map)
            # else:
            #    print("[-] No interesting specific driver functions found")
        return True
    else:
        print("[!] ERR: Couldn't populate function_map")
        return False


def get_xrefs(func_map):
    """
    Gets cross references to vulnerable functions stored in map.
    :param func_map: function map you want xrefs for
    :return:
    """

    for name, address in func_map.items():
        code_refs = idautils.CodeRefsTo(int(address), 0)
        for ref in code_refs:
            # xref = "0x%08x" % ref
            print("\t- Found {} at 0x{addr:08x}".format(name, addr=ref))


def get_driver_id(driver_entry_addr):
    """
    Attempts to determine the type of the loaded driver by using functions found inside the imports section.
    :param driver_entry_addr: `DriverEntry` address
    :return string: return the detected driver type
    """

    # print("[>] Trying to determine driver type...")
    driver_type = ""
    # Iterate through imports and try to determine driver type
    for name, address in imports_map.items():
        if name == "FltRegisterFilter":
            driver_type = "Mini-Filter"
            break
        elif name == "WdfVersionBind":
            driver_type = "WDF"
            populate_wdf()
            break
        elif name == "StreamClassRegisterMinidriver":
            driver_type = "Stream Minidriver"
            break
        elif name == "KsCreateFilterFactory":
            driver_type = "AVStream"
            break
        elif name == "PcRegisterSubdevice":
            driver_type = "PortCls"
            break
        else:
            continue
    if driver_type == "":
        print("[!] Unable to determine driver type; assuming WDM")
        # Only WDM drivers make it here so run all the WDM stuff
        driver_type = "WDM"
        real_driver_entry = check_for_fake_driver_entry(driver_entry_addr)
        real_ddc_addr = locate_ddc(real_driver_entry)
        if real_ddc_addr is not None:
            for ddc in real_ddc_addr.values():
                define_ddc(ddc)
        find_dispatch_function()
    return driver_type


def is_driver():
    """
    Determine if the loaded file is actually a Windows driver, check if `DriverEntry` is in the exports section.
    :return: address of `DriverEntry` if found in exports, False otherwise
    """

    for segment_address in idautils.Segments():
        for func_addr in idautils.Functions(idc.get_segm_start(segment_address), idc.get_segm_end(segment_address)):
            func_name = idc.get_func_name(func_addr)
            if func_name == "DriverEntry":
                return func_addr
    return False


def check_digits(n):
    """
    Given an integer number return how many digits it has
    :param n: number to check digits
    :return:
    """
    if n > 0:
        digits = int(math.log10(n)) + 1
    elif n == 0:
        digits = 1
    else:
        digits = int(math.log10(-n)) + 2  # +1 if you don't count the '-'
    return digits
