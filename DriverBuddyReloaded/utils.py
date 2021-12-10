import math
import time
from datetime import date

import ida_nalt
import idautils
import idc
from DriverBuddyReloaded.vulnerable_functions_lists.c import *
from DriverBuddyReloaded.vulnerable_functions_lists.custom import *
from DriverBuddyReloaded.vulnerable_functions_lists.opcode import *
from DriverBuddyReloaded.vulnerable_functions_lists.winapi import *
from .find_opcodes import find
from .wdf import populate_wdf
from .wdm import check_for_fake_driver_entry, locate_ddc, define_ddc, find_dispatch_function

# Data structures needed to store addresses of functions we are interested in
functions_map = {}
imports_map = {}
c_map = {}
winapi_map = {}
driver_map = {}


def timestamp():
    """
    Return timestamp
    :return: 1552562387
    """
    return str(int(time.time()))


def today():
    """
    Return today date (Y-M-d)
    :return: 2019-03-12
    """
    return str(date.today())


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


def populate_data_structures(log_file):
    """
    Enumerate through the list of functions and load vulnerable functions found into a map.
    :param log_file: log file handler
    :return boolean: False if unable to enumerate functions, True otherwise
    """

    # print("[>] Populating IDA functions...")
    result = populate_function_map()
    # search for problematic opcodes; x=True search in executable segments only
    print("[>] Searching for interesting opcodes...")
    log_file.write("[>] Searching for interesting opcodes...\n")
    for opcode in opcodes:
        # x=True; search opcodes in executable code segments only
        find(log_file, opcode, x=True)
    if result is True:
        print("[>] Searching for interesting C/C++ functions...")
        log_file.write("[>] Searching for interesting C/C++ functions...\n")
        result = populate_c_map()
        if result is True:
            # Interesting C/C++ functions detected
            get_xrefs(c_map, log_file)
        # else:
        #    print("[-] No interesting C/C++ functions found")
        print("[>] Searching for interesting Windows APIs...")
        log_file.write("[>] Searching for interesting Windows APIs...\n")
        result = populate_winapi_map()
        if result is True:
            # Interesting Windows API functions detected
            get_xrefs(winapi_map, log_file)
        # else:
        #    print("[-] No interesting Windows API functions found")
        # do not search for custom driver's functions if the list is empty
        if len(driver_functions) > 0:
            print("[>] Searching for interesting driver functions...")
            log_file.write("[>] Searching for interesting driver functions...\n")
            result = populate_driver_map()
            if result is True:
                # Interesting driver functions detected
                get_xrefs(driver_map, log_file)
            # else:
            #    print("[-] No interesting specific driver functions found")
        return True
    else:
        print("[!] ERR: Couldn't populate function_map")
        log_file.write("[!] ERR: Couldn't populate function_map\n")
        return False


def get_xrefs(func_map, log_file):
    """
    Gets cross references to vulnerable functions stored in map.
    :param func_map: function map you want xrefs for
    :param log_file: log file handler
    :return:
    """

    for name, address in func_map.items():
        code_refs = idautils.CodeRefsTo(int(address), 0)
        for ref in code_refs:
            # xref = "0x%08x" % ref
            print("\t- Found {} at 0x{addr:08x}".format(name, addr=ref))
            log_file.write("\t- Found {} at 0x{addr:08x}\n".format(name, addr=ref))


def get_driver_id(driver_entry_addr, log_file):
    """
    Attempts to determine the type of the loaded driver by using functions found inside the imports section.
    :param driver_entry_addr: `DriverEntry` address
    :param log_file: log file handler
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
        log_file.write("[!] Unable to determine driver type; assuming WDM\n")
        # Only WDM drivers make it here so run all the WDM stuff
        driver_type = "WDM"
        real_driver_entry = check_for_fake_driver_entry(driver_entry_addr, log_file)
        real_ddc_addr = locate_ddc(real_driver_entry, log_file)
        if real_ddc_addr is not None:
            for ddc in real_ddc_addr.values():
                define_ddc(ddc)
        find_dispatch_function(log_file)
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
