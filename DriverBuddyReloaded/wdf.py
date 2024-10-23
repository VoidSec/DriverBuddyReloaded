import ida_bytes
import idaapi
import idc

from collections import namedtuple

VersionInfo = namedtuple("VersionInfo", ['library', 'major', 'minor'])

from . import wdf_structs

"""
Script to automatically identify WDF function pointers
Inspired by http://redplait.blogspot.ru/2012/12/wdffunctionsidc.html
Originally by Nicolas Guigo
Modified by Braden Hollembaek, Adam Pond and Paolo Stagno
"""

MAJOR_VERSION_OFFSET = 0x0
MINOR_VERSION_OFFSET = 0x4

WDF_FUNCTIONS_OFFSET = 0x10

STRUCT_NAME = "WDFFUNCTIONS"

def log(string):
    """
    Custom print function
    :param string:
    :return:
    """

    print('[WDF]: ' + string)


def add_struct(version):
    """
    Define IDA structure
    :param version:
    :return:
    """

    # globals auto switch based on driver's architecture
    # dependent globals
    is64 = idaapi.get_inf_structure().is_64bit()
    if is64 is True:
        FF_PTR = ida_bytes.FF_QWORD
        ptr_size = 8
    else:
        FF_PTR = ida_bytes.FF_DWORD
        ptr_size = 4
    
    id = -1
    # check for existing
    id = idc.get_struc_id(STRUCT_NAME)
    if id != -1:
        # delete old struc
        idc.del_struc(id)
    log('Creating struct for %s Functions version %d.%d' % version)
    idc.add_struc(-1, STRUCT_NAME, 0)
    id = idc.get_struc_id(STRUCT_NAME)
    if id != -1:
        def add_to_struct(func_name):
            idc.add_struc_member(id, func_name, idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        if version.library not in wdf_structs.Wdfs:
            log("Bad mdfLibrary")
            return -1
        wdf_library = wdf_structs.Wdfs[version.library]
        if version.major not in wdf_library:
            log("Bad major version")
            return -1
        wdf_major = wdf_library[version.major]
        for minor_revision in reversed(wdf_major.minors):
            if version.minor >= minor_revision.revision:
                for func_name in wdf_major.names_list[:minor_revision.count]:
                    add_to_struct(func_name)
                break
    return id


def populate_wdf():
    """
    Find and define WDF driver's structures
    :return:
    """

    # globals auto switch based on driver's architecture dependent globals
    is64 = idaapi.get_inf_structure().is_64bit()
    if is64 is True:
        get_ptr = idaapi.get_64bit
        ptr_size = 8
    else:
        get_ptr = idaapi.get_32bit
        ptr_size = 4
    # find data sections
    segments = [idaapi.get_segm_by_name('.data'), idaapi.get_segm_by_name('.rdata'), idaapi.get_segm_by_name('NONPAGE')]
    for segm in segments:
        if segm is None:
            continue
        if segm.start_ea != idc.BADADDR and segm.end_ea != idc.BADADDR:
            # search `mdfLibrary` unicode string in .rdata section
            binpat = idaapi.compiled_binpat_vec_t()
            ida_bytes.parse_binpat_str(binpat, 0, 'L"mdfLibrary"', 16)
            idx = ida_bytes.bin_search(segm.start_ea, segm.end_ea, binpat, ida_bytes.BIN_SEARCH_NOCASE)
            if idx != idaapi.BADADDR:
                actual_library = chr(ida_bytes.get_byte(idx-2)) + "mdfLibrary"
                log(("Found %s string at 0x%x") % (actual_library, idx - 2))
                addr = idc.get_first_dref_to(idx - 2)
                version = VersionInfo(
                    library=actual_library,
                    major=idc.get_wide_dword(addr + ptr_size + MAJOR_VERSION_OFFSET),
                    minor=idc.get_wide_dword(addr + ptr_size + MINOR_VERSION_OFFSET)
                )
                id = add_struct(version)
                if id != -1:
                    wdf_func = get_ptr(addr + ptr_size + WDF_FUNCTIONS_OFFSET)
                    size = idc.get_struc_size(id)
                    log('doStruct (size=' + hex(size) + ') at ' + hex(wdf_func))
                    ida_bytes.del_items(wdf_func, 0, ptr_size)
                    
                    if idc.set_name(wdf_func, 'WdfFunctions_%s__%d_%d' % version, 0) and idc.SetType(wdf_func, STRUCT_NAME + " *") != 0:
                        log('Success')
                    else:
                        log('Failure')
