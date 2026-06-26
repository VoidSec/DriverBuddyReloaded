"""
wdf.py: WDF (KMDF/UMDF) driver analysis - WdfFunctions table discovery and struct labelling.

Identifies the mdfLibrary version string, resolves the matching WDFFUNCTIONS struct layout
from wdf_structs.py, creates the IDA struct definition, and applies it to WdfFunctions.

Inspired by http://redplait.blogspot.ru/2012/12/wdffunctionsidc.html
Originally by Nicolas Guigo; modified by Braden Hollembaek, Adam Pond and Paolo Stagno.
Ported to IDA 7.x/8.4/9.0+ via the ida_compat layer.
"""

from collections import namedtuple
from typing import Optional

import ida_bytes
import idaapi
import idc

from DriverBuddyReloaded import ida_compat
from . import wdf_structs

VersionInfo = namedtuple("VersionInfo", ['library', 'major', 'minor'])

MAJOR_VERSION_OFFSET = 0x0
MINOR_VERSION_OFFSET = 0x4
WDF_FUNCTIONS_OFFSET = 0x10
STRUCT_NAME = "WDFFUNCTIONS"


def add_struct(version: VersionInfo, rep: "Reporter") -> Optional[int]:
    """
    Define the WDFFUNCTIONS structure for the detected library/version.
    :param version: VersionInfo(library, major, minor)
    :param rep: Reporter instance
    :return: struct tid usable by ida_compat, or None on failure
    """

    if version.library not in wdf_structs.Wdfs:
        rep.info("[WDF] Bad mdfLibrary: {}".format(version.library))
        return None
    wdf_library = wdf_structs.Wdfs[version.library]
    if version.major not in wdf_library:
        rep.info("[WDF] Bad major version: {}".format(version.major))
        return None
    wdf_major = wdf_library[version.major]
    member_names = []
    for minor_revision in reversed(wdf_major.minors):
        if version.minor >= minor_revision.revision:
            member_names = wdf_major.names_list[:minor_revision.count]
            break
    if not member_names:
        rep.info("[WDF] No members for version %d.%d" % (version.major, version.minor))
        return None
    rep.info("[WDF] Creating struct for %s functions version %d.%d" % version)
    return ida_compat.create_named_struct(STRUCT_NAME, member_names)


def populate_wdf(rep: "Reporter") -> str:
    """
    Find and define the WDF driver's function table (WdfFunctions) and apply the
    WDFFUNCTIONS structure type to it.

    :param rep: Reporter instance
    :return str: "KMDF", "UMDF", or "WDF" based on the mdfLibrary prefix (issue #29)
    """

    ptr_size = ida_compat.ptr_size()
    detected_type = "WDF"
    _mdf_found = False
    # find candidate data sections
    segments = [idaapi.get_segm_by_name('.data'),
                idaapi.get_segm_by_name('.rdata'),
                idaapi.get_segm_by_name('NONPAGE')]
    for segm in segments:
        if segm is None:
            continue
        if segm.start_ea == ida_compat.BADADDR or segm.end_ea == ida_compat.BADADDR:
            continue
        # search the `mdfLibrary` UTF-16 string (K/U-mdfLibrary)
        idx = ida_compat.bin_search('L"mdfLibrary"', segm.start_ea, segm.end_ea)
        if idx == ida_compat.BADADDR:
            continue
        _mdf_found = True
        prefix_char = chr(ida_bytes.get_byte(idx - 2))
        actual_library = prefix_char + "mdfLibrary"
        # K-prefix = KMDF, U-prefix = UMDF
        if prefix_char == "K":
            detected_type = "KMDF"
        elif prefix_char == "U":
            detected_type = "UMDF"
        rep.info("[WDF] Found %s string at 0x%x (type: %s)" % (actual_library, idx - 2, detected_type))
        addr = idc.get_first_dref_to(idx - 2)
        version = VersionInfo(
            library=actual_library,
            major=idc.get_wide_dword(addr + ptr_size + MAJOR_VERSION_OFFSET),
            minor=idc.get_wide_dword(addr + ptr_size + MINOR_VERSION_OFFSET))
        tid = add_struct(version, rep)
        if tid is None:
            continue
        wdf_func = ida_compat.get_ptr(addr + ptr_size + WDF_FUNCTIONS_OFFSET)
        size = ida_compat.struct_size(tid)
        rep.info("[WDF] Applying struct (size=%s) at %s" % (hex(size), hex(wdf_func)))
        ida_bytes.del_items(wdf_func, 0, ptr_size)
        if ida_compat.apply_struct_ptr(wdf_func, STRUCT_NAME):
            idc.set_name(wdf_func, 'WdfFunctions_%s__%d_%d' % version, 0)
            rep.info("[WDF] Success")
        else:
            rep.info("[WDF] Failed to apply WDFFUNCTIONS type at %s" % hex(wdf_func))
    if not _mdf_found:
        rep.info("[!] WDF: mdfLibrary version string not found; driver classified as generic WDF")
    return detected_type
