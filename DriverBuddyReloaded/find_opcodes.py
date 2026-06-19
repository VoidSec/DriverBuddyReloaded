"""
find_opcodes.py: search the database for desired opcodes / assembly statements.

Accepts opcodes and assembly statements separated by semicolons. Assembly
statements are assembled with idautils.Assemble; raw space-separated hex byte
strings (e.g. "0f 32") are used verbatim.

  find(rep, "wrmsr", x=True)            # executable segments only
  find(rep, "0f 32;asm_statement", ...)

Adapted from Hex-Rays' find-instruction sample (Copyright (c) Hex-Rays);
ported to the ida_compat search layer for IDA 7.x/8.4/9.0+.
"""

import re

import ida_funcs
import ida_idaapi
import ida_segment
import idautils

from DriverBuddyReloaded import config, ida_compat
from DriverBuddyReloaded.reporting import Finding
from DriverBuddyReloaded.vulnerable_functions_lists.opcode import *

# Prevent Driver Buddy Reloaded from reporting opcode matches in data sections
# (https://github.com/VoidSec/DriverBuddyReloaded/issues/11). Switch to True to
# surface raw byte matches too (more false positives).
find_opcode_data = False


def FindInstructions(instr, asm_where=None):
    """
    Assemble/parse `instr` and find every matching location.
    :return: tuple(True, [ea, ...]) or tuple(False, "error message")
    """

    if asm_where is None:
        seg = ida_segment.get_first_seg()
        asm_where = seg.start_ea if seg else ida_idaapi.BADADDR
        if asm_where == ida_idaapi.BADADDR:
            return False, "No segments defined"

    re_opcode = re.compile('^[0-9a-f]{2} *', re.I)
    bufs = []
    for line in instr.split(";"):
        if re_opcode.match(line):
            # hex byte string -> bytes
            bufs.append(bytes(bytearray(int(x, 16) for x in line.split())))
        else:
            ret, buf = idautils.Assemble(asm_where, line)
            if not ret:
                return False, "Failed to assemble: {}".format(line)
            bufs.append(buf)

    buf = b''.join(bufs)
    tlen = len(buf)
    bin_str = ' '.join("%02X" % b for b in buf)

    ea = ida_compat.min_ea()
    end = ida_compat.max_ea()
    ret = []
    while True:
        ea = ida_compat.bin_search(bin_str, ea, end, nocase=False)
        if ea == ida_compat.BADADDR:
            break
        ret.append(ea)
        ea += tlen
    if not ret:
        return False, "Could not match {} - [{}]".format(instr, bin_str)
    return True, ret


def find(rep, s=None, x=False, asm_where=None):
    """
    Search for an opcode/instruction and report matches as findings.
    :param rep: Reporter instance
    :param s: opcode/instruction string
    :param x: if True, restrict to executable segments only
    :param asm_where: where to assemble in (defaults to first segment)
    """

    ok, ret = FindInstructions(s, asm_where)
    if not ok:
        return
    for ea in ret:
        seg = ida_segment.getseg(ea)
        if x and ((not seg) or (seg.perm & ida_segment.SEGPERM_EXEC) == 0):
            continue
        text = ida_compat.disasm_text(ea)
        # Filter false positives: require the disassembly to contain a known opcode,
        # unless data-section matching has been explicitly enabled.
        if not find_opcode_data and not any(op in text for op in opcodes):
            continue
        func_or_seg = ida_funcs.get_func_name(ea) \
            or (ida_segment.get_segm_name(seg) if seg else "")
        rep.add(Finding(
            category="opcode",
            title=s,
            ea=ea,
            func=func_or_seg,
            severity=config.OPCODE_SEVERITY.get(s, config.SEV_MEDIUM),
            detail=text))
