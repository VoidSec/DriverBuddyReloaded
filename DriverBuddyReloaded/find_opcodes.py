"""
find_opcodes.py: search the database for desired opcodes / assembly statements.

Accepts opcodes and assembly statements separated by semicolons. Assembly
statements are assembled with idautils.Assemble; raw space-separated hex byte
strings (e.g. "0f 32") are used verbatim.

  find(rep, "wrmsr", exec_only=True)    # executable segments only
  find(rep, "0f 32;asm_statement", ...)

Adapted from Hex-Rays' find-instruction sample (Copyright (c) Hex-Rays);
ported to the ida_compat search layer for IDA 7.x/8.4/9.0+.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from DriverBuddyReloaded.reporting import Reporter

import ida_funcs
import ida_idaapi
import ida_segment
import idautils
import idc

from DriverBuddyReloaded import config, ida_compat
from DriverBuddyReloaded.reporting import Finding
from DriverBuddyReloaded.vulnerable_functions_lists.opcode import opcodes

# Prevent Driver Buddy Reloaded from reporting opcode matches in data sections
# (https://github.com/VoidSec/DriverBuddyReloaded/issues/11). Switch to True to
# surface raw byte matches too (more false positives).
find_opcode_data = False

# Pre-compiled pattern for recognising a hex-byte string (e.g. "0f 32").
_HEX_BYTE_RE = re.compile(r'^[0-9a-fA-F]{2}[ ]*', re.I)


def find_instructions(
    instr: str,
    asm_where: int | None = None,
) -> tuple[bool, list[int]] | tuple[bool, str]:
    """
    Assemble/parse `instr` and find every matching location.
    :return: tuple(True, [ea, ...]) or tuple(False, "error message")
    """

    if asm_where is None:
        seg = ida_segment.get_first_seg()
        asm_where = seg.start_ea if seg else ida_idaapi.BADADDR
        if asm_where == ida_idaapi.BADADDR:
            return False, "No segments defined"

    bufs = []
    for line in instr.split(";"):
        if _HEX_BYTE_RE.match(line):
            # hex byte string -> bytes
            bufs.append(bytes(bytearray(int(x, 16) for x in line.split())))
        else:
            asm_ok, line_bytes = idautils.Assemble(asm_where, line)
            if not asm_ok:
                return False, "Failed to assemble: {}".format(line)
            bufs.append(line_bytes)

    buf = b''.join(bufs)
    tlen = len(buf)
    bin_str = ' '.join("%02X" % b for b in buf)

    ea = ida_compat.min_ea()
    end = ida_compat.max_ea()
    matches = []
    while True:
        ea = ida_compat.bin_search(bin_str, ea, end, nocase=False)
        if ea == ida_compat.BADADDR:
            break
        matches.append(ea)
        ea += tlen
    if not matches:
        return False, "Could not match {} - [{}]".format(instr, bin_str)
    return True, matches


def linear_scan(rep: "Reporter") -> None:
    """
    Segment-wide linear instruction decode looking for OPCODE_SEVERITY members.

    This is largely redundant with the existing find(exec_only=True) binary-pattern
    search; it is provided as an opt-in alternative (config.Feature.SEGMENT_OPCODE_SCAN)
    for databases where the pattern search is unreliable (e.g. Thumb2 or mixed-mode).
    Disabled by default to avoid noisy duplicate findings.
    :param rep: Reporter instance
    """
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if not seg or not (seg.perm & ida_segment.SEGPERM_EXEC):
            continue
        ea = seg.start_ea
        while ea < seg.end_ea:
            disasm = ida_compat.disasm_text(ea)
            for opcode in config.OPCODE_SEVERITY:
                if opcode in disasm:
                    func_or_seg = ida_funcs.get_func_name(ea) \
                        or (ida_segment.get_segm_name(seg) if seg else "")
                    rep.add(Finding(
                        category="opcode",
                        title=opcode,
                        ea=ea,
                        func=func_or_seg,
                        severity=config.OPCODE_SEVERITY[opcode],
                        detail=disasm))
                    break
            nxt = idc.next_head(ea, seg.end_ea)
            if nxt <= ea:
                break
            ea = nxt


def find(rep: "Reporter", instruction: str | None = None, exec_only: bool = False, asm_where: int | None = None) -> None:
    """
    Search for an opcode/instruction and report matches as findings.
    :param rep: Reporter instance
    :param instruction: opcode/instruction string
    :param exec_only: if True, restrict to executable segments only
    :param asm_where: where to assemble in (defaults to first segment)
    """

    ok, result = find_instructions(instruction, asm_where)
    if not ok:
        return
    for ea in result:
        seg = ida_segment.getseg(ea)
        if exec_only and ((not seg) or (seg.perm & ida_segment.SEGPERM_EXEC) == 0):
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
            title=instruction,
            ea=ea,
            func=func_or_seg,
            severity=config.OPCODE_SEVERITY.get(instruction, config.SEV_MEDIUM),
            detail=text))
