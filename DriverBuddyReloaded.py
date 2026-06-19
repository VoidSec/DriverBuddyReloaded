"""
DriverBuddyReloaded.py: Entry point for the IDA Python plugin used in Windows driver vulnerability
research.  Created in 2021 by Paolo Stagno aka VoidSec: https://voidsec.com
Ported to IDA 7.6/8.4/9.0+ and extended with risk scoring, JSON/HTML reporting and PoC generation.

This module owns the plugin lifecycle (plugin_t, hotkeys, UI hooks, IOCTL tracker) and delegates
all analysis work to DriverBuddyReloaded.analysis.run_analysis().
"""

import idaapi
import idc

from DriverBuddyReloaded import analysis
from DriverBuddyReloaded import config
from DriverBuddyReloaded import ioctl_decoder
from DriverBuddyReloaded import reporting
from DriverBuddyReloaded import utils

# Shared state, initialised in DriverBuddyPlugin.init()
ioctl_tracker = None
hooks = None


def make_comment(pos, string):
    """
    Creates a comment with contents `string` at address `pos`.
    If the address is already commented append the new comment to the existing comment.
    :param pos: position where to create the comment
    :param string: comment to write
    """

    current_comment = idc.get_cmt(pos, 0)
    if not current_comment:
        idc.set_cmt(pos, string, 0)
    elif string not in current_comment:
        idc.set_cmt(pos, current_comment + " " + string, 0)


def get_operand_value(addr):
    """
    Returns the value of the second operand to the instruction at `addr` masked to a 32 bit value.
    :param addr: address to get the operand from
    """

    return idc.get_operand_value(addr, 1) & 0xffffffff


class IOCTLTracker:
    """A container to keep track of decoded IOCTL codes and codes marked as invalid."""

    def __init__(self):
        self.ioctl_locs = set()
        self.ioctls = []

    def add_ioctl(self, addr, value):
        self.ioctl_locs.add(addr)
        self.ioctls.append((addr, value))

    def remove_ioctl(self, addr, value):
        self.ioctl_locs.remove(addr)
        self.ioctls.remove((addr, value))

    def print_table(self, ioctls):
        """
        Print a table of decoded IOCTL codes and write the result to a file in the IDB directory.
        Rendering happens once; a file-write failure no longer duplicates the table.
        :param ioctls: list of (address, IOCTL code) tuples
        """

        lines = ["Driver Buddy Reloaded - IOCTLs",
                 "-----------------------------------------------",
                 ioctl_decoder.IOCTL_TABLE_HEADER]
        lines += [ioctl_decoder.format_row(addr, code) for (addr, code) in ioctls]
        text = "\n".join(lines)
        print("\n" + text)
        path = config.out_path("IOCTLs.txt")
        try:
            with open(path, "w", encoding="utf-8") as ioctl_file:
                ioctl_file.write(text + "\n")
            print("\n[>] Saved decoded IOCTLs to \"{}\"".format(path))
        except IOError as e:
            print("[!] ERR: can't save decoded IOCTLs to \"{}\": {}".format(path, e))


def find_all_ioctls():
    """
    From the currently selected address, traverse all blocks of the current function to find immediate
    values used in a comparison/sub/mov, returning a list of (address, value) pairs that look like IOCTLs.
    """

    ioctls = []
    addr = idc.get_screen_ea()
    f = idaapi.get_func(addr)
    fc = idaapi.FlowChart(f, flags=idaapi.FC_PREDS)
    for block in fc:
        for instr in range(block.start_ea, block.end_ea):
            if idc.print_insn_mnem(instr) in ['cmp', 'sub', 'mov'] and idc.get_operand_type(instr, 1) == 5:
                value = get_operand_value(instr)
                # value >= IOCTL_MIN_VALUE (lower false positives) and not a known NTSTATUS value (issue #15)
                if value >= config.IOCTL_MIN_VALUE and value not in ioctl_decoder._get_ntstatus_values():
                    ioctls.append((instr, value))
                    ioctl_tracker.add_ioctl(instr, value)
    return ioctls


def track_ioctls(ioctls):
    """Decode and add IOCTL codes to the global table, generating C-define comments."""

    for addr, ioctl_code in ioctls:
        ioctl_tracker.add_ioctl(addr, ioctl_code)
        make_comment(addr, ioctl_decoder.get_define(ioctl_code))
    ioctl_tracker.print_table(ioctls)


def decode_all_ioctls():
    """Locate all IOCTLs in the current function and decode them."""

    track_ioctls(find_all_ioctls())


def get_position_and_translate():
    """
    Decode the immediate second operand of the currently selected instruction (if any), add the C-define
    comment and print a summary table of all decoded IOCTL codes.
    """

    pos = idc.get_screen_ea()
    if idc.get_operand_type(pos, 1) != 5:  # second operand must be an immediate
        return
    value = get_operand_value(pos)
    # value >= IOCTL_MIN_VALUE (lower false positives) and not a known NTSTATUS value (issue #15)
    if value >= config.IOCTL_MIN_VALUE and value not in ioctl_decoder._get_ntstatus_values():
        ioctl_tracker.add_ioctl(pos, value)
        make_comment(pos, ioctl_decoder.get_define(value))
        ioctls = [(inst, get_operand_value(inst)) for inst in ioctl_tracker.ioctl_locs]
        ioctl_tracker.print_table(ioctls)


class UiAction(idaapi.action_handler_t):
    """Wrapper for creating action handlers which add options to menus and are triggered via hot keys."""

    def __init__(self, id, name, tooltip, menuPath, callback, shortcut):
        idaapi.action_handler_t.__init__(self)
        self.id = id
        self.name = name
        self.tooltip = tooltip
        self.menuPath = menuPath
        self.callback = callback
        self.shortcut = shortcut

    def registerAction(self):
        action_desc = idaapi.action_desc_t(self.id, self.name, self, self.shortcut, self.tooltip, 0)
        if not idaapi.register_action(action_desc):
            return False
        if not idaapi.attach_action_to_menu(self.menuPath, self.id, 0):
            return False
        return True

    def unregisterAction(self):
        idaapi.detach_action_from_menu(self.menuPath, self.id)
        idaapi.unregister_action(self.id)

    def activate(self, ctx):
        self.callback()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class ActionHandler(idaapi.action_handler_t):
    """Wrapper class so action handlers don't each re-implement update()."""

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class DecodeHandler(ActionHandler):
    def activate(self, ctx):
        get_position_and_translate()


class DecodeAllHandler(ActionHandler):
    def activate(self, ctx):
        decode_all_ioctls()


class InvalidHandler(ActionHandler):
    """
    Removes an address marked as an IOCTL code location and deletes its C-define comment,
    leaving any other comment content at that location intact.
    """

    def activate(self, ctx):
        pos = idc.get_screen_ea()
        comment = idc.get_cmt(pos, 0)
        code = get_operand_value(pos)
        define = ioctl_decoder.get_define(code)
        comment = comment.replace(define, "")
        idc.set_cmt(pos, comment, 0)
        ioctl_tracker.remove_ioctl(pos, code)


def register_dynamic_action(form, popup, description, handler):
    """Registers a transient popup item which triggers `handler` when selected."""

    action = idaapi.action_desc_t(None, description, handler)
    idaapi.attach_dynamic_action_to_popup(form, popup, action, 'Driver Buddy Reloaded/')


class WinDriverHooks(idaapi.UI_Hooks):
    """Adds Driver Buddy Reloaded options to the disassembly right-click menu."""

    def finish_populating_widget_popup(self, form, popup):
        if idaapi.get_widget_type(form) != idaapi.BWN_DISASM:
            return
        pos = idc.get_screen_ea()
        register_dynamic_action(form, popup, 'Decode All IOCTLs in Function', DecodeAllHandler())
        if idc.get_operand_type(pos, 1) == 5:
            register_dynamic_action(form, popup, 'Decode IOCTL', DecodeHandler())
            if pos in ioctl_tracker.ioctl_locs:
                register_dynamic_action(form, popup, 'Invalid IOCTL', InvalidHandler())


class DriverBuddyPlugin(idaapi.plugin_t):
    """Main entry class for Driver Buddy Reloaded."""

    flags = idaapi.PLUGIN_UNL
    comment = ("Plugin to aid in Windows driver vulnerability research. "
               "Automatically tries to find IOCTL handlers, decode IOCTLs, "
               "flag dangerous C/C++ functions, find Windows imports for privilege escalation, "
               "dump Pooltags and identify the type of Windows driver.")
    help = ""
    wanted_name = "Driver Buddy Reloaded"
    wanted_hotkey = "Ctrl+Alt+A"

    def init(self):
        """Define hooks and shortcut actions."""

        global ioctl_tracker, hooks
        ioctl_tracker = IOCTLTracker()
        hooks = WinDriverHooks()
        hooks.hook()
        UiAction(
            id="ioctl:decode",
            name="Decode IOCTL",
            tooltip="Decodes the currently selected constant into its IOCTL details.",
            menuPath="",
            shortcut="Ctrl+Alt+D",
            callback=get_position_and_translate,
        ).registerAction()
        UiAction(
            id="ioctl:decode_all",
            name="Decode ALL IOCTLs in a Function",
            tooltip="Decodes ALL IOCTLs in a Function into their IOCTL details.",
            menuPath="",
            shortcut="Ctrl+Alt+F",
            callback=decode_all_ioctls,
        ).registerAction()
        print("[Driver Buddy Reloaded] Loaded (IDA SDK {}).".format(idaapi.IDA_SDK_VERSION))
        return idaapi.PLUGIN_KEEP

    def run(self, args):
        """Driver Buddy Reloaded auto-analysis entry point."""

        idc.auto_wait()  # wait for IDA's own analysis to complete
        # Fresh timestamp so all output artefacts for this run share one stamp.
        config._run_stamp = None
        rep = reporting.Reporter(config.out_path("autoanalysis.txt"))
        rep.info("Driver Buddy Reloaded Auto-analysis")
        rep.info("-----------------------------------------------")
        try:
            analysis.run_analysis(rep)
        finally:
            rep.close()
            if config.Feature.RESULTS_WINDOW:
                rep.show_window()

    def term(self):
        pass


def PLUGIN_ENTRY():
    return DriverBuddyPlugin()
