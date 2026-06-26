"""
DriverBuddyReloaded.py: Entry point for the IDA Python plugin used in Windows driver vulnerability
research.  Created in 2021 by Paolo Stagno aka VoidSec: https://voidsec.com
Ported to IDA 7.6/8.4/9.0+ and extended with risk scoring, JSON/HTML reporting and PoC generation.

This module owns the plugin lifecycle (plugin_t, hotkeys, UI hooks, IOCTL tracker) and delegates
all analysis work to DriverBuddyReloaded.analysis.run_analysis().
"""

import idaapi
import ida_kernwin
import idc

from DriverBuddyReloaded import __version__
from DriverBuddyReloaded import analysis
from DriverBuddyReloaded import config
from DriverBuddyReloaded import ioctl_decoder
from DriverBuddyReloaded import reporting
from DriverBuddyReloaded import scoring

# Shared state, initialised in DriverBuddyPlugin.init()
ioctl_tracker = None
hooks = None
# Stored after each auto-analysis run so the IOCTL/findings windows can be
# re-opened at any time via the menu actions.
_last_rep = None
# Tracks the last shown chooser instances for live refresh after row deletion.
_last_ioctl_chooser = None


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
    # Anterior comment -- visible in the HexRays decompiler pseudocode view.
    existing_anterior = idc.get_extra_cmt(pos, idc.E_PREV + 0) or ""
    if string not in existing_anterior:
        idc.add_extra_cmt(pos, True, string)


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
        self.ioctl_locs.discard(addr)
        if (addr, value) in self.ioctls:
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
        except OSError as e:
            print("[!] ERR: can't save decoded IOCTLs to \"{}\": {}".format(path, e))


class IOCTLChooser(ida_kernwin.Choose):
    """
    Standalone IDA window listing decoded IOCTL codes with full field breakdown.
    Double-clicking a row jumps to the address where the IOCTL code appears.
    """

    def __init__(self, findings, rep=None, title="Driver Buddy Reloaded - IOCTLs"):
        ida_kernwin.Choose.__init__(
            self,
            title,
            [["Severity", 9], ["Address", 12], ["Code", 12],
             ["Device", 28], ["Method", 18], ["Access", 28], ["Fn#", 7], ["Sinks", 30]],
            flags=(getattr(ida_kernwin.Choose, "CH_CAN_REFRESH", 0) |
                   getattr(ida_kernwin.Choose, "CH_CAN_DEL", 0)))
        # Highest severity first.
        self._items = sorted(findings, key=lambda f: -f.severity)
        self._rep = rep

    @classmethod
    def from_pairs(cls, pairs):
        """Build from (address, code) tuples produced by the interactive decoder."""
        items = []
        for addr, code in pairs:
            d = ioctl_decoder.decode(code)
            sev, reasons = scoring.score_ioctl(d)
            d["risk_reasons"] = reasons
            items.append(reporting.Finding(
                category="ioctl",
                title="IOCTL 0x{:08X}".format(code),
                ea=addr,
                severity=sev,
                detail="{} / {} / {}".format(
                    d["device_name"], d["method_name"], d["access_name"]),
                data=d))
        return cls(items)

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        f = self._items[n]
        loc = "0x{:08x}".format(f.ea) if f.ea not in (None, reporting.BADADDR) else "-"
        d = f.data
        return [
            config.severity_name(f.severity),
            loc,
            "0x{:08X}".format(d.get("code", 0)) if d else "-",
            d.get("device_name", "") if d else "",
            d.get("method_name", "") if d else "",
            d.get("access_name", "") if d else "",
            str(d.get("function", "")) if d else "-",
            ", ".join(d.get("sinks", [])) if d else "",
        ]

    def OnSelectLine(self, n):
        f = self._items[n]
        if f.ea not in (None, reporting.BADADDR):
            ida_kernwin.jumpto(f.ea)

    def OnDeleteLine(self, n):
        removed = self._items.pop(n)
        if self._rep is not None:
            self._rep.remove_findings_at(removed.ea)
            self._rep.re_save()
        if removed.ea not in (None, reporting.BADADDR):
            idc.del_extra_cmt(removed.ea, idc.E_PREV + 0)
            idc.set_cmt(removed.ea, "", 0)
            code = removed.data.get("code") if removed.data else None
            if code is not None:
                ioctl_tracker.remove_ioctl(removed.ea, code)
        return [ida_kernwin.Choose.ALL_CHANGED, 0]

    def OnGetLineAttr(self, n):
        color = reporting._SEVERITY_COLORS.get(self._items[n].severity)
        if color is not None:
            return [color, 0]
        return None


def show_all_ioctls():
    """
    Open (or refresh) the IOCTLs chooser window.
    Prefers IOCTLs from the most recent auto-analysis; falls back to the
    interactive decode session (ioctl_tracker).
    """
    global _last_ioctl_chooser
    if _last_rep is not None:
        ioctls = _last_rep.by_category("ioctl")
        if ioctls:
            _last_ioctl_chooser = IOCTLChooser(ioctls, rep=_last_rep)
            _last_ioctl_chooser.Show()
            return
    if ioctl_tracker and ioctl_tracker.ioctls:
        _last_ioctl_chooser = IOCTLChooser.from_pairs(ioctl_tracker.ioctls)
        _last_ioctl_chooser.Show()
    else:
        print("[Driver Buddy Reloaded] No IOCTLs found yet. "
              "Run auto-analysis (Ctrl+Alt+A) or use 'Decode IOCTL' first.")


def show_findings():
    """Re-open the findings window from the most recent auto-analysis run."""
    if _last_rep is not None and _last_rep.findings:
        _last_rep.show_window()
    else:
        print("[Driver Buddy Reloaded] No findings yet. "
              "Run auto-analysis first (Ctrl+Alt+A).")


def find_all_ioctls():
    """
    From the currently selected address, traverse all blocks of the current function to find immediate
    values used in a comparison/sub/mov, returning a list of (address, value) pairs that look like IOCTLs.
    """

    ioctls = []
    addr = idc.get_screen_ea()
    f = idaapi.get_func(addr)
    if f is None:
        return []
    fc = idaapi.FlowChart(f, flags=idaapi.FC_PREDS)
    for block in fc:
        for instr in range(block.start_ea, block.end_ea):
            if idc.print_insn_mnem(instr) in ['cmp', 'sub', 'mov'] and idc.get_operand_type(instr, 1) == idc.o_imm:
                value = get_operand_value(instr)
                if ioctl_decoder._is_valid_ctl_code(value):
                    ioctls.append((instr, value))
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


def decode_ioctl_at_cursor():
    """
    Decode the immediate second operand of the currently selected instruction (if any), add the C-define
    comment and print a summary table of all decoded IOCTL codes.
    """

    pos = idc.get_screen_ea()
    if idc.get_operand_type(pos, 1) != idc.o_imm:  # second operand must be an immediate
        return
    value = get_operand_value(pos)
    if ioctl_decoder._is_valid_ctl_code(value):
        ioctl_tracker.add_ioctl(pos, value)
        make_comment(pos, ioctl_decoder.get_define(value))
        ioctls = [(inst, get_operand_value(inst)) for inst in ioctl_tracker.ioctl_locs]
        ioctl_tracker.print_table(ioctls)


class UiAction(idaapi.action_handler_t):
    """Wrapper for creating action handlers which add options to menus and are triggered via hot keys."""

    def __init__(self, action_id, name, tooltip, menu_path, callback, shortcut):
        idaapi.action_handler_t.__init__(self)
        self.action_id = action_id
        self.name = name
        self.tooltip = tooltip
        self.menu_path = menu_path
        self.callback = callback
        self.shortcut = shortcut

    def register_action(self):
        action_desc = idaapi.action_desc_t(self.action_id, self.name, self, self.shortcut, self.tooltip, 0)
        if not idaapi.register_action(action_desc):
            return False
        if not idaapi.attach_action_to_menu(self.menu_path, self.action_id, 0):
            return False
        return True

    def unregister_action(self):
        idaapi.detach_action_from_menu(self.menu_path, self.action_id)
        idaapi.unregister_action(self.action_id)

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
        decode_ioctl_at_cursor()


class DecodeAllHandler(ActionHandler):
    def activate(self, ctx):
        decode_all_ioctls()


class ShowAllIOCTLsHandler(ActionHandler):
    def activate(self, ctx):
        show_all_ioctls()


class ShowFindingsHandler(ActionHandler):
    def activate(self, ctx):
        show_findings()


class InvalidHandler(ActionHandler):
    """
    Removes an address marked as an IOCTL code location and deletes its C-define comment,
    leaving any other comment content at that location intact.
    """

    def activate(self, ctx):
        pos = idc.get_screen_ea()
        comment = idc.get_cmt(pos, 0) or ""
        code = get_operand_value(pos)
        define = ioctl_decoder.get_define(code)
        comment = comment.replace(define, "")
        idc.set_cmt(pos, comment, 0)
        idc.del_extra_cmt(pos, idc.E_PREV + 0)
        ioctl_tracker.remove_ioctl(pos, code)
        if _last_rep is not None:
            _last_rep.remove_findings_at(pos)
        if _last_ioctl_chooser is not None:
            _last_ioctl_chooser._items = [
                f for f in _last_ioctl_chooser._items if f.ea != pos
            ]
            _last_ioctl_chooser.Refresh()


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
        register_dynamic_action(form, popup, 'Show all IOCTLs', ShowAllIOCTLsHandler())
        register_dynamic_action(form, popup, 'Show Findings', ShowFindingsHandler())
        if idc.get_operand_type(pos, 1) == idc.o_imm:
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
            action_id="ioctl:decode",
            name="Decode IOCTL",
            tooltip="Decodes the currently selected constant into its IOCTL details.",
            menu_path="",
            shortcut="Ctrl+Alt+D",
            callback=decode_ioctl_at_cursor,
        ).register_action()
        UiAction(
            action_id="ioctl:decode_all",
            name="Decode ALL IOCTLs in a Function",
            tooltip="Decodes ALL IOCTLs in a Function into their IOCTL details.",
            menu_path="",
            shortcut="Ctrl+Alt+F",
            callback=decode_all_ioctls,
        ).register_action()
        UiAction(
            action_id="ioctl:show_all",
            name="Show all IOCTLs",
            tooltip="Open the IOCTLs table window (from last analysis or interactive session).",
            menu_path="",
            shortcut="Ctrl+Alt+I",
            callback=show_all_ioctls,
        ).register_action()
        UiAction(
            action_id="dbr:show_findings",
            name="Show Findings",
            tooltip="Re-open the Driver Buddy Reloaded findings window.",
            menu_path="",
            shortcut="Ctrl+Alt+W",
            callback=show_findings,
        ).register_action()
        print("[Driver Buddy Reloaded] v{} loaded (IDA SDK {}).".format(
            __version__, idaapi.IDA_SDK_VERSION))
        return idaapi.PLUGIN_KEEP

    def run(self, args):
        """Driver Buddy Reloaded auto-analysis entry point."""

        global _last_rep
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
            _last_rep = rep
            for f in rep.by_category("ioctl"):
                if f.ea not in (None, reporting.BADADDR) and f.data:
                    code = f.data.get("code")
                    if code is not None and f.ea not in ioctl_tracker.ioctl_locs:
                        make_comment(f.ea, ioctl_decoder.get_define(code))
                        ioctl_tracker.add_ioctl(f.ea, code)
            if config.Feature.RESULTS_WINDOW:
                # Findings window: all categories, severity-sorted.
                rep.show_window()
                # IOCTL recap window: decoded fields + severity for quick triage.
                ioctls = rep.by_category("ioctl")
                if ioctls:
                    global _last_ioctl_chooser
                    _last_ioctl_chooser = IOCTLChooser(ioctls, rep=rep)
                    _last_ioctl_chooser.Show()

    def term(self):
        pass


def PLUGIN_ENTRY():
    return DriverBuddyPlugin()
