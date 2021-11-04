import idaapi
import idc
from DriverBuddyReloaded import device_name_finder
from DriverBuddyReloaded import dump_pool_tags
from DriverBuddyReloaded import ioctl_decoder
from DriverBuddyReloaded import utils

"""
DriverBuddyReloaded.py: Entry point for IDA python plugin used in Windows driver vulnerability research.
Updated in 2021 by Paolo Stagno aka VoidSec: https://voidsec.com - https://twitter.com/Void_Sec
"""


class UiAction(idaapi.action_handler_t):
    """
    Simple wrapper class for creating action handlers which add options to menu's and are triggered via hot keys
    """

    def __init__(self, id, name, tooltip, menuPath, callback, shortcut):
        """
        :param id: id
        :param name: action name
        :param tooltip: action tooltip
        :param menuPath: where to register the action
        :param callback: function to execute
        :param shortcut: hot-keys to register
        """

        idaapi.action_handler_t.__init__(self)
        self.id = id
        self.name = name
        self.tooltip = tooltip
        self.menuPath = menuPath
        self.callback = callback
        self.shortcut = shortcut

    def registerAction(self):
        """
        Register an action which add an options to the menu's
        :return:
        """

        action_desc = idaapi.action_desc_t(
            self.id,
            self.name,
            self,
            self.shortcut,
            self.tooltip,
            0
        )
        if not idaapi.register_action(action_desc):
            return False
        if not idaapi.attach_action_to_menu(self.menuPath, self.id, 0):
            return False
        return True

    def unregisterAction(self):
        """
        Unregister an action which remove an options from the menu's
        :return:
        """

        idaapi.detach_action_from_menu(self.menuPath, self.id)
        idaapi.unregister_action(self.id)

    def activate(self, ctx):
        """
        :param ctx:
        :return:
        """

        self.callback()
        return 1

    def update(self, ctx):
        """
        :param ctx:
        :return:
        """

        return idaapi.AST_ENABLE_ALWAYS


def make_comment(pos, string):
    """
    Creates a comment with contents `string` at address `pos`.
    If the address is already commented append the new comment to the existing comment
    :param pos: position where to create the comment
    :param string: comment to write
    :return:
    """

    current_comment = idc.get_cmt(pos, 0)
    if not current_comment:
        idc.set_cmt(pos, string, 0)
    elif string not in current_comment:
        idc.set_cmt(pos, current_comment + " " + string, 0)


def get_operand_value(addr):
    """
    Returns the value of the second operand to the instruction at `addr` masked to be a 32 bit value
    :param addr: address to get the operand from
    :return:
    """

    return idc.get_operand_value(addr, 1) & 0xffffffff


class IOCTLTracker:
    """
    A simple container to keep track of decoded IOCTL codes and codes marked as invalid
    """

    def __init__(self):
        self.ioctl_locs = set()
        self.ioctls = []

    def add_ioctl(self, addr, value):
        """
        Add discovered IOCTL code to the list
        :param addr: address
        :param value: IOCTL code
        :return:
        """

        self.ioctl_locs.add(addr)
        self.ioctls.append((addr, value))

    def remove_ioctl(self, addr, value):
        """
        Remove discovered IOCTL code to the list
        :param addr: address
        :param value: IOCTL code
        :return:
        """

        self.ioctl_locs.remove(addr)
        self.ioctls.remove((addr, value))

    def print_table(self, ioctls):
        """
        Print table of decoded IOCTL codes
        :param ioctls: IOCTL to decode
        :return:
        """

        print("\nDriver Buddy Reloaded - IOCTLs\n"
              "-----------------------------------------------")
        print("%-10s | %-10s | %-42s | %-10s | %-22s | %s" % (
            "Address", "IOCTL Code", "Device", "Function", "Method", "Access"))
        for (addr, ioctl_code) in ioctls:
            function = ioctl_decoder.get_function(ioctl_code)
            device_name, device_code = ioctl_decoder.get_ioctl_code(ioctl_code)
            method_name, method_code = ioctl_decoder.get_method(ioctl_code)
            access_name, access_code = ioctl_decoder.get_access(ioctl_code)
            all_vars = (
                addr, ioctl_code, device_name, device_code, function, method_name, method_code, access_name,
                access_code)
            print("0x%-8X | 0x%-8X | %-31s 0x%-8X | 0x%-8X | %-17s %-4d | %s (%d)" % all_vars)


def find_all_ioctls():
    """
    From the currently selected address attempts to traverse all blocks inside the current function to find all
    immediate values which are used for a comparison/sub immediately before a jz. Returns a list of address, second operand pairs.
    :return:
    """

    ioctls = []
    # Find the currently selected function and get a list of all of it's basic blocks
    addr = idc.get_screen_ea()
    f = idaapi.get_func(addr)
    fc = idaapi.FlowChart(f, flags=idaapi.FC_PREDS)
    for block in fc:
        start = block.start_ea
        end = block.end_ea
        # print("Block: {} - {}".format(start, end))
        for instr in range(start, end):
            # if the penultimate instruction is cmp or sub or mov against an immediate value
            if idc.print_insn_mnem(instr) in ['cmp', 'sub', 'mov'] and idc.get_operand_type(instr, 1) == 5:
                value = get_operand_value(instr)
                digits = utils.check_digits(value)
                # value has 10 digits and is not a known NTSTATUS value
                if digits == 10 and value not in utils.ntstatus_values:
                    ioctls.append((instr, value))
                    ioctl_tracker.add_ioctl(instr, value)
    return ioctls


def track_ioctls(ioctls):
    """
    Decode and add an IOCTL code to the global table, generate the comments
    :param ioctls: IOCTL code
    :return:
    """

    global ioctl_tracker
    for addr, ioctl_code in ioctls:
        ioctl_tracker.add_ioctl(addr, ioctl_code)
        define = ioctl_decoder.get_define(ioctl_code)
        make_comment(addr, define)
    ioctl_tracker.print_table(ioctls)


def decode_all_ioctls():
    """
    Attempts to locate all the IOCTLs in a function and decode them all
    :return:
    """

    global ioctl_tracker
    ioctls = find_all_ioctls()
    track_ioctls(ioctls)


def get_position_and_translate():
    """
    Gets the current selected address and decodes the second parameter to the instruction if it exists/is an immediate
    then adds the C define for the code as a comment and prints a summary table of all decoded IOCTL codes.
    :return:
    """

    pos = idc.get_screen_ea()
    if idc.get_operand_type(pos, 1) != 5:  # Check the second operand to the instruction is an immediate
        return

    value = get_operand_value(pos)
    digits = utils.check_digits(value)
    if digits == 10 and value not in utils.ntstatus_values:
            ioctl_tracker.add_ioctl(pos, value)
            define = ioctl_decoder.get_define(value)
            make_comment(pos, define)
            # Print summary table each time a new IOCTL code is decoded
            ioctls = []
            for inst in ioctl_tracker.ioctl_locs:
                value = get_operand_value(inst)
                ioctls.append((inst, value))
            ioctl_tracker.print_table(ioctls)


class ActionHandler(idaapi.action_handler_t):
    """
    Basic wrapper class to avoid all action handlers needing to implement update identically
    """

    def update(self, ctx):
        """
        :param ctx:
        :return:
        """

        return idaapi.AST_ENABLE_ALWAYS


class DecodeHandler(ActionHandler):
    """
    Wrapper for `get_position_and_translate` used for right-click context menu hook
    """

    def activate(self, ctx):
        """
        :param ctx:
        :return:
        """

        get_position_and_translate()


class DecodeAllHandler(ActionHandler):
    """
    Wrapper for `decode_all_ioctls` used for right-click context menu hook
    """

    def activate(self, ctx):
        """
        :param ctx:
        :return:
        """

        decode_all_ioctls()


class InvalidHandler(ActionHandler):
    """
    Only available when right-clicking on an address marked as an IOCTL code location, removes it from the location list
    and deletes C define comment marking it (but leaves any other comment content at that location intact).
    """

    def activate(self, ctx):
        """
        :param ctx:
        :return:
        """

        pos = idc.get_screen_ea()
        # Get current comment for this instruction and remove the C define from it, if present
        comment = idc.get_cmt(pos, 0)
        code = get_operand_value(pos)
        define = ioctl_decoder.get_define(code)
        comment = comment.replace(define, "")
        idc.set_cmt(pos, comment, 0)
        # Remove the ioctl from the valid list and add it to the invalid list to avoid 'find_all_ioctls' accidently re-indexing it.
        ioctl_tracker.remove_ioctl(pos, code)


def register_dynamic_action(form, popup, description, handler):
    """
    Registers a new item in a popup which will trigger a function when selected
    :param form:
    :param popup:
    :param description:
    :param handler:
    :return:
    """

    # Note the 'None' as action name (1st parameter), that's because the action will be deleted immediately
    # after the context menu is hidden anyway, so there's no need giving it a valid ID.
    action = idaapi.action_desc_t(None, description, handler)
    idaapi.attach_dynamic_action_to_popup(form, popup, action, 'Driver Buddy Reloaded/')


class WinDriverHooks(idaapi.UI_Hooks):
    """
    Installs hook function which is triggered when popup forms are created
    and adds extra menu options if it is the right-click disasm view menu
    """

    def finish_populating_widget_popup(self, form, popup):
        """
        :param form:
        :param popup:
        :return:
        """

        if idaapi.get_widget_type(form) != idaapi.BWN_DISASM:
            return

        pos = idc.get_screen_ea()
        register_dynamic_action(form, popup, 'Decode All IOCTLs in Function', DecodeAllHandler())
        # If the second argument to the current selected instruction is an immediately
        # then give the option to decode it.
        if idc.get_operand_type(pos, 1) == 5:
            register_dynamic_action(form, popup, 'Decode IOCTL', DecodeHandler())
            if pos in ioctl_tracker.ioctl_locs:
                register_dynamic_action(form, popup, 'Invalid IOCTL', InvalidHandler())


class DriverBuddyPlugin(idaapi.plugin_t):
    """
    Main entry class for DriverBuddyPlugin
    """
    flags = idaapi.PLUGIN_UNL
    comment = ("Plugin to aid in Windows driver vulnerability research. " +
               "Automatically tries to find IOCTL handlers, decode IOCTLS, " +
               "flag dangerous C/C++ functions, find Windows imports for privilege escalation, " +
               "dump Pooltags and identify the type of Windows driver.")
    help = ""
    wanted_name = "Driver Buddy Reloaded"
    wanted_hotkey = "Ctrl+Alt+A"

    def init(self):
        """
        Define hooks and shortcut actions
        :return:
        """
        global ioctl_tracker
        ioctl_tracker = IOCTLTracker()
        global hooks
        hooks = WinDriverHooks()
        hooks.hook()
        decode_ioctl = UiAction(
            id="ioctl:decode",
            name="Decode IOCTL",
            tooltip="Decodes the currently selected constant into its IOCTL details.",
            menuPath="",
            shortcut="Ctrl+Alt+D",
            callback=get_position_and_translate
        )
        decode_ioctl.registerAction()
        decode_all_ioctl = UiAction(
            id="ioctl:decode_all",
            name="Decode ALL IOCTLs in a Function",
            tooltip="Decodes ALL IOCTLs in a Function into its IOCTL details.",
            menuPath="",
            shortcut="Ctrl+Alt+F",
            callback=decode_all_ioctls
        )
        decode_all_ioctl.registerAction()
        return idaapi.PLUGIN_KEEP

    def run(self, args):
        """
        Driver Buddy Reloaded Auto-analysis function
        :param args:
        :return:
        """
        print("\nDriver Buddy Reloaded Auto-analysis\n"
              "-----------------------------------------------")
        idc.auto_wait()  # Wait for IDA analysis to complete
        file_type = idaapi.get_file_type_name()
        if "portable executable" not in file_type.lower():
            print("[!] ERR: Loaded file is not a valid PE")
        else:
            driver_entry_addr = utils.is_driver()
            if driver_entry_addr is False:
                print("[!] ERR: Loaded file is not a Driver")
            else:
                print("[+] `DriverEntry` found at: 0x{addr:08x}".format(addr=driver_entry_addr))
                print("[>] Searching for `Device Names`...")
                device_name_finder.search()
                print("[>] Searching for `Pooltags`... ")
                pool = dump_pool_tags.get_all_pooltags()
                if pool:
                    print(pool)
                if utils.populate_data_structures() is True:
                    driver_type = utils.get_driver_id(driver_entry_addr)
                    print(("[+] Driver type detected: {}".format(driver_type)))
                    if ioctl_decoder.find_ioctls_dumb() is False:
                        print("[!] Unable to automatically find any IOCTLs")
                else:
                    print("[!] ERR: Unable to enumerate functions")
        print("[+] Analysis Completed!\n"
              "-----------------------------------------------")
        return

    def term(self):
        pass


def PLUGIN_ENTRY():
    return DriverBuddyPlugin()
