"""
wdm.py: WDM driver specific function calls.
Ported to IDA 7.x/8.4/9.0+ via the ida_compat layer.
"""

import idaapi
import idautils
import idc

from DriverBuddyReloaded import ida_compat

# DRIVER_OBJECT.MajorFunction slot offsets matched against IDA-printed operands.
_DDC_OFFSET = "+0E0h]"            # MajorFunction[IRP_MJ_DEVICE_CONTROL]
_DIDC_OFFSET = "+0E8h]"           # MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL]
_IRP_IOSTACK_OFFSET = "[rdx+0B8h]"  # IRP.Tail.Overlay.CurrentStackLocation
_DISPATCH_ARRAY_SLOT = "+70h"     # DRIVER_OBJECT.MajorFunction base offset


def check_for_fake_driver_entry(driver_entry_address, rep):
    """
    Checks if DriverEntry in WDM driver is fake and try to recover the real one
    :param driver_entry_address: Autodetected address of `DriverEntry` function
    :param rep: Reporter instance
    :return: real_driver_entry address
    """

    address = idaapi.get_func(driver_entry_address)
    end_address = address.end_ea
    MAX_WALK = 256
    _walk_count = 0
    while idc.print_insn_mnem(end_address) != "jmp" and idc.print_insn_mnem(end_address) != "call":
        end_address -= 0x1
        _walk_count += 1
        if _walk_count >= MAX_WALK:
            break
    # e.g print_operand(end_address, 0) = sub_11008
    real_driver_entry_address = idc.get_name_ea_simple(idc.print_operand(end_address, 0))
    if real_driver_entry_address not in (ida_compat.BADADDR, idaapi.BADADDR):
        rep.info("[+] Found REAL `DriverEntry` address at 0x{addr:08x}".format(addr=real_driver_entry_address))
        idc.set_name(real_driver_entry_address, "Real_Driver_Entry")
        return real_driver_entry_address
    rep.info("[!] Cannot find real `DriverEntry`; using IDA's one at 0x{addr:08x}".format(addr=driver_entry_address))
    return driver_entry_address


def locate_ddc(driver_entry_address, rep):
    """
    Tries to automatically discover the `DispatchDeviceControl` in WDM drivers.
    Also looks for `DispatchInternalDeviceControl`. Has some experimental DDC searching.
    :param driver_entry_address: Address of `DriverEntry` found using check_for_fake_driver_entry.
    :param rep: Reporter instance
    :return: dict with `DispatchDeviceControl`/`DispatchInternalDeviceControl` addresses, or None
    """

    driver_entry_func = list(idautils.FuncItems(driver_entry_address))
    dispatch = {}
    prev_instruction = driver_entry_func[0]
    for i in driver_entry_func[1:]:
        if _DDC_OFFSET in idc.print_operand(i, 0)[4:] and idc.print_insn_mnem(prev_instruction) == "lea":
            real_ddc = idc.get_name_ea_simple(idc.print_operand(prev_instruction, 1))
            if real_ddc != ida_compat.BADADDR:
                rep.info("[+] Found `DispatchDeviceControl` at 0x{addr:08x}".format(addr=real_ddc))
                idc.set_name(real_ddc, "DispatchDeviceControl")
                dispatch["ddc"] = real_ddc
        if _DIDC_OFFSET in idc.print_operand(i, 0)[4:] and idc.print_insn_mnem(prev_instruction) == "lea":
            real_didc = idc.get_name_ea_simple(idc.print_operand(prev_instruction, 1))
            rep.info("[+] Found `DispatchInternalDeviceControl` at 0x{addr:08x}".format(addr=real_didc))
            idc.set_name(real_didc, "DispatchInternalDeviceControl")
            dispatch["didc"] = real_didc
        prev_instruction = i

    # if we already have `DispatchDeviceControl` return it
    if "ddc" in dispatch:
        return dispatch
    # otherwise, try some experimental `DispatchDeviceControl` searching: look for a function
    # loading known `IO_STACK_LOCATION` & `IRP` addresses. Prone to false-positives.
    rep.info("[!] Unable to locate `DispatchDeviceControl`; using some experimental searching")
    ddc_list = []
    for f in idautils.Functions():
        instructions = list(idautils.FuncItems(f))
        iocode = "0xDEADB33F"
        for i in instructions:
            if _IRP_IOSTACK_OFFSET in idc.print_operand(i, 1):
                iostack_register = idc.print_operand(i, 0)
                iocode = "[" + iostack_register + "+18h]"
            if iocode in ida_compat.disasm_text(i):
                ddc_list.append(f)
    real_ddc = {}
    # Keep only candidates that are called from `DriverEntry`.
    for ddc in ddc_list:
        for count, refs in enumerate(idautils.XrefsTo(ddc, 0)):
            reffunc = idaapi.get_func(refs.frm)
            if reffunc is not None and reffunc.start_ea == driver_entry_address:
                real_ddc[count] = ddc
                rep.info("[+] Possible `DispatchDeviceControl` at 0x{addr:08x}".format(addr=ddc))
                idc.set_name(ddc, "Possible_DispatchDeviceControl_{}".format(count))
    return real_ddc or None


def define_ddc(ddc_address, rep):
    """
    Defines known structs (IRP, IO_STACK_LOCATION, DEVICE_OBJECT) in `DispatchDeviceControl`.
    :param ddc_address: Address of a possible `DispatchDeviceControl`, found using locate_ddc.
    :param rep: Reporter instance
    """

    irp_id = ida_compat.import_std_type("IRP")
    io_stack_location_id = ida_compat.import_std_type("IO_STACK_LOCATION")
    device_object_id = ida_compat.import_std_type("DEVICE_OBJECT")
    if irp_id is None and io_stack_location_id is None and device_object_id is None:
        rep.info("[!] WDM types (IRP/IO_STACK_LOCATION/DEVICE_OBJECT) unavailable; skipping struct labelling")
        return
    # Register canaries
    io_stack_reg = "io_stack_reg"
    irp_reg = "irp_reg"
    device_object_reg = "device_object_reg"
    rdx_flag = 0
    rcx_flag = 0
    io_stack_flag = 0
    irp_reg_flag = 0
    for i in idautils.FuncItems(ddc_address):
        disasm = ida_compat.disasm_text(i)
        src = idc.print_operand(i, 1)
        if "rdx" in disasm and rdx_flag != 1 or irp_reg in disasm and irp_reg_flag != 1:
            # `IO_STACK_LOCATION` (IRP + 0B8h)
            if "+0B8h" in disasm:
                if "rdx+0B8h" in src or irp_reg + "+0B8h" in src:
                    ida_compat.op_struct_offset(i, 1, irp_id)
                    if idc.print_insn_mnem(i) == "mov":
                        io_stack_reg = idc.print_operand(i, 0)
                        io_stack_flag = 0
                else:
                    ida_compat.op_struct_offset(i, 0, irp_id)
            # `IRP + SystemBuffer` (IRP + 18h)
            elif "+18h" in disasm:
                if "rdx+18h" in src or irp_reg + "+18h" in src:
                    ida_compat.op_struct_offset(i, 1, irp_id)
                else:
                    ida_compat.op_struct_offset(i, 0, irp_id)
            # `IRP + IoStatus.Information` (IRP + 38h)
            elif "+38h" in disasm:
                if "rdx+38h" in src or irp_reg + "+38h" in src:
                    ida_compat.op_struct_offset(i, 1, irp_id)
                else:
                    ida_compat.op_struct_offset(i, 0, irp_id)
            # track where `IRP` is being moved
            elif idc.print_insn_mnem(i) == "mov" and (src == "rdx" or src == irp_reg):
                irp_reg = idc.print_operand(i, 0)
                irp_reg_flag = 0
            # rdx got clobbered
            elif idc.print_insn_mnem(i) == "mov" and idc.print_operand(i, 0) == "rdx":
                rdx_flag = 1
            # irp_reg got clobbered
            elif idc.print_insn_mnem(i) == "mov" and idc.print_operand(i, 0) == irp_reg:
                irp_reg_flag = 1
        elif "rcx" in disasm and rcx_flag != 1:
            # DEVICE_OBJECT.Extension (rcx + 40h)
            if "rcx+40h" in disasm:
                if "rcx+40h" in src:
                    ida_compat.op_struct_offset(i, 1, device_object_id)
                else:
                    ida_compat.op_struct_offset(i, 0, device_object_id)
            # track where `DEVICE_OBJECT` is being moved
            elif idc.print_insn_mnem(i) == "mov" and src == "rcx":
                device_object_reg = idc.print_operand(i, 0)
            # rcx got clobbered
            elif idc.print_insn_mnem(i) == "mov" and idc.print_operand(i, 0) == "rcx":
                rcx_flag = 1
        elif io_stack_reg in disasm and io_stack_flag != 1:
            # `IO_STACK_LOCATION + DeviceIoControlCode` (+18h)
            if io_stack_reg + "+18h" in disasm:
                if io_stack_reg + "+18h" in src:
                    ida_compat.op_struct_offset(i, 1, io_stack_location_id)
                else:
                    ida_compat.op_struct_offset(i, 0, io_stack_location_id)
            # `IO_STACK_LOCATION + InputBufferLength` (+10h)
            elif io_stack_reg + "+10h" in disasm:
                if io_stack_reg + "+10h" in src:
                    ida_compat.op_struct_offset(i, 1, io_stack_location_id)
                else:
                    ida_compat.op_struct_offset(i, 0, io_stack_location_id)
            # `IO_STACK_LOCATION + OutputBufferLength` (+8)
            elif io_stack_reg + "+8" in disasm:
                if io_stack_reg + "+8" in src:
                    ida_compat.op_struct_offset(i, 1, io_stack_location_id)
                else:
                    ida_compat.op_struct_offset(i, 0, io_stack_location_id)
            # io_stack_reg is being clobbered
            elif idc.print_insn_mnem(i) == "mov" and idc.print_operand(i, 0) == io_stack_reg:
                io_stack_flag = 1


def find_dispatch_by_struct_index():
    """
    Attempts to locate the dispatch function based off it being loaded in a structure
    at offset 70h, based off of
    https://github.com/kbandla/ImmunityDebugger/blob/master/1.73/Libs/driverlib.py
    """

    out = set()
    for function_ea in idautils.Functions():
        flags = idc.get_func_flags(function_ea)
        if flags & idc.FUNC_LIB:  # skip library functions
            continue
        func = idaapi.get_func(function_ea)
        addr = func.start_ea
        while addr < func.end_ea:
            if idc.print_insn_mnem(addr) == 'mov':
                if _DISPATCH_ARRAY_SLOT in idc.print_operand(addr, 0) and idc.get_operand_type(addr, 1) == 5:
                    out.add(idc.print_operand(addr, 1))
            addr = idc.next_head(addr)
    return out


def find_dispatch_by_cfg():
    """
    Finds functions which are not directly called anywhere and counts how many other
    functions they call, returning all functions which call > 0 other functions but are
    not called themselves - a fairly good guess for the dispatch function.
    """

    out = []
    called = set()
    caller = dict()
    for function_ea in idautils.Functions():
        flags = idc.get_func_flags(function_ea)
        if flags & idc.FUNC_LIB:  # skip library functions
            continue
        f_name = idc.get_func_name(function_ea)
        for ref_ea in idautils.CodeRefsTo(function_ea, 0):
            called.add(f_name)
            caller_name = idc.get_func_name(ref_ea)
            if caller_name not in caller.keys():
                caller[caller_name] = 1
            else:
                caller[caller_name] += 1
    while True:
        if len(caller.keys()) == 0:
            break
        potential = max(caller, key=caller.get)
        if potential not in called:
            out.append(potential)
        del caller[potential]
    return out


def find_dispatch_function(rep):
    """
    Compares and processes results of `find_dispatch_by_struct_index` and
    `find_dispatch_by_cfg` to output potential dispatch function addresses.
    :param rep: Reporter instance
    :return: list of resolved EAs for the selected candidates
    """

    index_funcs = find_dispatch_by_struct_index()
    cfg_funcs = find_dispatch_by_cfg()
    excluded_functions = [
        "__security_check_cookie", "start", "DriverEntry", "Real_Driver_Entry",
        "__GSHandlerCheck_SEH", "GsDriverEntry",
        "_guard_xfg_dispatch_icall_nop", "_guard_xfg_dispatch_icall",
        "_guard_dispatch_icall_nop", "_guard_dispatch_icall",
    ]
    candidates = []
    if len(index_funcs) == 0:
        cfg_finds_to_print = min(len(cfg_funcs), 3)
        rep.info("[>] Based off basic CFG analysis, potential dispatch functions are:")
        for i in range(cfg_finds_to_print):
            if cfg_funcs[i] and cfg_funcs[i] not in excluded_functions:
                rep.info("\t- {}".format(cfg_funcs[i]))
                candidates.append(cfg_funcs[i])
    elif len(index_funcs) == 1:
        func = index_funcs.pop()
        if func in cfg_funcs:
            rep.info("[>] The likely dispatch function is: {}".format(func))
            candidates.append(func)
        else:
            rep.info("[>] Based off the offset it is loaded at, a potential dispatch function is: {}".format(func))
            candidates.append(func)
            if cfg_funcs:
                rep.info("[>] Based off basic CFG analysis, the likely dispatch function is: {}".format(cfg_funcs[0]))
                candidates.append(cfg_funcs[0])
    else:
        rep.info("[>] Potential dispatch functions:")
        for i in index_funcs:
            if i in cfg_funcs:
                rep.info("\t- {}".format(i))
                candidates.append(i)

    eas = []
    for name in candidates:
        ea = idc.get_name_ea_simple(name)
        if ea not in (None, ida_compat.BADADDR):
            eas.append(ea)
    return eas
