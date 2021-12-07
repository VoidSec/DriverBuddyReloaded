import idaapi
import idautils
import idc

"""
WDM driver specific function calls.
"""


def check_for_fake_driver_entry(driver_entry_address):
    """
    Checks if DriverEntry in WDM driver is fake and try to recover the real one
    :param driver_entry_address: Autodetected address of `DriverEntry` function
    :return: real_driver_entry address
    """

    is64 = idaapi.get_inf_structure().is_64bit()
    address = idaapi.get_func(driver_entry_address)
    end_address = address.end_ea
    while idc.print_insn_mnem(end_address) != "jmp" and idc.print_insn_mnem(end_address) != "call":
        end_address -= 0x1
    # e.g print_operand(end_address, 0) = sub_11008
    real_driver_entry_address = idc.get_name_ea_simple(idc.print_operand(end_address, 0))
    # value auto switch based on driver's architecture
    if is64 is True:
        end_range = "0xffffffffffffffff"
    else:
        end_range = "0xffffffff"
    if hex(real_driver_entry_address) != end_range:
        print("[+] Found REAL `DriverEntry` address at 0x{addr:08x}".format(addr=real_driver_entry_address))
        idc.set_name(real_driver_entry_address, "Real_Driver_Entry")
        return real_driver_entry_address
    else:
        print("[!] Cannot find real `DriverEntry`; using IDA's one at 0x{addr:08x}".format(addr=driver_entry_address))
        return driver_entry_address


def locate_ddc(driver_entry_address):
    """
    Tries to automatically discover the `DispatchDeviceControl` in WDM drivers.
    Also looks for `DispatchInternalDeviceControl`. Has some experimental DDC searching
    :param driver_entry_address: Address of `DriverEntry` function found using check_for_fake_driver_entry.
    :return: dictionary containing `DispatchDeviceControl` and `DispatchInternalDeviceControl` addresses, None otherwise
    """

    driver_entry_func = list(idautils.FuncItems(driver_entry_address))
    # Offset to search for `DispatchDeviceControl` loaded into `DriverObject` struct
    ddc_offset = "+0E0h]"
    didc_offset = "+0E8h]"
    dispatch = {}
    # Enumerate the `DriverEntry` function and check if `DriverObject` struct loads address of `DispatchDeviceControl`
    prev_instruction = driver_entry_func[0]
    for i in driver_entry_func[1:]:
        if ddc_offset in idc.print_operand(i, 0)[4:] and idc.print_insn_mnem(prev_instruction) == "lea":
            real_ddc = idc.get_name_ea_simple(idc.print_operand(prev_instruction, 1))
            print("[+] Found `DispatchDeviceControl` at 0x{addr:08x}".format(addr=real_ddc))
            idc.set_name(real_ddc, "DispatchDeviceControl")
            dispatch["ddc"] = real_ddc
        if didc_offset in idc.print_operand(i, 0)[4:] and idc.print_insn_mnem(prev_instruction) == "lea":
            real_didc = idc.get_name_ea_simple(idc.print_operand(prev_instruction, 1))
            print("[+] Found `DispatchInternalDeviceControl` at 0x{addr:08x}".format(addr=real_didc))
            idc.set_name(real_didc, "DispatchInternalDeviceControl")
            dispatch["didc"] = real_didc
        prev_instruction = i

    # if we already have `DispatchDeviceControl` return it
    if "ddc" in dispatch:
        return dispatch
    # otherwise, try some experimental `DispatchDeviceControl` searching:
    # check for case where function is loading known `IO_STACK_LOCATION` & `IRP` addresses,
    # indicating it could be the `DispatchDeviceControl`.
    # probably going to give you false-positives
    print("[!] Unable to locate `DispatchDeviceControl`; using some experimental searching")
    ddc_list = []
    for f in idautils.Functions():
        # For each function, get list of all instructions
        instructions = list(idautils.FuncItems(f))
        iocode = "0xDEADB33F"  # no idea from where it come from
        iostack_location = "[rdx+0B8h]"
        for i in instructions:
            if iostack_location in idc.print_operand(i, 1):
                iostack_register = idc.print_operand(i, 0)
                iocode = "[" + iostack_register + "+18h]"
            if iocode in idc.GetDisasm(i):
                ddc_list.append(f)
    real_ddc = {}
    # Go through potential list of `DispatchDeviceControl` and see if they get called from `DriverEntry`,
    # if so, then it might be real deal
    for ddc in ddc_list:
        for count, refs in enumerate(idautils.XrefsTo(ddc, 0)):
            reffunc = idaapi.get_func(refs.frm)
            if reffunc is not None and reffunc.start_ea == driver_entry_address:
                real_ddc[count] = ddc
                print("[+] Possible `DispatchDeviceControl` at 0x{addr:08x}".format(addr=ddc))
                idc.set_name(ddc, "Possible_DispatchDeviceControl_{}".format(count))
    if real_ddc != {}:
        return real_ddc
    else:
        return None


def define_ddc(ddc_address):
    """
    Defines known structs in the `DispatchDeviceControl`
    :param ddc_address: Address of possible `DispatchDeviceControl`, found using locate_ddc.
    :return: None
    """

    # Special hidden IDA function to load "standard structures"
    irp_id = idc.import_type(-1, "IRP")
    io_stack_location_id = idc.import_type(-1, "IO_STACK_LOCATION")
    device_object_id = idc.import_type(-1, "DEVICE_OBJECT")
    # Register canaries
    io_stack_reg = "io_stack_reg"
    irp_reg = "irp_reg"
    device_object_reg = "device_object_reg"
    rdx_flag = 0
    rcx_flag = 0
    io_stack_flag = 0
    irp_reg_flag = 0
    # Get list of all instructions of DispatchDeviceControl function
    instructions = list(idautils.FuncItems(ddc_address))
    # Scan instructions until we discover RCX, or RDX register being used
    for i in instructions:
        disasm = idc.GetDisasm(i)
        src = idc.print_operand(i, 1)
        if "rdx" in disasm and rdx_flag != 1 or irp_reg in disasm and irp_reg_flag != 1:
            # Check for `IO_STACK_LOCATION`
            if "+0B8h" in disasm:
                if "rdx+0B8h" in src or irp_reg + "+0B8h" in src:
                    idc.op_stroff(i, 1, irp_id, 0)
                    # If it is a MOV, we want to save where `IO_STACK_LOCATION` is
                    if idc.print_insn_mnem(i) == "mov":
                        io_stack_reg = idc.print_operand(i, 0)
                        io_stack_flag = 0
                        # print("[+] Stored `IO_STACK_LOCATION` in {}".format(io_stack_reg))
                else:
                    idc.op_stroff(i, 0, irp_id, 0)
                # print("[+] Made struct `IO_STACK_LOCATION`")
            # Check for `SystemBuffer`
            elif "+18h" in disasm:
                if "rdx+18h" in src or irp_reg + "+18h" in src:
                    idc.op_stroff(i, 1, irp_id, 0)
                else:
                    idc.op_stroff(i, 0, irp_id, 0)
                # print("[+] Made struct `IRP + SystemBuffer`")
            # Check for `IoStatus.Information`
            elif "+38h" in disasm:
                if "rdx+38h" in src or irp_reg + "+38h" in src:
                    idc.op_stroff(i, 1, irp_id, 0)
                else:
                    idc.op_stroff(i, 0, irp_id, 0)
                # print("[+] Made struct `IRP + IoStatus.Information`")
            # Need to keep track of where `IRP` is being moved
            elif idc.print_insn_mnem(i) == "mov" and (src == "rdx" or src == irp_reg):
                irp_reg = idc.print_operand(i, 0)
                irp_reg_flag = 0
                # print("[+] Stored `IRP` in {}".format(irp_reg))
            # rdx got clobbered
            elif idc.print_insn_mnem(i) == "mov" and idc.print_operand(i, 0) == "rdx":
                # print("[+] RDX got clobbered: {}".format(GetDisasm(i)))
                rdx_flag = 1
            # irp_reg got clobbered
            elif idc.print_insn_mnem(i) == "mov" and idc.print_operand(i, 0) == irp_reg:
                # print("[+] IRP got clobbered: {}".format(GetDisasm(i)))
                irp_reg_flag = 1
            else:
                "[!] ERR: something weird happened {}".format(idc.GetDisasm(i))
        elif "rcx" in disasm and rcx_flag != 1:
            # Check for DEVICE_OBJECT.Extension
            if "rcx+40h" in disasm:
                if "rcx+40h" in src:
                    idc.op_stroff(i, 1, device_object_id, 0)
                else:
                    idc.op_stroff(i, 0, device_object_id, 0)
                # print("[+] Made struct `DEVICE_OBJECT.Extension`")
            # Need to keep track of where `DEVICE_OBJECT` is being moved
            elif idc.print_insn_mnem(i) == "mov" and src == "rcx":
                device_object_reg = idc.print_operand(i, 0)
                # print("[+] Stored `DEVICE_OBJECT` in {}".format(device_object_reg))
            # rcx got clobbered
            elif idc.print_insn_mnem(i) == "mov" and idc.print_operand(i, 0) == "rcx":
                # print("[+] RCX got clobbered: {}".format(GetDisasm(i)))
                rcx_flag = 1
        elif io_stack_reg in disasm and io_stack_flag != 1:
            # print("[+] io_stack_reg = {}; {}".format(io_stack_reg, GetDisasm(i)))
            # Check for `DeviceIoControlCode` which is `IO_STACK_LOCATION+18h`
            if io_stack_reg + "+18h" in disasm:
                if io_stack_reg + "+18h" in src:
                    idc.op_stroff(i, 1, io_stack_location_id, 0)
                else:
                    idc.op_stroff(i, 0, io_stack_location_id, 0)
                # print("[+] Made struct `IO_STACK_LOCATION + DeviceIoControlCode`")
            # Check for InputBufferLength which is `IO_STACK_LOCATION+10h`
            elif io_stack_reg in "+10h" in disasm:
                if io_stack_reg + "+10h" in src:
                    idc.op_stroff(i, 1, io_stack_location_id, 0)
                else:
                    idc.op_stroff(i, 1, io_stack_location_id, 0)
                # print("[+] Made struct `IO_STACK_LOCATION + InputBufferLength`")
            # Check for OutputBufferLength which is `IO_STACK_LOCATION+8`
            elif io_stack_reg + "+8" in disasm:
                if io_stack_reg + "+8" in src:
                    idc.op_stroff(i, 1, io_stack_location_id, 0)
                else:
                    idc.op_stroff(i, 0, io_stack_location_id, 0)
                # print("[+] Made struct `IO_STACK_LOCATION + OutputBufferLength`")
            # io_stack_reg is being clobbered
            elif idc.print_insn_mnem(i) == "mov" and idc.print_operand(i, 0) == io_stack_reg:
                io_stack_flag = 1
        else:
            continue
            # print("[+] nothing interesting in 0x{addr:08x}\nInstruction: {}".format(GetDisasm(i), addr=i))


def find_dispatch_by_struct_index():
    """
    Attempts to locate the dispatch function based off it being loaded in a structure
    at offset 70h, based off of https://github.com/kbandla/ImmunityDebugger/blob/master/1.73/Libs/driverlib.py
    """

    out = set()
    for function_ea in idautils.Functions():
        flags = idautils.idc.get_func_flags(function_ea)
        # skip library functions
        if flags & idautils.idc.FUNC_LIB:
            continue
        func = idaapi.get_func(function_ea)
        addr = func.start_ea
        while addr < func.end_ea:
            if idautils.idc.print_insn_mnem(addr) == 'mov':
                if '+70h' in idautils.idc.print_operand(addr, 0) and idautils.idc.get_operand_type(addr, 1) == 5:
                    out.add(idautils.idc.print_operand(addr, 1))
            addr = idautils.idc.next_head(addr)
    return out


def find_dispatch_by_cfg():
    """
    Finds the functions in the binary which are not directly called anywhere and counts how many other functions they call,
    returing all functions which call > 0 other functions but are not called themselves. As a dispatch function is not normally directly
    called but will normally many other functions this is a fairly good way to guess which function it is.
    """

    out = []
    called = set()
    caller = dict()
    # Loop through all the functions in the binary
    for function_ea in idautils.Functions():
        flags = idautils.idc.get_func_flags(function_ea)
        # skip library functions
        if flags & idautils.idc.FUNC_LIB:
            continue
        f_name = idautils.idc.get_func_name(function_ea)
        # For each of the incoming references
        for ref_ea in idautils.CodeRefsTo(function_ea, 0):
            called.add(f_name)
            # Get the name of the referring function
            caller_name = idautils.idc.get_func_name(ref_ea)
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


def find_dispatch_function():
    """
    Compares and processes results of `find_dispatch_by_struct_index` and `find_dispatch_by_cfg`
    to output potential dispatch function addresses
    """

    index_funcs = find_dispatch_by_struct_index()
    cfg_funcs = find_dispatch_by_cfg()
    if len(index_funcs) == 0:
        cfg_finds_to_print = min(len(cfg_funcs), 3)
        print("[>] Based off basic CFG analysis, potential dispatch functions are:")
        for i in range(cfg_finds_to_print):
            excluded_functions = ["__security_check_cookie", "start", "DriverEntry", "Real_Driver_Entry"]
            if cfg_funcs[i] not in excluded_functions:
                if cfg_funcs[i] != "" and cfg_funcs[i] is not None:
                    print("\t- {}".format(cfg_funcs[i]))
    elif len(index_funcs) == 1:
        func = index_funcs.pop()
        if func in cfg_funcs:
            print("[>] The likely dispatch function is: " + func)
        else:
            print("[>] Based off of the offset it is loaded at, a potential dispatch function is: {}".format(func))
            print("[>] Based off basic CFG analysis, the likely dispatch function is: {}".format(cfg_funcs[0]))
    else:
        print("[>] Potential dispatch functions:")
        for i in index_funcs:
            if i in cfg_funcs:
                print("\t- {}".format(i))
