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


def _operand_targets_offset(op_text, offset_tag):
    """True when a destination operand string stores into a struct slot at
    `offset_tag` (e.g. '+0E0h]'), independent of the base-register width.

    The previous code sliced a fixed 4-char '[reg' prefix off the operand before
    the substring test, which silently failed for 2-char base registers:
    '[r8+0E0h]'[4:] == '0E0h]' drops the leading '+', so the tag '+0E0h]' no
    longer matched and the DDC store went undetected.  The tag already includes
    the trailing ']', so testing it against the whole operand is both simpler and
    width-independent.
    """
    return offset_tag in (op_text or "")


def references_iocontrolcode(func_ea):
    """True when *func_ea* loads the IO_STACK_LOCATION from the IRP (IRP+0B8h) and
    then reads the control code at iostack+18h.

    This is the structural signature of an IRP_MJ_DEVICE_CONTROL dispatcher.  It
    corroborates CFG-guessed dispatch candidates (so statically-linked library /
    CRT helpers such as SepSddlGetAclForString or __GSHandlerCheckCommon are not
    mistaken for dispatchers) and gates the low-precision immediate-operand IOCTL
    scan so it never mines a non-dispatcher's internal constants.

    The iostack load is recognised by its *offset*, not by member-name text: the
    same `mov reg, [irp+0B8h]` renders as `[rdx+0B8h]` on a pristine database but
    as `[rdx+(IRP.Tail+40h)]` once the IRP struct type is applied (issue #41).
    """

    _IRP_STACK_OFFSET = 0xB8  # IRP.Tail.Overlay.CurrentStackLocation, x64
    try:
        items = list(idautils.FuncItems(func_ea))
    except Exception:
        return False
    iostack_read = "0xDEADB33F"  # sentinel that cannot appear before an iostack load
    saw_iostack = False
    for i in items:
        try:
            disasm = ida_compat.disasm_text(i) or ""
            # Annotated form (database already carries IRP / IO_STACK_LOCATION
            # struct types, e.g. from a prior run): the operands render as struct
            # fields.  "IoControlCode" is the decisive one; "CurrentStackLocation"
            # is the iostack load.
            if "IoControlCode" in disasm:
                return True
            if "CurrentStackLocation" in disasm:
                saw_iostack = True
            # Structural form: a register load from [reg+0B8h], regardless of how
            # IDA renders the member path (raw offset, "(IRP.Tail+40h)", ...).
            # Operand 0 must be a register so a *store* into [x+0B8h] is not
            # mistaken for the load.
            if (idc.print_insn_mnem(i) == "mov"
                    and idc.get_operand_type(i, 0) == idc.o_reg
                    and idc.get_operand_type(i, 1) == idc.o_displ
                    and (idc.get_operand_value(i, 1) & 0xFFFFFFFF) == _IRP_STACK_OFFSET):
                saw_iostack = True
                iostack_reg = idc.print_operand(i, 0)
                if iostack_reg:
                    iostack_read = "[" + iostack_reg + "+18h]"
            # Raw form (pristine database): IRP.Tail.Overlay.CurrentStackLocation
            # load dst reg <- [irp+0B8h], then the control code at [iostack+18h].
            if "+0B8h" in disasm:
                saw_iostack = True
                iostack_reg = idc.print_operand(i, 0)
                if iostack_reg:
                    iostack_read = "[" + iostack_reg + "+18h]"
            # +18h control-code read is the strongest raw signal; the iostack load
            # alone is already a strong dispatcher hallmark, so accept it too
            # (lenient enough not to drop a real dispatcher whose control-code read
            # uses a forwarded register).
            if iostack_read in disasm:
                return True
        except Exception:
            continue
    return saw_iostack


def _resolve_store_target(store_ea, prev_ea):
    """Resolve the handler address stored into a MajorFunction slot.

    Handles the two shapes compilers emit:
      lea rax, Handler / mov [reg+0E0h], rax    (target on the previous `lea`)
      mov [reg+0E0h], offset Handler            (target is the store's own source)
    Returns the handler function EA or None.
    """
    _BAD = (None, ida_compat.BADADDR, idaapi.BADADDR)
    if prev_ea is not None and idc.print_insn_mnem(prev_ea) == "lea":
        ea = idc.get_name_ea_simple(idc.print_operand(prev_ea, 1))
        if ea not in _BAD and idaapi.get_func(ea):
            return ea
    name_ea = idc.get_name_ea_simple(idc.print_operand(store_ea, 1))
    if name_ea not in _BAD and idaapi.get_func(name_ea):
        return name_ea
    if idc.get_operand_type(store_ea, 1) in (idc.o_imm, idc.o_mem, idc.o_near, idc.o_far):
        val = idc.get_operand_value(store_ea, 1)
        if val not in _BAD and idaapi.get_func(val):
            return val
    return None


def find_majorfunction_dispatchers(rep):
    """Binary-wide scan for stores into DRIVER_OBJECT.MajorFunction[IRP_MJ_DEVICE_CONTROL]
    (+0E0h) and [IRP_MJ_INTERNAL_DEVICE_CONTROL] (+0E8h); returns a de-duplicated list of
    resolved handler EAs.

    This is the primary dispatcher source.  Unlike locate_ddc (which scans only the
    DriverEntry body and only runs for WDM drivers), it works regardless of driver type
    (minifilter / WDF included) and regardless of whether the MajorFunction assignment
    lives in DriverEntry or in a helper it calls -- both cases the entry-only scan misses
    (e.g. zam64's DriverInit, amp's DriverCreateDevice).
    """
    handlers = []
    seen = set()
    for f in idautils.Functions():
        prev = None
        for i in idautils.FuncItems(f):
            op0 = idc.print_operand(i, 0) or ""
            if _operand_targets_offset(op0, _DDC_OFFSET):
                tag = "DispatchDeviceControl"
            elif _operand_targets_offset(op0, _DIDC_OFFSET):
                tag = "DispatchInternalDeviceControl"
            else:
                prev = i
                continue
            target = _resolve_store_target(i, prev)
            if target is not None and target not in seen:
                seen.add(target)
                idc.set_name(target, tag)
                rep.info("[+] Found `{}` at 0x{:08x}".format(tag, target))
                handlers.append(target)
            prev = i
    return handlers


def check_for_fake_driver_entry(driver_entry_address, rep):
    """
    Checks if DriverEntry in WDM driver is fake and try to recover the real one
    :param driver_entry_address: Autodetected address of `DriverEntry` function
    :param rep: Reporter instance
    :return: real_driver_entry address
    """

    address = idaapi.get_func(driver_entry_address)
    end_address = address.end_ea
    MAX_WALK = 64
    _walk_count = 0
    while idc.print_insn_mnem(end_address) not in ("jmp", "call"):
        prev = idc.prev_head(end_address, address.start_ea)
        if prev == idc.BADADDR or prev == end_address or _walk_count >= MAX_WALK:
            rep.info("[!] Cannot find real `DriverEntry`; using IDA's one at 0x{addr:08x}".format(addr=driver_entry_address))
            return driver_entry_address
        end_address = prev
        _walk_count += 1
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
        if _operand_targets_offset(idc.print_operand(i, 0), _DDC_OFFSET) and idc.print_insn_mnem(prev_instruction) == "lea":
            real_ddc = idc.get_name_ea_simple(idc.print_operand(prev_instruction, 1))
            if real_ddc != ida_compat.BADADDR:
                rep.info("[+] Found `DispatchDeviceControl` at 0x{addr:08x}".format(addr=real_ddc))
                idc.set_name(real_ddc, "DispatchDeviceControl")
                dispatch["ddc"] = real_ddc
        if _operand_targets_offset(idc.print_operand(i, 0), _DIDC_OFFSET) and idc.print_insn_mnem(prev_instruction) == "lea":
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
    # Build the set of functions reachable in one call step from DriverEntry.
    # Many drivers move MajorFunction assignments into a helper, so the DDC is
    # never referenced directly from DriverEntry's own instructions.
    entry_callees = {driver_entry_address}
    for head in idautils.FuncItems(driver_entry_address):
        for ref in idautils.CodeRefsFrom(head, 0):
            fn = idaapi.get_func(ref)
            if fn is not None:
                entry_callees.add(fn.start_ea)

    real_ddc = {}
    count = 0
    for ddc in set(ddc_list):  # deduplicate candidates before xref walk
        for refs in idautils.XrefsTo(ddc, 0):
            reffunc = idaapi.get_func(refs.frm)
            if reffunc is not None and reffunc.start_ea in entry_callees:
                real_ddc[count] = ddc
                count += 1
                rep.info("[+] Possible `DispatchDeviceControl` at 0x{addr:08x}".format(addr=ddc))
                idc.set_name(ddc, "Possible_DispatchDeviceControl_{}".format(count))
                break  # one hit per candidate is enough
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
    # Whether the IRP / IO_STACK_LOCATION pointer register has been resolved to a
    # real register yet.  Guards the `<canary> in disasm` tests below so the
    # placeholder sentinels ("irp_reg", "io_stack_reg") can never spuriously match
    # real disassembly text (N25).  Behaviour is otherwise unchanged: an unresolved
    # sentinel never appears in disassembly, so these guards only make that
    # explicit.
    irp_resolved = False
    io_stack_resolved = False
    for i in idautils.FuncItems(ddc_address):
        disasm = ida_compat.disasm_text(i)
        src = idc.print_operand(i, 1)
        if ("rdx" in disasm and rdx_flag != 1) or (irp_resolved and irp_reg in disasm and irp_reg_flag != 1):
            # `IO_STACK_LOCATION` (IRP + 0B8h)
            if "+0B8h" in disasm:
                if "rdx+0B8h" in src or irp_reg + "+0B8h" in src:
                    ida_compat.op_struct_offset(i, 1, irp_id)
                    if idc.print_insn_mnem(i) == "mov":
                        io_stack_reg = idc.print_operand(i, 0)
                        io_stack_flag = 0
                        io_stack_resolved = True
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
                irp_resolved = True
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
        elif io_stack_resolved and io_stack_reg in disasm and io_stack_flag != 1:
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
            # `IO_STACK_LOCATION + OutputBufferLength` (+8).  Anchor on the closing
            # bracket so this does not also match +80h / +88h etc. (N24): IDA prints
            # offset 8 as "[reg+8]" (single digit, no 'h'), so "reg+8]" is exact.
            elif io_stack_reg + "+8]" in disasm:
                if io_stack_reg + "+8]" in src:
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
        "__GSHandlerCheck_SEH", "__GSHandlerCheck", "__GSHandlerCheckCommon",
        "GsDriverEntry",
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

    # Resolve candidate names to EAs, skipping library functions.  We do NOT hard-
    # filter here on references_iocontrolcode: on a database that already carries
    # struct annotations (e.g. a prior DBR run), the real dispatcher's control-code
    # read renders as an IO_STACK_LOCATION field rather than a raw offset, and a
    # strict text gate would wrongly drop it.  A non-dispatcher that slips through
    # (e.g. SepSddlGetAclForString) is harmless: it yields no structured IOCTLs and
    # scan_dispatchers gates its low-precision immediate scan on the same
    # IoControlCode-reference check, so it produces no findings.
    eas = []
    for name in candidates:
        ea = idc.get_name_ea_simple(name)
        if ea in (None, ida_compat.BADADDR):
            continue
        if idc.get_func_flags(ea) & idc.FUNC_LIB:
            rep.info("[!] Skipping dispatch candidate {} (library function)".format(name))
            continue
        eas.append(ea)
    return eas
