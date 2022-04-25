import ida_bytes
import idaapi
import idc

"""
Script to automatically identify WDF function pointers
Inspired by http://redplait.blogspot.ru/2012/12/wdffunctionsidc.html
Originally by Nicolas Guigo
Modified by Braden Hollembaek, Adam Pond and Paolo Stagno
"""


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
    offset = 0
    # check for existing
    id = idc.get_struc_id('WDFFUNCTIONS')
    if id != -1:
        # delete old struc
        idc.del_struc(id)
    log('Creating struct for WDF Functions version 1.%d' % version)
    id = idc.add_struc(-1, 'WDFFUNCTIONS', 0)
    struc = idaapi.get_struc(id)
    if id != -1:
        idc.add_struc_member(struc, "pfnWdfChildListCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfChildListGetDevice", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfChildListRetrievePdo", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfChildListRetrieveAddressDescription", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfChildListBeginScan", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfChildListEndScan", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfChildListBeginIteration", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfChildListRetrieveNextDevice", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfChildListEndIteration", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfChildListAddOrUpdateChildDescriptionAsPresent", idc.BADADDR,
                             idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfChildListUpdateChildDescriptionAsMissing", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfChildListUpdateAllChildDescriptionsAsPresent", idc.BADADDR,
                             idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfChildListRequestChildEject", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfCollectionCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfCollectionGetCount", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfCollectionAdd", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfCollectionRemove", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfCollectionRemoveItem", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfCollectionGetItem", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfCollectionGetFirstItem", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfCollectionGetLastItem", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfCommonBufferCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfCommonBufferGetAlignedVirtualAddress", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfCommonBufferGetAlignedLogicalAddress", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfCommonBufferGetLength", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfControlDeviceInitAllocate", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfControlDeviceInitSetShutdownNotification", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfControlFinishInitializing", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceGetDeviceState", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceSetDeviceState", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfWdmDeviceGetWdfDeviceHandle", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceWdmGetDeviceObject", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceWdmGetAttachedDevice", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceWdmGetPhysicalDevice", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceWdmDispatchPreprocessedIrp", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceAddDependentUsageDeviceObject", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceAddRemovalRelationsPhysicalDevice", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceRemoveRemovalRelationsPhysicalDevice", idc.BADADDR,
                             idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceClearRemovalRelationsDevices", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceGetDriver", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceRetrieveDeviceName", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceAssignMofResourceName", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceGetIoTarget", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceGetDevicePnpState", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceGetDevicePowerState", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceGetDevicePowerPolicyState", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceAssignS0IdleSettings", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceAssignSxWakeSettings", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceOpenRegistryKey", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceSetSpecialFileSupport", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceSetCharacteristics", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceGetCharacteristics", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceGetAlignmentRequirement", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceSetAlignmentRequirement", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceInitFree", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceInitSetPnpPowerEventCallbacks", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceInitSetPowerPolicyEventCallbacks", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceInitSetPowerPolicyOwnership", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceInitRegisterPnpStateChangeCallback", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceInitRegisterPowerStateChangeCallback", idc.BADADDR,
                             idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceInitRegisterPowerPolicyStateChangeCallback", idc.BADADDR,
                             idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceInitSetIoType", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceInitSetExclusive", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceInitSetPowerNotPageable", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceInitSetPowerPageable", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceInitSetPowerInrush", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceInitSetDeviceType", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceInitAssignName", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceInitAssignSDDLString", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceInitSetDeviceClass", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceInitSetCharacteristics", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceInitSetFileObjectConfig", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceInitSetRequestAttributes", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceInitAssignWdmIrpPreprocessCallback", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceInitSetIoInCallerContextCallback", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceSetStaticStopRemove", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceCreateDeviceInterface", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceSetDeviceInterfaceState", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceRetrieveDeviceInterfaceString", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceCreateSymbolicLink", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceQueryProperty", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceAllocAndQueryProperty", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceSetPnpCapabilities", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceSetPowerCapabilities", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceSetBusInformationForChildren", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceIndicateWakeStatus", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceSetFailed", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceStopIdle", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceResumeIdle", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceGetFileObject", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceEnqueueRequest", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceGetDefaultQueue", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceConfigureRequestDispatching", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDmaEnablerCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDmaEnablerGetMaximumLength", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDmaEnablerGetMaximumScatterGatherElements", idc.BADADDR,
                             idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDmaEnablerSetMaximumScatterGatherElements", idc.BADADDR,
                             idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDmaTransactionCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDmaTransactionInitialize", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDmaTransactionInitializeUsingRequest", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDmaTransactionExecute", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDmaTransactionRelease", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDmaTransactionDmaCompleted", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDmaTransactionDmaCompletedWithLength", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDmaTransactionDmaCompletedFinal", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDmaTransactionGetBytesTransferred", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDmaTransactionSetMaximumLength", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDmaTransactionGetRequest", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDmaTransactionGetCurrentDmaTransferLength", idc.BADADDR,
                             idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDmaTransactionGetDevice", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDpcCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDpcEnqueue", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDpcCancel", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDpcGetParentObject", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDpcWdmGetDpc", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDriverCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDriverGetRegistryPath", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDriverWdmGetDriverObject", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDriverOpenParametersRegistryKey", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfWdmDriverGetWdfDriverHandle", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDriverRegisterTraceInfo", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDriverRetrieveVersionString", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDriverIsVersionAvailable", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfFdoInitWdmGetPhysicalDevice", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfFdoInitOpenRegistryKey", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfFdoInitQueryProperty", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfFdoInitAllocAndQueryProperty", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfFdoInitSetEventCallbacks", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfFdoInitSetFilter", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfFdoInitSetDefaultChildListConfig", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfFdoQueryForInterface", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfFdoGetDefaultChildList", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfFdoAddStaticChild", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfFdoLockStaticChildListForIteration", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfFdoRetrieveNextStaticChild", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfFdoUnlockStaticChildListFromIteration", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfFileObjectGetFileName", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfFileObjectGetFlags", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfFileObjectGetDevice", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfFileObjectWdmGetFileObject", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfInterruptCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfInterruptQueueDpcForIsr", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfInterruptSynchronize", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfInterruptAcquireLock", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfInterruptReleaseLock", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfInterruptEnable", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfInterruptDisable", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfInterruptWdmGetInterrupt", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfInterruptGetInfo", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfInterruptSetPolicy", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfInterruptGetDevice", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoQueueCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoQueueGetState", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoQueueStart", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoQueueStop", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoQueueStopSynchronously", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoQueueGetDevice", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoQueueRetrieveNextRequest", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoQueueRetrieveRequestByFileObject", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoQueueFindRequest", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoQueueRetrieveFoundRequest", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoQueueDrainSynchronously", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoQueueDrain", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoQueuePurgeSynchronously", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoQueuePurge", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoQueueReadyNotify", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoTargetCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoTargetOpen", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoTargetCloseForQueryRemove", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoTargetClose", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoTargetStart", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoTargetStop", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoTargetGetState", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoTargetGetDevice", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoTargetQueryTargetProperty", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoTargetAllocAndQueryTargetProperty", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoTargetQueryForInterface", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoTargetWdmGetTargetDeviceObject", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoTargetWdmGetTargetPhysicalDevice", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoTargetWdmGetTargetFileObject", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoTargetWdmGetTargetFileHandle", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoTargetSendReadSynchronously", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoTargetFormatRequestForRead", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoTargetSendWriteSynchronously", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoTargetFormatRequestForWrite", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoTargetSendIoctlSynchronously", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoTargetFormatRequestForIoctl", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoTargetSendInternalIoctlSynchronously", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoTargetFormatRequestForInternalIoctl", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoTargetSendInternalIoctlOthersSynchronously", idc.BADADDR,
                             idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoTargetFormatRequestForInternalIoctlOthers", idc.BADADDR,
                             idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfMemoryCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfMemoryCreatePreallocated", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfMemoryGetBuffer", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfMemoryAssignBuffer", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfMemoryCopyToBuffer", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfMemoryCopyFromBuffer", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfLookasideListCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfMemoryCreateFromLookaside", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceMiniportCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfDriverMiniportUnload", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfObjectGetTypedContextWorker", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfObjectAllocateContext", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfObjectContextGetObject", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfObjectReferenceActual", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfObjectDereferenceActual", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfObjectCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfObjectDelete", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfObjectQuery", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfPdoInitAllocate", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfPdoInitSetEventCallbacks", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfPdoInitAssignDeviceID", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfPdoInitAssignInstanceID", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfPdoInitAddHardwareID", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfPdoInitAddCompatibleID", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfPdoInitAddDeviceText", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfPdoInitSetDefaultLocale", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfPdoInitAssignRawDevice", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfPdoMarkMissing", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfPdoRequestEject", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfPdoGetParent", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfPdoRetrieveIdentificationDescription", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfPdoRetrieveAddressDescription", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfPdoUpdateAddressDescription", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfPdoAddEjectionRelationsPhysicalDevice", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfPdoRemoveEjectionRelationsPhysicalDevice", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfPdoClearEjectionRelationsDevices", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDeviceAddQueryInterface", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRegistryOpenKey", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRegistryCreateKey", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRegistryClose", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRegistryWdmGetHandle", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRegistryRemoveKey", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRegistryRemoveValue", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRegistryQueryValue", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRegistryQueryMemory", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRegistryQueryMultiString", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRegistryQueryUnicodeString", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfRegistryQueryString", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRegistryQueryULong", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRegistryAssignValue", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRegistryAssignMemory", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRegistryAssignMultiString", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfRegistryAssignUnicodeString", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfRegistryAssignString", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRegistryAssignULong", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestCreateFromIrp", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestReuse", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestChangeTarget", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestFormatRequestUsingCurrentType", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestWdmFormatUsingStackLocation", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestSend", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestGetStatus", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestMarkCancelable", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestUnmarkCancelable", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestIsCanceled", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestCancelSentRequest", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestIsFrom32BitProcess", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestSetCompletionRoutine", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestGetCompletionParams", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestAllocateTimer", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestComplete", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestCompleteWithPriorityBoost", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestCompleteWithInformation", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestGetParameters", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestRetrieveInputMemory", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestRetrieveOutputMemory", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestRetrieveInputBuffer", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestRetrieveOutputBuffer", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestRetrieveInputWdmMdl", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestRetrieveOutputWdmMdl", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestRetrieveUnsafeUserInputBuffer", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestRetrieveUnsafeUserOutputBuffer", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestSetInformation", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestGetInformation", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestGetFileObject", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestProbeAndLockUserBufferForRead", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestProbeAndLockUserBufferForWrite", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestGetRequestorMode", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestForwardToIoQueue", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestGetIoQueue", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestRequeue", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestStopAcknowledge", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfRequestWdmGetIrp", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoResourceRequirementsListSetSlotNumber", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoResourceRequirementsListSetInterfaceType", idc.BADADDR,
                             idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoResourceRequirementsListAppendIoResList", idc.BADADDR,
                             idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoResourceRequirementsListInsertIoResList", idc.BADADDR,
                             idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoResourceRequirementsListGetCount", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoResourceRequirementsListGetIoResList", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoResourceRequirementsListRemove", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoResourceRequirementsListRemoveByIoResList", idc.BADADDR,
                             idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoResourceListCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoResourceListAppendDescriptor", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoResourceListInsertDescriptor", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoResourceListUpdateDescriptor", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoResourceListGetCount", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoResourceListGetDescriptor", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoResourceListRemove", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfIoResourceListRemoveByDescriptor", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfCmResourceListAppendDescriptor", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfCmResourceListInsertDescriptor", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfCmResourceListGetCount", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfCmResourceListGetDescriptor", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfCmResourceListRemove", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfCmResourceListRemoveByDescriptor", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfStringCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfStringGetUnicodeString", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfObjectAcquireLock", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfObjectReleaseLock", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfWaitLockCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfWaitLockAcquire", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfWaitLockRelease", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfSpinLockCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfSpinLockAcquire", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfSpinLockRelease", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfTimerCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfTimerStart", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfTimerStop", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfTimerGetParentObject", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbTargetDeviceCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbTargetDeviceRetrieveInformation", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbTargetDeviceGetDeviceDescriptor", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbTargetDeviceRetrieveConfigDescriptor", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbTargetDeviceQueryString", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbTargetDeviceAllocAndQueryString", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbTargetDeviceFormatRequestForString", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbTargetDeviceGetNumInterfaces", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbTargetDeviceSelectConfig", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbTargetDeviceWdmGetConfigurationHandle", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbTargetDeviceRetrieveCurrentFrameNumber", idc.BADADDR,
                             idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbTargetDeviceSendControlTransferSynchronously", idc.BADADDR,
                             idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbTargetDeviceFormatRequestForControlTransfer", idc.BADADDR,
                             idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbTargetDeviceIsConnectedSynchronous", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbTargetDeviceResetPortSynchronously", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbTargetDeviceCyclePortSynchronously", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbTargetDeviceFormatRequestForCyclePort", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbTargetDeviceSendUrbSynchronously", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbTargetDeviceFormatRequestForUrb", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbTargetPipeGetInformation", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbTargetPipeIsInEndpoint", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbTargetPipeIsOutEndpoint", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbTargetPipeGetType", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbTargetPipeSetNoMaximumPacketSizeCheck", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbTargetPipeWriteSynchronously", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbTargetPipeFormatRequestForWrite", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbTargetPipeReadSynchronously", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbTargetPipeFormatRequestForRead", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbTargetPipeConfigContinuousReader", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbTargetPipeAbortSynchronously", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbTargetPipeFormatRequestForAbort", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbTargetPipeResetSynchronously", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbTargetPipeFormatRequestForReset", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbTargetPipeSendUrbSynchronously", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbTargetPipeFormatRequestForUrb", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbInterfaceGetInterfaceNumber", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbInterfaceGetNumEndpoints", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbInterfaceGetDescriptor", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbInterfaceSelectSetting", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbInterfaceGetEndpointInformation", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbTargetDeviceGetInterface", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbInterfaceGetConfiguredSettingIndex", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbInterfaceGetNumConfiguredPipes", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbInterfaceGetConfiguredPipe", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbTargetPipeWdmGetPipeHandle", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfVerifierDbgBreakPoint", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfVerifierKeBugCheck", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfWmiProviderCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfWmiProviderGetDevice", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfWmiProviderIsEnabled", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfWmiProviderGetTracingHandle", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfWmiInstanceCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfWmiInstanceRegister", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfWmiInstanceDeregister", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfWmiInstanceGetDevice", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfWmiInstanceGetProvider", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfWmiInstanceFireEvent", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfWorkItemCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfWorkItemEnqueue", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfWorkItemGetParentObject", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfWorkItemFlush", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
        idc.add_struc_member(struc, "pfnWdfCommonBufferCreateWithConfig", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDmaEnablerGetFragmentLength", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfDmaEnablerWdmGetDmaAdapter", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        idc.add_struc_member(struc, "pfnWdfUsbInterfaceGetNumSettings", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                             ptr_size)
        if version >= 5:
            idc.add_struc_member(struc, "pfnWdfDeviceRemoveDependentUsageDeviceObject", idc.BADADDR,
                                 idc.FF_DATA | FF_PTR, None, ptr_size)
            idc.add_struc_member(struc, "pfnWdfDeviceGetSystemPowerAction", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                                 ptr_size)
            idc.add_struc_member(struc, "pfnWdfInterruptSetExtendedPolicy", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                                 ptr_size)
            idc.add_struc_member(struc, "pfnWdfIoQueueAssignForwardProgressPolicy", idc.BADADDR, idc.FF_DATA | FF_PTR,
                                 None, ptr_size)
            idc.add_struc_member(struc, "pfnWdfPdoInitAssignContainerID", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                                 ptr_size)
            idc.add_struc_member(struc, "pfnWdfPdoInitAllowForwardingRequestToParent", idc.BADADDR,
                                 idc.FF_DATA | FF_PTR, None, ptr_size)
            idc.add_struc_member(struc, "pfnWdfRequestMarkCancelableEx", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                                 ptr_size)
            idc.add_struc_member(struc, "pfnWdfRequestIsReserved", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
            idc.add_struc_member(struc, "pfnWdfRequestForwardToParentDeviceIoQueue", idc.BADADDR, idc.FF_DATA | FF_PTR,
                                 None, ptr_size)
            if version >= 9:
                idc.add_struc_member(struc, "pfnWdfCxDeviceInitAllocate", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                                     ptr_size)
                idc.add_struc_member(struc, "pfnWdfCxDeviceInitAssignWdmIrpPreprocessCallback", idc.BADADDR,
                                     idc.FF_DATA | FF_PTR, None, ptr_size)
                idc.add_struc_member(struc, "pfnWdfCxDeviceInitSetIoInCallerContextCallback", idc.BADADDR,
                                     idc.FF_DATA | FF_PTR, None, ptr_size)
                idc.add_struc_member(struc, "pfnWdfCxDeviceInitSetRequestAttributes", idc.BADADDR, idc.FF_DATA | FF_PTR,
                                     None, ptr_size)
                idc.add_struc_member(struc, "pfnWdfCxDeviceInitSetFileObjectConfig", idc.BADADDR, idc.FF_DATA | FF_PTR,
                                     None, ptr_size)
                idc.add_struc_member(struc, "pfnWdfDeviceWdmDispatchIrp", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                                     ptr_size)
                idc.add_struc_member(struc, "pfnWdfDeviceWdmDispatchIrpToIoQueue", idc.BADADDR, idc.FF_DATA | FF_PTR,
                                     None, ptr_size)
                idc.add_struc_member(struc, "pfnWdfDeviceInitSetRemoveLockOptions", idc.BADADDR, idc.FF_DATA | FF_PTR,
                                     None, ptr_size)
                idc.add_struc_member(struc, "pfnWdfDeviceConfigureWdmIrpDispatchCallback", idc.BADADDR,
                                     idc.FF_DATA | FF_PTR, None, ptr_size)
                idc.add_struc_member(struc, "pfnWdfDmaEnablerConfigureSystemProfile", idc.BADADDR, idc.FF_DATA | FF_PTR,
                                     None, ptr_size)
                idc.add_struc_member(struc, "pfnWdfDmaTransactionInitializeUsingOffset", idc.BADADDR,
                                     idc.FF_DATA | FF_PTR, None, ptr_size)
                idc.add_struc_member(struc, "pfnWdfDmaTransactionGetTransferInfo", idc.BADADDR, idc.FF_DATA | FF_PTR,
                                     None, ptr_size)
                idc.add_struc_member(struc, "pfnWdfDmaTransactionSetChannelConfigurationCallback", idc.BADADDR,
                                     idc.FF_DATA | FF_PTR, None, ptr_size)
                idc.add_struc_member(struc, "pfnWdfDmaTransactionSetTransferCompleteCallback", idc.BADADDR,
                                     idc.FF_DATA | FF_PTR, None, ptr_size)
                idc.add_struc_member(struc, "pfnWdfDmaTransactionSetImmediateExecution", idc.BADADDR,
                                     idc.FF_DATA | FF_PTR, None, ptr_size)
                idc.add_struc_member(struc, "pfnWdfDmaTransactionAllocateResources", idc.BADADDR, idc.FF_DATA | FF_PTR,
                                     None, ptr_size)
                idc.add_struc_member(struc, "pfnWdfDmaTransactionSetDeviceAddressOffset", idc.BADADDR,
                                     idc.FF_DATA | FF_PTR, None, ptr_size)
                idc.add_struc_member(struc, "pfnWdfDmaTransactionFreeResources", idc.BADADDR, idc.FF_DATA | FF_PTR,
                                     None, ptr_size)
                idc.add_struc_member(struc, "pfnWdfDmaTransactionCancel", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                                     ptr_size)
                idc.add_struc_member(struc, "pfnWdfDmaTransactionWdmGetTransferContext", idc.BADADDR,
                                     idc.FF_DATA | FF_PTR, None, ptr_size)
                idc.add_struc_member(struc, "pfnWdfInterruptQueueWorkItemForIsr", idc.BADADDR, idc.FF_DATA | FF_PTR,
                                     None, ptr_size)
                idc.add_struc_member(struc, "pfnWdfInterruptTryToAcquireLock", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                                     ptr_size)
                idc.add_struc_member(struc, "pfnWdfIoQueueStopAndPurge", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                                     ptr_size)
                idc.add_struc_member(struc, "pfnWdfIoQueueStopAndPurgeSynchronously", idc.BADADDR, idc.FF_DATA | FF_PTR,
                                     None, ptr_size)
                idc.add_struc_member(struc, "pfnWdfIoTargetPurge", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
                idc.add_struc_member(struc, "pfnWdfUsbTargetDeviceCreateWithParameters", idc.BADADDR,
                                     idc.FF_DATA | FF_PTR, None, ptr_size)
                idc.add_struc_member(struc, "pfnWdfUsbTargetDeviceQueryUsbCapability", idc.BADADDR,
                                     idc.FF_DATA | FF_PTR, None, ptr_size)
                idc.add_struc_member(struc, "pfnWdfUsbTargetDeviceCreateUrb", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                                     ptr_size)
                idc.add_struc_member(struc, "pfnWdfUsbTargetDeviceCreateIsochUrb", idc.BADADDR, idc.FF_DATA | FF_PTR,
                                     None, ptr_size)
                idc.add_struc_member(struc, "pfnWdfDeviceWdmAssignPowerFrameworkSettings", idc.BADADDR,
                                     idc.FF_DATA | FF_PTR, None, ptr_size)
                idc.add_struc_member(struc, "pfnWdfDmaTransactionStopSystemTransfer", idc.BADADDR, idc.FF_DATA | FF_PTR,
                                     None, ptr_size)
                idc.add_struc_member(struc, "pfnWdfCxVerifierKeBugCheck", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                                     ptr_size)
                idc.add_struc_member(struc, "pfnWdfInterruptReportActive", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                                     ptr_size)
                idc.add_struc_member(struc, "pfnWdfInterruptReportInactive", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                                     ptr_size)
                idc.add_struc_member(struc, "pfnWdfDeviceInitSetReleaseHardwareOrderOnFailure", idc.BADADDR,
                                     idc.FF_DATA | FF_PTR, None, ptr_size)
                idc.add_struc_member(struc, "pfnWdfGetTriageInfo", idc.BADADDR, idc.FF_DATA | FF_PTR, None, ptr_size)
                if version >= 11:
                    idc.add_struc_member(struc, "pfnWdfDeviceInitSetIoTypeEx", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                                         ptr_size)
                    idc.add_struc_member(struc, "pfnWdfDeviceQueryPropertyEx", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                                         ptr_size)
                    idc.add_struc_member(struc, "pfnWdfDeviceAllocAndQueryPropertyEx", idc.BADADDR,
                                         idc.FF_DATA | FF_PTR, None, ptr_size)
                    idc.add_struc_member(struc, "pfnWdfDeviceAssignProperty", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                                         ptr_size)
                    idc.add_struc_member(struc, "pfnWdfFdoInitQueryPropertyEx", idc.BADADDR, idc.FF_DATA | FF_PTR, None,
                                         ptr_size)
                    idc.add_struc_member(struc, "pfnWdfFdoInitAllocAndQueryPropertyEx", idc.BADADDR,
                                         idc.FF_DATA | FF_PTR, None, ptr_size)
                    if version >= 13:
                        idc.add_struc_member(struc, "pfnWdfDeviceStopIdleActual", idc.BADADDR, idc.FF_DATA | FF_PTR,
                                             None, ptr_size)
                        idc.add_struc_member(struc, "pfnWdfDeviceResumeIdleActual", idc.BADADDR, idc.FF_DATA | FF_PTR,
                                             None, ptr_size)
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
    segments = [idaapi.get_segm_by_name('.data'), idaapi.get_segm_by_name('.rdata')]
    for segm in segments:
        if segm.start_ea != idc.BADADDR and segm.end_ea != idc.BADADDR:
            # search `KmdfLibrary` unicode string in .rdata section
            binpat = idaapi.compiled_binpat_vec_t()
            ida_bytes.parse_binpat_str(binpat, 0, 'L"KmdfLibrary"', 16)
            idx = ida_bytes.bin_search(segm.start_ea, segm.end_ea, binpat, ida_bytes.BIN_SEARCH_NOCASE)
            if idx != idaapi.BADADDR:
                log("Found `KmdfLibrary` string at " + hex(idx))
                addr = idc.get_first_dref_to(idx)
                # hacky logic fix , consider only the minor portion
                version = int(str(idc.get_wide_dword(addr + ptr_size + 0x4)))
                id = add_struct(version)
                if id != -1:
                    # log('Success')
                    wdf_func = get_ptr(addr + ptr_size + 0x10)
                    size = idc.GetStrucSize(id)
                    log('doStruct (size=' + hex(size) + ') at ' + hex(wdf_func))
                    idaapi.do_unknown_range(wdf_func, size, 0)
                    if idaapi.doStruct(wdf_func, size, id) and idc.set_name(wdf_func, 'WdfFunctions', 0):
                        log('Success')
                    else:
                        log('Failure')
