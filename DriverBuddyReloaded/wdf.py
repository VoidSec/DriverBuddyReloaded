import ida_bytes
import ida_struct
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
    idc.add_struc(-1, 'WDFFUNCTIONS', 0)
    id = idc.get_struc_id('WDFFUNCTIONS')
    if id != -1:
        idc.add_struc_member(id, "pfnWdfChildListCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfChildListGetDevice", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfChildListRetrievePdo", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfChildListRetrieveAddressDescription", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfChildListBeginScan", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfChildListEndScan", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfChildListBeginIteration", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfChildListRetrieveNextDevice", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfChildListEndIteration", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfChildListAddOrUpdateChildDescriptionAsPresent", idc.BADADDR,
                             idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfChildListUpdateChildDescriptionAsMissing", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfChildListUpdateAllChildDescriptionsAsPresent", idc.BADADDR,
                             idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfChildListRequestChildEject", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfCollectionCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfCollectionGetCount", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfCollectionAdd", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfCollectionRemove", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfCollectionRemoveItem", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfCollectionGetItem", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfCollectionGetFirstItem", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfCollectionGetLastItem", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfCommonBufferCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfCommonBufferGetAlignedVirtualAddress", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfCommonBufferGetAlignedLogicalAddress", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfCommonBufferGetLength", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfControlDeviceInitAllocate", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfControlDeviceInitSetShutdownNotification", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfControlFinishInitializing", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceGetDeviceState", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceSetDeviceState", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfWdmDeviceGetWdfDeviceHandle", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceWdmGetDeviceObject", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceWdmGetAttachedDevice", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceWdmGetPhysicalDevice", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceWdmDispatchPreprocessedIrp", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceAddDependentUsageDeviceObject", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceAddRemovalRelationsPhysicalDevice", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceRemoveRemovalRelationsPhysicalDevice", idc.BADADDR,
                             idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceClearRemovalRelationsDevices", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceGetDriver", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceRetrieveDeviceName", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceAssignMofResourceName", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceGetIoTarget", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceGetDevicePnpState", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceGetDevicePowerState", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceGetDevicePowerPolicyState", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceAssignS0IdleSettings", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceAssignSxWakeSettings", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceOpenRegistryKey", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceSetSpecialFileSupport", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceSetCharacteristics", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceGetCharacteristics", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceGetAlignmentRequirement", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceSetAlignmentRequirement", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceInitFree", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceInitSetPnpPowerEventCallbacks", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceInitSetPowerPolicyEventCallbacks", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceInitSetPowerPolicyOwnership", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceInitRegisterPnpStateChangeCallback", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceInitRegisterPowerStateChangeCallback", idc.BADADDR,
                             idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceInitRegisterPowerPolicyStateChangeCallback", idc.BADADDR,
                             idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceInitSetIoType", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceInitSetExclusive", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceInitSetPowerNotPageable", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceInitSetPowerPageable", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceInitSetPowerInrush", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceInitSetDeviceType", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceInitAssignName", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceInitAssignSDDLString", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceInitSetDeviceClass", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceInitSetCharacteristics", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceInitSetFileObjectConfig", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceInitSetRequestAttributes", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceInitAssignWdmIrpPreprocessCallback", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceInitSetIoInCallerContextCallback", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceSetStaticStopRemove", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceCreateDeviceInterface", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceSetDeviceInterfaceState", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceRetrieveDeviceInterfaceString", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceCreateSymbolicLink", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceQueryProperty", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceAllocAndQueryProperty", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceSetPnpCapabilities", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceSetPowerCapabilities", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceSetBusInformationForChildren", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceIndicateWakeStatus", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceSetFailed", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceStopIdle", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceResumeIdle", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceGetFileObject", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceEnqueueRequest", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceGetDefaultQueue", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceConfigureRequestDispatching", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDmaEnablerCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDmaEnablerGetMaximumLength", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDmaEnablerGetMaximumScatterGatherElements", idc.BADADDR,
                             idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDmaEnablerSetMaximumScatterGatherElements", idc.BADADDR,
                             idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDmaTransactionCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDmaTransactionInitialize", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDmaTransactionInitializeUsingRequest", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDmaTransactionExecute", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDmaTransactionRelease", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDmaTransactionDmaCompleted", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDmaTransactionDmaCompletedWithLength", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDmaTransactionDmaCompletedFinal", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDmaTransactionGetBytesTransferred", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDmaTransactionSetMaximumLength", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDmaTransactionGetRequest", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDmaTransactionGetCurrentDmaTransferLength", idc.BADADDR,
                             idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDmaTransactionGetDevice", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDpcCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDpcEnqueue", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDpcCancel", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDpcGetParentObject", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDpcWdmGetDpc", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDriverCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDriverGetRegistryPath", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDriverWdmGetDriverObject", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDriverOpenParametersRegistryKey", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfWdmDriverGetWdfDriverHandle", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDriverRegisterTraceInfo", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDriverRetrieveVersionString", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDriverIsVersionAvailable", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfFdoInitWdmGetPhysicalDevice", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfFdoInitOpenRegistryKey", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfFdoInitQueryProperty", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfFdoInitAllocAndQueryProperty", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfFdoInitSetEventCallbacks", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfFdoInitSetFilter", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfFdoInitSetDefaultChildListConfig", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfFdoQueryForInterface", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfFdoGetDefaultChildList", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfFdoAddStaticChild", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfFdoLockStaticChildListForIteration", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfFdoRetrieveNextStaticChild", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfFdoUnlockStaticChildListFromIteration", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfFileObjectGetFileName", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfFileObjectGetFlags", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfFileObjectGetDevice", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfFileObjectWdmGetFileObject", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfInterruptCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfInterruptQueueDpcForIsr", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfInterruptSynchronize", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfInterruptAcquireLock", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfInterruptReleaseLock", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfInterruptEnable", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfInterruptDisable", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfInterruptWdmGetInterrupt", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfInterruptGetInfo", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfInterruptSetPolicy", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfInterruptGetDevice", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfIoQueueCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfIoQueueGetState", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfIoQueueStart", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfIoQueueStop", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfIoQueueStopSynchronously", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfIoQueueGetDevice", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfIoQueueRetrieveNextRequest", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfIoQueueRetrieveRequestByFileObject", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfIoQueueFindRequest", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfIoQueueRetrieveFoundRequest", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfIoQueueDrainSynchronously", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfIoQueueDrain", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfIoQueuePurgeSynchronously", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfIoQueuePurge", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfIoQueueReadyNotify", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfIoTargetCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfIoTargetOpen", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfIoTargetCloseForQueryRemove", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfIoTargetClose", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfIoTargetStart", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfIoTargetStop", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfIoTargetGetState", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfIoTargetGetDevice", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfIoTargetQueryTargetProperty", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfIoTargetAllocAndQueryTargetProperty", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfIoTargetQueryForInterface", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfIoTargetWdmGetTargetDeviceObject", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfIoTargetWdmGetTargetPhysicalDevice", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfIoTargetWdmGetTargetFileObject", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfIoTargetWdmGetTargetFileHandle", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfIoTargetSendReadSynchronously", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfIoTargetFormatRequestForRead", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfIoTargetSendWriteSynchronously", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfIoTargetFormatRequestForWrite", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfIoTargetSendIoctlSynchronously", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfIoTargetFormatRequestForIoctl", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfIoTargetSendInternalIoctlSynchronously", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfIoTargetFormatRequestForInternalIoctl", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfIoTargetSendInternalIoctlOthersSynchronously", idc.BADADDR,
                             idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfIoTargetFormatRequestForInternalIoctlOthers", idc.BADADDR,
                             idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfMemoryCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfMemoryCreatePreallocated", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfMemoryGetBuffer", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfMemoryAssignBuffer", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfMemoryCopyToBuffer", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfMemoryCopyFromBuffer", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfLookasideListCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfMemoryCreateFromLookaside", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceMiniportCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfDriverMiniportUnload", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfObjectGetTypedContextWorker", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfObjectAllocateContext", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfObjectContextGetObject", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfObjectReferenceActual", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfObjectDereferenceActual", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfObjectCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfObjectDelete", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfObjectQuery", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfPdoInitAllocate", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfPdoInitSetEventCallbacks", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfPdoInitAssignDeviceID", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfPdoInitAssignInstanceID", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfPdoInitAddHardwareID", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfPdoInitAddCompatibleID", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfPdoInitAddDeviceText", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfPdoInitSetDefaultLocale", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfPdoInitAssignRawDevice", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfPdoMarkMissing", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfPdoRequestEject", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfPdoGetParent", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfPdoRetrieveIdentificationDescription", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfPdoRetrieveAddressDescription", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfPdoUpdateAddressDescription", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfPdoAddEjectionRelationsPhysicalDevice", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfPdoRemoveEjectionRelationsPhysicalDevice", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfPdoClearEjectionRelationsDevices", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDeviceAddQueryInterface", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRegistryOpenKey", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRegistryCreateKey", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRegistryClose", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRegistryWdmGetHandle", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRegistryRemoveKey", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRegistryRemoveValue", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRegistryQueryValue", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRegistryQueryMemory", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRegistryQueryMultiString", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRegistryQueryUnicodeString", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfRegistryQueryString", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRegistryQueryULong", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRegistryAssignValue", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRegistryAssignMemory", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRegistryAssignMultiString", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfRegistryAssignUnicodeString", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfRegistryAssignString", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRegistryAssignULong", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestCreateFromIrp", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestReuse", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestChangeTarget", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestFormatRequestUsingCurrentType", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestWdmFormatUsingStackLocation", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestSend", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestGetStatus", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestMarkCancelable", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestUnmarkCancelable", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestIsCanceled", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestCancelSentRequest", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestIsFrom32BitProcess", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestSetCompletionRoutine", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestGetCompletionParams", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestAllocateTimer", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestComplete", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestCompleteWithPriorityBoost", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestCompleteWithInformation", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestGetParameters", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestRetrieveInputMemory", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestRetrieveOutputMemory", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestRetrieveInputBuffer", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestRetrieveOutputBuffer", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestRetrieveInputWdmMdl", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestRetrieveOutputWdmMdl", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestRetrieveUnsafeUserInputBuffer", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestRetrieveUnsafeUserOutputBuffer", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestSetInformation", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestGetInformation", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestGetFileObject", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestProbeAndLockUserBufferForRead", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestProbeAndLockUserBufferForWrite", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestGetRequestorMode", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestForwardToIoQueue", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestGetIoQueue", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestRequeue", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestStopAcknowledge", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfRequestWdmGetIrp", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfIoResourceRequirementsListSetSlotNumber", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfIoResourceRequirementsListSetInterfaceType", idc.BADADDR,
                             idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfIoResourceRequirementsListAppendIoResList", idc.BADADDR,
                             idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfIoResourceRequirementsListInsertIoResList", idc.BADADDR,
                             idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfIoResourceRequirementsListGetCount", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfIoResourceRequirementsListGetIoResList", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfIoResourceRequirementsListRemove", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfIoResourceRequirementsListRemoveByIoResList", idc.BADADDR,
                             idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfIoResourceListCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfIoResourceListAppendDescriptor", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfIoResourceListInsertDescriptor", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfIoResourceListUpdateDescriptor", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfIoResourceListGetCount", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfIoResourceListGetDescriptor", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfIoResourceListRemove", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfIoResourceListRemoveByDescriptor", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfCmResourceListAppendDescriptor", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfCmResourceListInsertDescriptor", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfCmResourceListGetCount", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfCmResourceListGetDescriptor", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfCmResourceListRemove", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfCmResourceListRemoveByDescriptor", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfStringCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfStringGetUnicodeString", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfObjectAcquireLock", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfObjectReleaseLock", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfWaitLockCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfWaitLockAcquire", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfWaitLockRelease", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfSpinLockCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfSpinLockAcquire", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfSpinLockRelease", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfTimerCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfTimerStart", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfTimerStop", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfTimerGetParentObject", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbTargetDeviceCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbTargetDeviceRetrieveInformation", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbTargetDeviceGetDeviceDescriptor", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbTargetDeviceRetrieveConfigDescriptor", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbTargetDeviceQueryString", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbTargetDeviceAllocAndQueryString", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbTargetDeviceFormatRequestForString", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbTargetDeviceGetNumInterfaces", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbTargetDeviceSelectConfig", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbTargetDeviceWdmGetConfigurationHandle", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbTargetDeviceRetrieveCurrentFrameNumber", idc.BADADDR,
                             idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbTargetDeviceSendControlTransferSynchronously", idc.BADADDR,
                             idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbTargetDeviceFormatRequestForControlTransfer", idc.BADADDR,
                             idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbTargetDeviceIsConnectedSynchronous", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbTargetDeviceResetPortSynchronously", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbTargetDeviceCyclePortSynchronously", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbTargetDeviceFormatRequestForCyclePort", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbTargetDeviceSendUrbSynchronously", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbTargetDeviceFormatRequestForUrb", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbTargetPipeGetInformation", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbTargetPipeIsInEndpoint", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbTargetPipeIsOutEndpoint", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbTargetPipeGetType", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbTargetPipeSetNoMaximumPacketSizeCheck", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbTargetPipeWriteSynchronously", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbTargetPipeFormatRequestForWrite", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbTargetPipeReadSynchronously", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbTargetPipeFormatRequestForRead", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbTargetPipeConfigContinuousReader", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbTargetPipeAbortSynchronously", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbTargetPipeFormatRequestForAbort", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbTargetPipeResetSynchronously", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbTargetPipeFormatRequestForReset", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbTargetPipeSendUrbSynchronously", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbTargetPipeFormatRequestForUrb", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbInterfaceGetInterfaceNumber", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbInterfaceGetNumEndpoints", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbInterfaceGetDescriptor", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbInterfaceSelectSetting", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbInterfaceGetEndpointInformation", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbTargetDeviceGetInterface", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbInterfaceGetConfiguredSettingIndex", idc.BADADDR, idc.FF_DATA | FF_PTR,
                             -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbInterfaceGetNumConfiguredPipes", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbInterfaceGetConfiguredPipe", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbTargetPipeWdmGetPipeHandle", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfVerifierDbgBreakPoint", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfVerifierKeBugCheck", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfWmiProviderCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfWmiProviderGetDevice", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfWmiProviderIsEnabled", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfWmiProviderGetTracingHandle", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfWmiInstanceCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfWmiInstanceRegister", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfWmiInstanceDeregister", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfWmiInstanceGetDevice", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfWmiInstanceGetProvider", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfWmiInstanceFireEvent", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfWorkItemCreate", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfWorkItemEnqueue", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfWorkItemGetParentObject", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfWorkItemFlush", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
        idc.add_struc_member(id, "pfnWdfCommonBufferCreateWithConfig", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDmaEnablerGetFragmentLength", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfDmaEnablerWdmGetDmaAdapter", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        idc.add_struc_member(id, "pfnWdfUsbInterfaceGetNumSettings", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                             ptr_size)
        if version >= 5:
            idc.add_struc_member(id, "pfnWdfDeviceRemoveDependentUsageDeviceObject", idc.BADADDR,
                                 idc.FF_DATA | FF_PTR, -1, ptr_size)
            idc.add_struc_member(id, "pfnWdfDeviceGetSystemPowerAction", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                                 ptr_size)
            idc.add_struc_member(id, "pfnWdfInterruptSetExtendedPolicy", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                                 ptr_size)
            idc.add_struc_member(id, "pfnWdfIoQueueAssignForwardProgressPolicy", idc.BADADDR, idc.FF_DATA | FF_PTR,
                                 -1, ptr_size)
            idc.add_struc_member(id, "pfnWdfPdoInitAssignContainerID", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                                 ptr_size)
            idc.add_struc_member(id, "pfnWdfPdoInitAllowForwardingRequestToParent", idc.BADADDR,
                                 idc.FF_DATA | FF_PTR, -1, ptr_size)
            idc.add_struc_member(id, "pfnWdfRequestMarkCancelableEx", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                                 ptr_size)
            idc.add_struc_member(id, "pfnWdfRequestIsReserved", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
            idc.add_struc_member(id, "pfnWdfRequestForwardToParentDeviceIoQueue", idc.BADADDR, idc.FF_DATA | FF_PTR,
                                 -1, ptr_size)
            if version >= 9:
                idc.add_struc_member(id, "pfnWdfCxDeviceInitAllocate", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                                     ptr_size)
                idc.add_struc_member(id, "pfnWdfCxDeviceInitAssignWdmIrpPreprocessCallback", idc.BADADDR,
                                     idc.FF_DATA | FF_PTR, -1, ptr_size)
                idc.add_struc_member(id, "pfnWdfCxDeviceInitSetIoInCallerContextCallback", idc.BADADDR,
                                     idc.FF_DATA | FF_PTR, -1, ptr_size)
                idc.add_struc_member(id, "pfnWdfCxDeviceInitSetRequestAttributes", idc.BADADDR, idc.FF_DATA | FF_PTR,
                                     -1, ptr_size)
                idc.add_struc_member(id, "pfnWdfCxDeviceInitSetFileObjectConfig", idc.BADADDR, idc.FF_DATA | FF_PTR,
                                     -1, ptr_size)
                idc.add_struc_member(id, "pfnWdfDeviceWdmDispatchIrp", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                                     ptr_size)
                idc.add_struc_member(id, "pfnWdfDeviceWdmDispatchIrpToIoQueue", idc.BADADDR, idc.FF_DATA | FF_PTR,
                                     -1, ptr_size)
                idc.add_struc_member(id, "pfnWdfDeviceInitSetRemoveLockOptions", idc.BADADDR, idc.FF_DATA | FF_PTR,
                                     -1, ptr_size)
                idc.add_struc_member(id, "pfnWdfDeviceConfigureWdmIrpDispatchCallback", idc.BADADDR,
                                     idc.FF_DATA | FF_PTR, -1, ptr_size)
                idc.add_struc_member(id, "pfnWdfDmaEnablerConfigureSystemProfile", idc.BADADDR, idc.FF_DATA | FF_PTR,
                                     -1, ptr_size)
                idc.add_struc_member(id, "pfnWdfDmaTransactionInitializeUsingOffset", idc.BADADDR,
                                     idc.FF_DATA | FF_PTR, -1, ptr_size)
                idc.add_struc_member(id, "pfnWdfDmaTransactionGetTransferInfo", idc.BADADDR, idc.FF_DATA | FF_PTR,
                                     -1, ptr_size)
                idc.add_struc_member(id, "pfnWdfDmaTransactionSetChannelConfigurationCallback", idc.BADADDR,
                                     idc.FF_DATA | FF_PTR, -1, ptr_size)
                idc.add_struc_member(id, "pfnWdfDmaTransactionSetTransferCompleteCallback", idc.BADADDR,
                                     idc.FF_DATA | FF_PTR, -1, ptr_size)
                idc.add_struc_member(id, "pfnWdfDmaTransactionSetImmediateExecution", idc.BADADDR,
                                     idc.FF_DATA | FF_PTR, -1, ptr_size)
                idc.add_struc_member(id, "pfnWdfDmaTransactionAllocateResources", idc.BADADDR, idc.FF_DATA | FF_PTR,
                                     -1, ptr_size)
                idc.add_struc_member(id, "pfnWdfDmaTransactionSetDeviceAddressOffset", idc.BADADDR,
                                     idc.FF_DATA | FF_PTR, -1, ptr_size)
                idc.add_struc_member(id, "pfnWdfDmaTransactionFreeResources", idc.BADADDR, idc.FF_DATA | FF_PTR,
                                     -1, ptr_size)
                idc.add_struc_member(id, "pfnWdfDmaTransactionCancel", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                                     ptr_size)
                idc.add_struc_member(id, "pfnWdfDmaTransactionWdmGetTransferContext", idc.BADADDR,
                                     idc.FF_DATA | FF_PTR, -1, ptr_size)
                idc.add_struc_member(id, "pfnWdfInterruptQueueWorkItemForIsr", idc.BADADDR, idc.FF_DATA | FF_PTR,
                                     -1, ptr_size)
                idc.add_struc_member(id, "pfnWdfInterruptTryToAcquireLock", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                                     ptr_size)
                idc.add_struc_member(id, "pfnWdfIoQueueStopAndPurge", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                                     ptr_size)
                idc.add_struc_member(id, "pfnWdfIoQueueStopAndPurgeSynchronously", idc.BADADDR, idc.FF_DATA | FF_PTR,
                                     -1, ptr_size)
                idc.add_struc_member(id, "pfnWdfIoTargetPurge", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
                idc.add_struc_member(id, "pfnWdfUsbTargetDeviceCreateWithParameters", idc.BADADDR,
                                     idc.FF_DATA | FF_PTR, -1, ptr_size)
                idc.add_struc_member(id, "pfnWdfUsbTargetDeviceQueryUsbCapability", idc.BADADDR,
                                     idc.FF_DATA | FF_PTR, -1, ptr_size)
                idc.add_struc_member(id, "pfnWdfUsbTargetDeviceCreateUrb", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                                     ptr_size)
                idc.add_struc_member(id, "pfnWdfUsbTargetDeviceCreateIsochUrb", idc.BADADDR, idc.FF_DATA | FF_PTR,
                                     -1, ptr_size)
                idc.add_struc_member(id, "pfnWdfDeviceWdmAssignPowerFrameworkSettings", idc.BADADDR,
                                     idc.FF_DATA | FF_PTR, -1, ptr_size)
                idc.add_struc_member(id, "pfnWdfDmaTransactionStopSystemTransfer", idc.BADADDR, idc.FF_DATA | FF_PTR,
                                     -1, ptr_size)
                idc.add_struc_member(id, "pfnWdfCxVerifierKeBugCheck", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                                     ptr_size)
                idc.add_struc_member(id, "pfnWdfInterruptReportActive", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                                     ptr_size)
                idc.add_struc_member(id, "pfnWdfInterruptReportInactive", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                                     ptr_size)
                idc.add_struc_member(id, "pfnWdfDeviceInitSetReleaseHardwareOrderOnFailure", idc.BADADDR,
                                     idc.FF_DATA | FF_PTR, -1, ptr_size)
                idc.add_struc_member(id, "pfnWdfGetTriageInfo", idc.BADADDR, idc.FF_DATA | FF_PTR, -1, ptr_size)
                if version >= 11:
                    idc.add_struc_member(id, "pfnWdfDeviceInitSetIoTypeEx", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                                         ptr_size)
                    idc.add_struc_member(id, "pfnWdfDeviceQueryPropertyEx", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                                         ptr_size)
                    idc.add_struc_member(id, "pfnWdfDeviceAllocAndQueryPropertyEx", idc.BADADDR,
                                         idc.FF_DATA | FF_PTR, -1, ptr_size)
                    idc.add_struc_member(id, "pfnWdfDeviceAssignProperty", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                                         ptr_size)
                    idc.add_struc_member(id, "pfnWdfFdoInitQueryPropertyEx", idc.BADADDR, idc.FF_DATA | FF_PTR, -1,
                                         ptr_size)
                    idc.add_struc_member(id, "pfnWdfFdoInitAllocAndQueryPropertyEx", idc.BADADDR,
                                         idc.FF_DATA | FF_PTR, -1, ptr_size)
                    if version >= 13:
                        idc.add_struc_member(id, "pfnWdfDeviceStopIdleActual", idc.BADADDR, idc.FF_DATA | FF_PTR,
                                             -1, ptr_size)
                        idc.add_struc_member(id, "pfnWdfDeviceResumeIdleActual", idc.BADADDR, idc.FF_DATA | FF_PTR,
                                             -1, ptr_size)
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
                    size = ida_struct.get_struc_size(id)
                    log('doStruct (size=' + hex(size) + ') at ' + hex(wdf_func))
                    # ida_bytes.do_unknown_range(ea, size, flags)
                    # idaapi.do_unknown_range(wdf_func, size, 0)
                    ida_bytes.del_items(wdf_func, 0, size)
                    # if idaapi.doStruct(wdf_func, size, id) and idc.set_name(wdf_func, 'WdfFunctions', 0):
                    if ida_bytes.create_struct(wdf_func, size, id) and idc.set_name(wdf_func, 'WdfFunctions', 0):
                        log('Success')
                    else:
                        log('Failure')
