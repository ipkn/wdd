/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

#define WDDDeviceType 0x8000+123

#define IOCTL_WDDDRV_START CTL_CODE(WDDDeviceType, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WDDDRV_STOP CTL_CODE(WDDDeviceType, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)
//#define IOCTL_WDDDRV_READ CTL_CODE(WDDDeviceType, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Define an Interface Guid so that app can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_wdddrv,
    0x7ae6126c,0xb516,0x4f00,0x97,0x35,0x6a,0x47,0x2c,0x21,0x96,0x75);
// {7ae6126c-b516-4f00-9735-6a472c219675}
