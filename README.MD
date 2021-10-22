# Driver Buddy Reloaded Quickstart

## Table of Contents

1. [Installation](#Installation)
2. [Usage](#Usage)
3. [About Driver Buddy Reloaded](#About-Driver-Buddy-Reloaded)
    1. [Finding DispatchDeviceControl](#Finding-DispatchDeviceControl)
    2. [Labeling WDM Structs](#Labeling-WDM-Structs)
    3. [Labeling WDF Functions](#Labeling-WDF-Functions)
    4. [Finding & Decoding IOCTL Codes](#Finding-&-Decoding-IOCTL-Codes)
    6. [Flagging Functions](#Flagging-Functions)
    7. [Finding Device Names](#Finding-Device-Names)
    8. [Dumping Pooltags](#Dumping-Pooltags)
4. [Known Caveats & Limitations](#Known-Caveats-&-Limitations)
5. [Credits & Acknowledgements](#Credits-&-Acknowledgements)

## Installation

Copy `DriverBuddyReloaded` folder and `DriverBuddyReloaded.py` file into the IDA plugins folder (
e.g. `C:\Program Files (x86)\IDA 7\plugins\`) or wherever you have installed IDA.

## Usage

To use the auto-analysis feature:

1. Start IDA and load a Windows kernel driver.
2. Go to `Edit -> Plugins -> Driver Buddy Reloaded` or press `CTRL+ALT+A` to start the auto-analysis.
3. Check the "Output" window for the analysis results.

To decode an IOCTLs:

1. Over the mouse over a suspected IOCTL code.
2. Right-click it and select `Driver Buddy Reloaded -> Decode IOCTL`; alternatively highlight it and then
   press `CTRL+ALT+D`.

## About Driver Buddy Reloaded

**Driver Buddy Reloaded** is an IDA Pro Python plugin that helps automate some tedious Windows Kernel Drivers reverse
engineering tasks. It has a number of handy features, such as:

* Identifying the type of the driver
* Locating `DispatchDeviceControl` and `DispatchInternalDeviceControl` functions
* Populating common structs for `WDF` and `WDM` drivers
    * Attempts to identify and label structs like the `IRP` and `IO_STACK_LOCATION`
    * Label calls to `WDF` functions that would normally be unlabeled
* Finding IOCTL codes and decoding them
* Flagging functions prone to misuse
* Finding potential Device Names
* Dumping Pooltags

![](/screenshots/auto-analysis.png)

### Finding DispatchDeviceControl

Being able to automatically locate and identify the `DispatchDeviceControl`
function is a time saving task during driver reverse engineering. This function is used to route all
incoming `DeviceIoControl` codes to the specific driver function associated with that code. Automatically identifying
this function makes finding the valid `DeviceIoControl` codes for each driver much quicker. Additionally, when
investigating possible vulnerabilities in a driver due to a crash, knowing the location of this function helps narrow
the focus to the specific function call associated with the crashing `DeviceIoControl` code.

![](/screenshots/finding-dispatchdevicecontrol.png)

### Labeling WDM Structs

Several driver structures are shared among all `WDM` drivers. Being able to automatically identify these structures,
such as the `IO_STACK_LOCATION`, `IRP`, and `DeviceObject` structures, can help save time during the reverse engineering
process. It attempts to locate and identify many of these structs.
![](/screenshots/WDM-structures.png)

### Labeling WDF Functions

As with `WDM` drivers, there are several functions and structures that are shared among all WDF drivers. Automatically
identifying these functions and structures will save time during the reverse engineering process and provide context to
areas of the driver where these functions are in use.

### Finding & Decoding IOCTL Codes

While reversing drivers, it is common to come across IOCTL codes as part of the analysis. These codes, when decoded,
reveal useful information to reverse engineers and may draw focus to specific parts of the driver where vulnerabilities
are more likely to exist.

By right-clicking on a potential IOCTL code a context menu option can be used to decode the value, alternatively
`Ctrl+Alt+D` can be used; this will print a table with all decoded IOCTL codes. By right-clicking on a decoded IOCTL
code, in the disasm view, it's possible to mark it as invalid, this will leave any non-IOCTL define based comment
contents intact.

If you right-click on the first instruction of the function you believe to be the IOCTL dispatcher, a "Decode All"
options appears, this attempt to decode all IOCTL codes it can find in the function. This is a bit hacky, but it can
speed things up most of the time.
![](/screenshots/IOCTL-table.png)
![](/screenshots/decode-IOCTL.png)

### Flagging Functions

List C/C++ functions and opcodes that are commonly vulnerable or that can facilitate buffer overflow conditions are
reported back by the auto-analysis feature and can speed things up while looking for possible user-controlled code paths
reaching sensitive functions.

![](/screenshots/flagging-functions.png)

### Finding Device Names

It attempts to find the drivers registered device paths, if no paths can be found by looking at Unicode strings inside
the binary, then the analyst can manually use [FLOSS](https://github.com/mandiant/flare-floss/) in an attempt to find
obfuscated paths.
![](/screenshots/devicename.png)

### Dumping Pooltags

It's possible to dump the pooltags in use by the binary in a format which works with `pooltags.txt`. This means the
output can be copy-pasted at the end of the file and then be picked up by WinDbg etc.
![](/screenshots/pooltag.png)

## Known Caveats & Limitations

- Experimental `DispatchDeviceControl` searching works only for x64 drivers
- Shortcuts are incompatible with FSecure's [win_driver_plugin](https://github.com/FSecureLABS/win_driver_plugin)

## Credits & Acknowledgements

- Created in 2021 by [Paolo Stagno](https://voidsec.com/) aka [@Void_Sec](https://twitter.com/Void_Sec):
    - Made it compatible with Python 3.x
    - Made it compatible with IDA 7.x
    - Updated C/C++ function and Windows APIs list
    - Various bug fixing
    - Various improvements
    - Integrated part of the functionalities present in FSecure's win_driver_plugin
- [DriverBuddy](https://github.com/nccgroup/DriverBuddy) was originally written by Braden Hollembaek and Adam Pond of NCC Group
- Using Satoshi Tanda's IOCTL decoder, originally found here https://github.com/tandasat/WinIoCtlDecoder.
- The WDF functions struct is based on Red Plait's work (http://redplait.blogspot.ru/2012/12/wdffunctionsidc.html) and
  was ported to IDA Python by Nicolas Guigo, later updated by Braden Hollembaek and Adam Pond.
- Using Sam Brown's FSecure [win_driver_plugin](https://github.com/FSecureLABS/win_driver_plugin) to retrieve device
  name and pool tags, specifically Alexander Pick [fork](https://github.com/alexander-pick/win_driver_plugin).
- The original code for adding items to the right-click menu (and possibly some other random snippets) came
  from '[herrcore](https://gist.github.com/herrcore/b3143dde185cecda7c1dee7ffbce5d2c)'.
