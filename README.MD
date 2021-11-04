# Driver Buddy Reloaded Quickstart

## Table of Contents

1. [Installation](#Installation)
2. [Usage](#Usage)
3. [About Driver Buddy Reloaded](#About-Driver-Buddy-Reloaded)
    1. [Finding DispatchDeviceControl](#Finding-DispatchDeviceControl)
    2. [Labelling WDM & WDF Structures](#Labelling-WDM-and-WDF-Structures)
    3. [Finding & Decoding IOCTL Codes](#Finding-and-Decoding-IOCTL-Codes)
    4. [Flagging Functions](#Flagging-Functions)
    5. [Finding DeviceName](#Finding-DeviceName)
    6. [Dumping Pooltags](#Dumping-Pooltags)
4. [Known Caveats & Limitations](#Known-Caveats-and-Limitations)
5. [Credits & Acknowledgements](#Credits-and-Acknowledgements)

## Installation

Copy `DriverBuddyReloaded` folder and `DriverBuddyReloaded.py` file into the IDA plugins folder (
e.g. `C:\Program Files (x86)\IDA 7\plugins\`) or wherever you have installed IDA.

## Usage

To use the auto-analysis feature:

1. Start IDA and load a Windows kernel driver.
2. Go to `Edit -> Plugins -> Driver Buddy Reloaded` or press `CTRL+ALT+A` to start the auto-analysis.
3. Check the "Output" window for the analysis results.

To decode an IOCTL:

1. Place the mouse cursor on the line containing a suspected IOCTL code.
2. Right-click and select `Driver Buddy Reloaded -> Decode IOCTL`; alternatively press the `CTRL+ALT+D` shortcut.

To decode ALL IOCTLs within a function:

1. Place the mouse cursor on the first instruction of the function you believe to be the IOCTL dispatcher (
   `DispatchDeviceControl`, `DispatchInternalDeviceControl`, `Possible_DispatchDeviceControl_#`)
2. Right-click and select `Driver Buddy Reloaded -> Decode ALL IOCTLs in Function`; alternatively press the `CTRL+ALT+F`
   shortcut.

## About Driver Buddy Reloaded

**Driver Buddy Reloaded** is an IDA Pro Python plugin that helps automate some tedious Windows Kernel Drivers reverse
engineering tasks. It has a number of handy features, such as:

* Identifying the type of the driver
* Locating `DispatchDeviceControl` / `DispatchInternalDeviceControl` functions
* Populating common structures for `WDF` and `WDM` drivers
    * Attempts to identify and label structures like the `IRP` and `IO_STACK_LOCATION`
    * Label calls to `WDF` functions that would normally be unlabeled
* Finding and decoding IOCTL codes
* Flagging functions prone to misuse
* Finding potential `DeviceName`
* Dumping `Pooltags`

![](/screenshots/auto-analysis.png)

### Finding DispatchDeviceControl

The tool can automatically locate and identify the `DispatchDeviceControl` routine. This function is used to route all
incoming `DeviceIoControl` codes to the specific driver function associated with that code. Automatically identifying
this function makes finding the valid `DeviceIoControl` codes for each driver much quicker. Additionally, when
investigating possible vulnerabilities in a driver due to a crash, knowing the location of this function helps narrow
the focus to the specific function call associated with the crashing `DeviceIoControl` code.

When the analysis is successful some subs will be renamed as follow:

- `DriverEntry`: the original first driver-supplied routine that is called after a driver is loaded. It is responsible
  for initializing the driver.
- `Real_Driver_Entry`: usually the function where the execution from `DriverEntry` has been transferred to. It is
  usually where the `DeviceName` is initialized.
- `DispatchDeviceControl`/`DispatchInternalDeviceControl`: if the tool was able to recover the functions at some
  specific offsets, the functions will then be renamed with the appropriate name.
- `Possible_DispatchDeviceControl_#`: if the tool was not able to recover `DispatchDeviceControl`
  or `DispatchInternalDeviceControl`, it employs an experimental searching, following the execution flow, and checking
  for cases where the function is loading known `IO_STACK_LOCATION` & `IRP` addresses; indicating that the function
  could be the DispatchDeviceControl. As it is based on heuristic, it could return more than one result, and it is prone
  to false positives.

![](/screenshots/finding-dispatchdevicecontrol.png)

### Labelling WDM and WDF Structures

Several driver structures are shared among all `WDM`/`WDF` drivers. The tool is able to automatically identify these
structures, such as the `IO_STACK_LOCATION`, `IRP`, and `DeviceObject` structures and can help save time during the
reverse engineering process and provide context to areas of the driver where these functions are in use.

![](/screenshots/WDM-structures.png)

### Finding and Decoding IOCTL Codes

While reversing drivers, it is common to come across IOCTL codes as part of the analysis. These codes, when decoded,
reveal useful information and may draw focus to specific parts of the driver where vulnerabilities are more likely to
exist.

By right-clicking on a potential IOCTL code, a context menu option is presented (alternatively using the
`Ctrl+Alt+D` shortcut when the cursor is on the line containing a suspected IOCTL code) and can be used to decode the
value. This will print out a table with all decoded IOCTL codes. By right-clicking on a decoded IOCTL code, in the
disassembly view, it's possible to mark it as invalid; this will leave any non-IOCTL comment intact.

If you right-click, alternatively using the
`Ctrl+Alt+F` shortcut, on the first instruction of the function you believe to be the IOCTL dispatcher (
`DispatchDeviceControl`, `DispatchInternalDeviceControl`, `Possible_DispatchDeviceControl_#`) under the Driver Buddy
Reloaded menu, a “**Decode All**” option appears, this attempt to decode all the IOCTL codes it can find in the
function. This is a bit hacky but most of the time it can speed things up.

![](/screenshots/IOCTL-table.png)
![](/screenshots/decode-IOCTL.png)

### Flagging Functions

Driver Buddy Reloaded has a list of C/C++ functions and opcodes as well as Windows API that are commonly vulnerable or
that can facilitate buffer overflow conditions. All found instances are reported back during the auto-analysis and can
help while looking for possible user-controlled code paths reaching sensitive functions.

![](/screenshots/flagging-functions.png)

### Finding DeviceName

The tool automatically attempts to find the drivers registered device paths (`DeviceName`), if no paths can be found by
looking at Unicode strings inside the binary, then the analyst can manually try to use
Madiant’s [FLOSS](https://github.com/mandiant/flare-floss/) in an attempt to find obfuscated paths.

![](/screenshots/devicename.png)

### Dumping Pooltags

During the auto-analysis, the tool also dumps the `Pooltags` used by the binary in a format that works
with `pooltags.txt`. The output can then be copy-pasted at the end of the file and later picked up by WinDbg.

![](/screenshots/pooltag.png)

## Known Caveats and Limitations

- Experimental `DispatchDeviceControl` searching works only for x64 drivers
- Shortcuts are incompatible with F-Secure's [win_driver_plugin](https://github.com/FSecureLABS/win_driver_plugin)
- Shortcuts are incompatible with [findcrypt-yara](https://github.com/polymorf/findcrypt-yara)

## Credits and Acknowledgements

- Created in 2021 by [Paolo Stagno](https://voidsec.com/) aka [@Void_Sec](https://twitter.com/Void_Sec):
    - Made it compatible with Python 3.x
    - Made it compatible with IDA 7.x
    - Updated C/C++ function and Windows APIs list
    - Various bug fixing
    - Various improvements
    - Integrated part of the functionalities presents in F-Secure's win_driver_plugin
- [DriverBuddy](https://github.com/nccgroup/DriverBuddy) was originally written by Braden Hollembaek and Adam Pond of
  NCC Group.
- Using Satoshi Tanda's [IOCTL decoder](https://github.com/tandasat/WinIoCtlDecoder).
- The WDF functions struct is based on [Red Plait's work](http://redplait.blogspot.ru/2012/12/wdffunctionsidc.html) and
  was ported to IDA Python by Nicolas Guigo, later updated by Braden Hollembaek and Adam Pond.
- Using Sam Brown's F-Secure [win_driver_plugin](https://github.com/FSecureLABS/win_driver_plugin) to retrieve device
  name and pool tags, specifically Alexander Pick [fork](https://github.com/alexander-pick/win_driver_plugin).
- The original code for adding items to the right-click menu (and possibly some other random snippets) came
  from '[herrcore](https://gist.github.com/herrcore/b3143dde185cecda7c1dee7ffbce5d2c)'.
