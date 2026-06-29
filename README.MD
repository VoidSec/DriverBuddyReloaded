# Driver Buddy Reloaded Quickstart

![Driver Buddy Reloaded](img/logo.png)

## Table of Contents

- [Driver Buddy Reloaded Quickstart](#driver-buddy-reloaded-quickstart)
  - [Table of Contents](#table-of-contents)
  - [Installation](#installation)
  - [Quick Usage](#quick-usage)
    - [Advanced Usage](#advanced-usage)
  - [About Driver Buddy Reloaded](#about-driver-buddy-reloaded)
    - [Finding DispatchDeviceControl](#finding-dispatchdevicecontrol)
    - [Labelling WDM and WDF Structures](#labelling-wdm-and-wdf-structures)
    - [Finding and Decoding IOCTL Codes](#finding-and-decoding-ioctl-codes)
    - [Flagging Functions](#flagging-functions)
    - [Finding DeviceName](#finding-devicename)
    - [Dumping Pooltags](#dumping-pooltags)
    - [Heuristic Vulnerability Checks](#heuristic-vulnerability-checks)
  - [Feature Flags](#feature-flags)
  - [Testing](#testing)
  - [Known Caveats and Limitations](#known-caveats-and-limitations)
  - [Credits and Acknowledgements](#credits-and-acknowledgements)

## Installation

Copy the `DriverBuddyReloaded` folder and the `DriverBuddyReloaded.py` script file into the IDA plugins folder, for example:
- `%APPDATA%\Hex-Rays\IDA Pro\plugins\`
- `C:\Program Files\IDA Pro 8.4\plugins\`
- `~/.idapro/plugins/`

If your IDA is configured for Python 2, run the `idapyswitch` binary (located in IDA's folder) to switch it to Python 3.

**NOTE:** Driver Buddy Reloaded runs on IDA 7.x, 8.x (including 8.4) and 9.0+ with Python 3. All version-specific
IDA API differences (the removal of `get_inf_structure`, the `ida_struct` module and the `idc.*struc*` helpers in
IDA 9.0, etc.) are handled internally by the `DriverBuddyReloaded/ida_compat.py` compatibility layer.

## Quick Usage

To use the auto-analysis feature:

1. Start IDA and load a Windows kernel driver.
2. Go to `Edit -> Plugins -> Driver Buddy Reloaded` or press `CTRL+ALT+A` to start the auto-analysis.
3. Check the "Output" window for the analysis results, and the **Driver Buddy Reloaded - Findings** window that opens
   at the end of the run (double-click a row to jump to its address).
4. The following files are written under IDA's DB directory (all prefixed with `<DRIVER_NAME>-YYYY-MM-DD-TIMESTAMP-`):
   - `findings.json` - machine-readable findings (IOCTLs, flagged functions, device names, pooltags, call chains, heuristics)
   - `report.html` - a standalone, severity-grouped HTML report
   - `pooltags.txt` - dumped Pooltags in `pooltags.txt` format for WinDbg
   - `autoanalysis.txt` - the full text analysis log (mirrors the Output window)

To decode an IOCTL:

1. Place the mouse cursor on the line containing a suspected IOCTL code.
2. Right-click and select `Driver Buddy Reloaded -> Decode IOCTL`; alternatively, press the `CTRL+ALT+D` shortcut.

To decode ALL IOCTLs within a function:

1. Place the mouse cursor on the first instruction of the function you believe to be the IOCTL dispatcher (
   `DispatchDeviceControl`, `DispatchInternalDeviceControl`, `Possible_DispatchDeviceControl_#`)
2. Right-click and select `Driver Buddy Reloaded -> Decode ALL IOCTLs in Function`; alternatively, press the `CTRL+ALT+F`
   shortcut.
3. The decoded IOCTLs are printed to the Output window and listed in the severity-coloured IOCTLs window.

To reopen the IOCTLs window or findings window at any time (without re-running analysis):

- Press `CTRL+ALT+I` to open the IOCTLs window.
- Press `CTRL+ALT+W` to open the findings window.

### Advanced Usage

- The [vulnerable_function_lists](DriverBuddyReloaded/vulnerable_functions_lists) directory contains a lists of potentially
  dangerous/problematic functions, Windows APIs and opcodes; a brief description on why a specific function/API has been listed is
  provided. You can edit the `custom` list including driver's specific functions.
  
  **Note**: `winapi_function_prefixes` will partial match to start of function name (e.g. `Zw` will match `ZwClose`, `ZwCommitComplete` and so on) while `winapi_functions` will perform exact matches only.
- In [find_opcodes.py](DriverBuddyReloaded/find_opcodes.py), the `find_opcode_data` option will prevent Driver Buddy
  Reloaded to find opcodes in data sections. Switching it to `True` will print something along
  this [line](https://github.com/VoidSec/DriverBuddyReloaded/issues/11):
  `Found jnz     short loc_15862 in sub_15820 at 0x00015852`
  Usually, going at the showed address and re-defining the selection as code will bring the searched opcode back.
  
  **Watch out**: switching it to `True`, will generates more false positives!

## About Driver Buddy Reloaded

**Driver Buddy Reloaded** is an IDA Pro Python plugin that helps automate some tedious Windows Kernel Drivers reverse
engineering tasks. It has a number of handy features, such as:

* Identifying the type of the driver (WDM, KMDF, UMDF, Mini-Filter, Stream Minidriver, AVStream, PortCls)
* Locating `DispatchDeviceControl` / `DispatchInternalDeviceControl` functions
* Populating common structures for `WDF` and `WDM` drivers
    * Attempts to identify and label structures like the `IRP` and `IO_STACK_LOCATION`
    * Label calls to `WDF` functions that would normally be unlabeled
    * Creates an `IRP_MJ_FUNCTION` IDA enum and applies it to `MajorFunction` array slots in `DriverEntry` (WDM)
* Finding and decoding IOCTL codes
    * Automatic multi-strategy scan of identified dispatcher functions (no cursor placement required):
      decompiler ctree (recovers codes hidden by jump-table or binary-search dispatch that never appear as
      immediates), IDA switch-table recovery, and a raw immediate-operand fallback
    * NTSTATUS values resolved dynamically from the IDA type database (no static list)
* Flagging functions prone to misuse
* Finding potential `DeviceName` (mmap scan + IDA Strings DB fallback, with source address)
* Dumping `Pooltags` (import-based primary + register-propagated fallback for tags staged in a register)
* **Heuristic vulnerability checks** over each dispatcher and the functions it transitively calls: unvalidated
  user-copy, TOCTOU/double-fetch, use-after-free (intra-function and cross-function via a freed global), missing
  privilege gate, IRQL mismatch, unsafe MDL mapping, stack-allocated buffers (`_alloca`), pool allocation without
  size validation, privileged CPU instructions (port I/O `in`/`out`, `mov cr*`), arbitrary-write
  (write-what-where), and `\Device\PhysicalMemory` references (BYOVD pattern) - see
  [Heuristic Vulnerability Checks](#heuristic-vulnerability-checks)
* **Device ACL audit and symbolic-link tracking**: flags `IoCreateDevice` devices created with no security
  descriptor (world-accessible) / weak `IoCreateDeviceSecure` SDDLs, and decodes `IoCreateSymbolicLink` target paths
* **Exports audit**: flags driver exports with zero internal cross-references (potential attack surface)
* **Risk-scoring** decoded IOCTLs (prioritising `METHOD_NEITHER` / `FILE_ANY_ACCESS`, and bumping the IOCTLs whose
  own handler reaches a dangerous sink such as `MmMapIoSpace`, `memcpy`, `__writemsr`, port I/O or PCI-config
  access) and presenting all findings, by severity, in a clickable results window (double-click to jump to the address)
* **Tracing call chains** from dispatch / IOCTL handlers to dangerous sinks (heuristic, name-based)
* Exporting results as a machine-readable **JSON** file and a standalone **HTML report**

![](img/auto-analysis.png)

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

![](img/finding-dispatchdevicecontrol.png)

### Labelling WDM and WDF Structures

Several driver structures are shared among all `WDM`/`WDF` drivers. The tool is able to automatically identify these
structures, such as the `IO_STACK_LOCATION`, `IRP`, and `DeviceObject` structures and can help save time during the
reverse engineering process and provide context to areas of the driver where these functions are in use.

![](img/WDM-structures.png)

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
Reloaded menu, a "**Decode All**" option appears, this attempt to decode all the IOCTL codes it can find in the
function. This is a bit hacky but most of the time it can speed things up.

- The decoded IOCTLs are printed to the Output window and listed in the severity-coloured IOCTLs window; after
  auto-analysis they are also recorded in `findings.json` / `report.html`.

Auto-analysis additionally runs a multi-strategy scan over identified dispatcher functions to discover IOCTLs
automatically, without requiring manual cursor placement. For each dispatcher it uses the Hex-Rays decompiler
(when available) to read switch-case labels and `==`/`!=` comparison constants directly from the reconstructed
control flow, falling back to IDA's switch-table metadata and then to a raw immediate-operand scan. The
decompiler path recovers codes that never appear verbatim in the disassembly - e.g. drivers whose dispatcher
the compiler emitted as a jump table (only the table base/bound survive as immediates) or as a binary-search
comparison tree (intermediate codes survive only as deltas). On a representative corpus this raised recovery
from 7/28 to 28/28 (HEVD) and 4/17 to 17/17 (ALSysIO64) with no false positives.

![](img/IOCTL-table.png)
![](img/decode-IOCTL.png)

### Flagging Functions

Driver Buddy Reloaded has lists of C/C++ functions, opcodes and Windows APIs (defined in
the [vulnerable_function_lists](DriverBuddyReloaded/vulnerable_functions_lists) directory) that are commonly vulnerable
or that can facilitate buffer overflow conditions. All found instances are reported back during the auto-analysis and
can help while looking for possible user-controlled code paths reaching sensitive functions.

![](img/flagging-functions.png)

### Finding DeviceName

The tool automatically attempts to find the drivers registered device paths (`DeviceName`), if no paths can be found by
looking at Unicode strings inside the binary, then the analyst can manually try to use
Madiant's [FLOSS](https://github.com/mandiant/flare-floss/) in an attempt to find obfuscated paths.

![](img/devicename.png)

### Dumping Pooltags

During the auto-analysis, the tool also dumps the `Pooltags` used by the binary in a format that works
with `pooltags.txt`. The output can then be copy-pasted at the end of the file and later picked up by WinDbg.

- A `DriverName.sys-DATE-TIME_STAMP-pooltags.txt` file, containing all the dumped Pooltags, will be written under
  IDA's DB directory.

![](img/pooltag.png)

### Heuristic Vulnerability Checks

The `heuristics.py` module runs after call-chain tracing and examines each dispatcher **and the functions it
transitively calls** - so the per-IOCTL handlers, not just the dispatcher prologue, are analysed. Callee matching
is import-aware (an imported `call cs:__imp_<Name>` matches the same name as a local call). It emits findings in
the **heuristic** category (privileged-instruction findings use the **opcode** category):

| Check | What is flagged | Severity |
|---|---|---|
| Unvalidated user copy | `memcpy`/`RtlCopyMemory`/etc. with no nearby `ProbeForRead`/`ProbeForWrite`/safe-string guard | HIGH (handler), MEDIUM (other) |
| TOCTOU / double fetch | a user-mode pointer field re-read on one control-flow path with no intervening `ProbeForRead` (only on METHOD_NEITHER handlers, so kernel-buffer re-reads are not flagged) | MEDIUM |
| Use-after-free | a freed pointer reused intra-function (register CFG walk), or a global freed without being nulled and then dereferenced from another function | HIGH |
| Missing privilege gate | a sensitive op (`ZwOpenProcess`/`MmMapIoSpace`/PCI-config/etc.) reachable from a dispatcher with no `SeAccessCheck`/`SeSinglePrivilegeCheck`/token check anywhere on the path | HIGH |
| IRQL mismatch | Pageable / `Zw*` / `MmMap*` call when an IRQL-raising function is also present | MEDIUM |
| Unsafe MDL mapping | `MmMapLockedPages`/`MmProbeAndLockPages`/etc. with `UserMode` in disassembly | HIGH, else MEDIUM |
| Stack allocation | `_alloca`/`_malloca`/`_chkstk` call (large or dynamic stack allocation) | LOW |
| Pool alloc without size validation | `ExAllocatePool*` call with no safe-arithmetic guard nearby (integer-overflow-before-alloc pattern) | HIGH |
| Privileged instruction | port I/O (`in`/`out`), control/debug-register move (`mov cr*`/`mov dr*`), descriptor-table load, `cli`/`sti`/`hlt` reachable from a handler (BYOVD hardware-access primitive) | CRITICAL (`out`) / HIGH (`in`) / MEDIUM |
| Arbitrary write (write-what-where) | a store through a double-dereferenced user pointer `*(*p) = c`; a `*p = *q` controlled copy is reported as a weaker lead | HIGH / MEDIUM |
| `\Device\PhysicalMemory` reference | Cross-reference to the physical memory device object string (BYOVD pattern via `ZwOpenSection`/`ZwMapViewOfSection`) | HIGH (handler), MEDIUM (other) |

These are **lead generators**, not confirmed vulnerabilities. Treat HIGH/CRITICAL findings as starting points for
manual review.

## Feature Flags

All optional analysis stages are controlled by `DriverBuddyReloaded/config.py`. Edit the `Feature` class to
enable or disable them:

| Flag | Default | Description |
|---|---|---|
| `IOCTL_SCAN` | `True` | Discover & decode IOCTLs (dispatcher scan + `IoControlCode` fallback) |
| `IOCTL_DECOMPILER` | `True` | Use the Hex-Rays ctree in the dispatcher scan (recovers jump-table / binary-search codes) |
| `HEURISTICS` | `True` | Heuristic vulnerability checks (see the table above) |
| `TOCTOU_CHECK` | `True` | Double-fetch / TOCTOU heuristic |
| `UAF_DETECT` | `True` | Use-after-free heuristics (intra-function register walk + cross-function global) |
| `ACL_AUDIT` | `True` | Flag world-accessible `IoCreateDevice` / weak `IoCreateDeviceSecure` SDDL |
| `SYMLINK_TRACK` | `True` | Decode `IoCreateSymbolicLink` target paths |
| `CALLCHAIN` | `True` | BFS call-chain tracing from handlers to dangerous sinks |
| `EXPORTS_AUDIT` | `True` | Flag driver exports with zero internal cross-references |
| `POOLTAG_FALLBACK` | `True` | Register-propagated pool tag scanner (used when import-based scan finds nothing) |
| `IRP_MJ_ENUM` | `True` | Create `IRP_MJ_FUNCTION` IDA enum and apply to `MajorFunction` slots (WDM only) |
| `RISK_SCORING` | `True` | IOCTL risk scoring (METHOD/ACCESS weights + per-handler sink bump) |
| `RESULTS_WINDOW` | `True` | Show the Driver Buddy Reloaded findings window after analysis |
| `JSON_EXPORT` | `True` | Write `findings.json` |
| `HTML_REPORT` | `True` | Write `report.html` |
| `SEGMENT_OPCODE_SCAN` | `False` | Linear segment-wide opcode scan (noisy, off by default) |

## Testing

Three layers, from fast to thorough:

- **Pure-Python regression** (no IDA required) - covers all logic that does not touch the live database:
  ```
  python tests/test_dbr.py
  DBR_SDK=900 python tests/test_dbr.py   # simulate the IDA 9.0 import paths
  ```
- **Cross-version smoke** - runs the full pipeline under IDA 7.6 SP1, 8.4 and Free 9.3 against a matrix of real
  `.sys` files and prints a pass/fail table: `pwsh tests/run_cross_version.ps1`.
- **Golden-output regression** (the false-positive / false-negative guard) - `pwsh tests/run_golden.ps1` re-runs
  the full analysis on a pristine copy of each reference driver in `tests/drivers/` and compares the findings to
  the committed `tests/drivers/<driver>.golden.json` baseline (order-insensitive on category, title, severity and
  IOCTL code/method/access). Any added finding (false positive), missing finding (false negative) or severity
  change fails the run. Regenerate a golden only when a change intentionally alters findings, and review the diff.
  Goldens are tied to the IDA decompiler build they were captured with (8.4), so run the regression with that version.

## Known Caveats and Limitations

- IOCTL candidates are validated against the `CTL_CODE` structure: the DeviceType field (bits 31-16) must be non-zero, and the value must not match a known NTSTATUS code. This rules out loop counters and small immediates while preserving all valid IOCTLs including vendor-defined device types (`0x8000+`). The filter is applied by both the `IoControlCode` xref scan and the dispatcher flow-chart scan. [Issue #15](https://github.com/VoidSec/DriverBuddyReloaded/issues/15)
- Risk scoring and call-chain tracing are **heuristic, name-based lead generators**, not dataflow analysis; treat
  High/Critical findings as places to look first, not as confirmed vulnerabilities. Feature toggles live in
  `DriverBuddyReloaded/config.py`.
- Experimental `DispatchDeviceControl` searching works only for x64 drivers
- In [find_opcodes.py](DriverBuddyReloaded/find_opcodes.py), the `find_opcode_data` option will prevent Driver Buddy
  Reloaded to find opcodes in data sections. Switching it to `True` will print something along
  this line:
  `Found jnz     short loc_15862 in sub_15820 at 0x00015852`
  Usually, going at the showed address and re-defining the selection as code will bring the searched opcode back.
  **Watch out**: It is prone to false positives!

## Credits and Acknowledgements

- Created in 2021 by [Paolo Stagno](https://voidsec.com/) aka [@Void_Sec](https://twitter.com/Void_Sec):
- Risk-scoring and reporting ideas adapted from
  [Driver Buddy Revolutions](https://github.com/jsacco/driverbuddyrevolutionsIDA) by Juan Sacco.
- [DriverBuddy](https://github.com/nccgroup/DriverBuddy) was originally written by Braden Hollembaek and Adam Pond of
  NCC Group.
- Using Satoshi Tanda's [IOCTL decoder](https://github.com/tandasat/WinIoCtlDecoder).
- The WDF functions struct is based on [Red Plait's work](http://redplait.blogspot.ru/2012/12/wdffunctionsidc.html) and
  was ported to IDA Python by Nicolas Guigo, later updated by Braden Hollembaek and Adam Pond.
- Using Sam Brown's F-Secure [win_driver_plugin](https://github.com/FSecureLABS/win_driver_plugin) to retrieve device
  name and pool tags, specifically Alexander Pick [fork](https://github.com/alexander-pick/win_driver_plugin).
- The original code for adding items to the right-click menu (and possibly some other random snippets) came
  from '[herrcore](https://gist.github.com/herrcore/b3143dde185cecda7c1dee7ffbce5d2c)'.
- Proudly developed using **PyCharm** for [Open Source development](https://www.jetbrains.com/community/opensource/#support) by JetBrains
