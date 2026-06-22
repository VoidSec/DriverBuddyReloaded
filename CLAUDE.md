# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Run pure-Python regression tests (no IDA required)
```
python tests/test_dbr.py
DBR_SDK=900 python tests/test_dbr.py    # simulate IDA 9.0 import paths
```
19 checks, all logic that does not touch the live IDA database. Run both variants on every change.

### Run cross-version smoke tests (requires all three IDA installs)
```
pwsh tests\run_cross_version.ps1
pwsh tests\run_cross_version.ps1 -Timeout 180 -KeepTemp
```
Launches IDA 7.6 SP1, 8.4, and Free 9.3 in batch mode against real `.sys` files and prints a pass/fail matrix. Results land in `smoke_results/`.

### IDA installs
- `C:\Users\c108\Desktop\IDA Pro 7.6 SP1\ida64.exe`
- `C:\Program Files\IDA Pro 8.4\ida64.exe`
- `C:\Program Files\IDA Free 9.3\ida.exe` (unified 32/64 on 9.3; only `ida.exe` exists)

### Install the plugin
Copy `DriverBuddyReloaded/` and `DriverBuddyReloaded.py` to `%APPDATA%\Hex-Rays\IDA Pro\plugins\` or the IDA install's `plugins\` directory.

---

## Architecture

### Execution flow
```
DriverBuddyReloaded.py          <- IDA plugin_t (init / run / term / UI hooks)
  |
  +-- analysis.run_analysis(rep)  <- full pipeline; headless-callable without plugin_t
        |
        +-- utils.py              device/WDM/WDF identification, AnalysisContext
        +-- wdm.py / wdf.py       structure labelling, DDC address discovery
        +-- device_name_finder.py unicode device paths
        +-- dump_pool_tags.py     pool tag extraction
        +-- irp_mj.py             IRP_MJ_FUNCTION IDA enum (WDM only)
        +-- ioctl_decoder.py      find_ioctls + scan_dispatchers (auto flow-chart scan)
        +-- callchain.py          BFS handler -> dangerous sink tracing
        +-- heuristics.py         seven checks: copy-validation, priv-gate, IRQL, MDL,
        |                         alloca, pool-alloc-trust, physical-mem-ref
        +-- exports_audit.py      zero-xref export detection
        +-- find_opcodes.py       opcode scan (off by default: Feature.SEGMENT_OPCODE_SCAN)
        +-- scoring.py            IOCTL risk scoring + severity bump
        +-- reporting.py          JSON / HTML / results window / IOCTL window
        +-- poc.py                DeviceIoControl PoC harness
```

### The Reporter spine
Every module emits `Finding` objects (defined in `reporting.py`) via `rep.add_finding(category, title, ...)` instead of bare `print()`. `rep.info()` writes INFO-level lines. At the end of a run the Reporter renders the clickable findings window (`ResultsChooser`), the IOCTL recap window (`IOCTLChooser`), `findings.json`, `report.html`, and `ioctl_pocs.c`. Never bypass the Reporter with direct `print()` calls.

### Plugin UI layer (DriverBuddyReloaded.py)
`DriverBuddyReloaded.py` owns all IDA UI concerns and delegates analysis to `analysis.run_analysis()`.

- **Hotkeys**: `Ctrl+Alt+A` auto-analysis, `Ctrl+Alt+D` decode IOCTL at cursor, `Ctrl+Alt+F` decode all in function, `Ctrl+Alt+I` open IOCTLs window, `Ctrl+Alt+W` open findings window.
- **Right-click menu** (disassembly view): Decode All IOCTLs in Function, Show all IOCTLs, Show Findings, Decode IOCTL (when cursor is on an immediate), Invalid IOCTL (when already decoded).
- **`IOCTLChooser`**: severity-colored chooser showing Severity / Address / Code / Device / Method / Access / Fn# columns. Populated from `rep.by_category("ioctl")` after auto-analysis, or from `IOCTLChooser.from_pairs(ioctl_tracker.ioctls)` for the interactive decode session.
- **`_last_rep`**: module-level variable storing the Reporter from the most recent auto-analysis run. `show_all_ioctls()` and `show_findings()` use it so both windows can be reopened at any time without re-running analysis.
- **`IOCTLTracker`**: tracks interactively-decoded IOCTL codes (address, value) across the session; separate from the Reporter findings.

### Output file naming
`config.out_path(suffix)` returns `<IDB_DIR>/<DRIVER_NAME>-<DATE>-<UNIX_TS>-<suffix>`. All output artefacts share the same timestamp for a given run (`config._run_stamp`, reset in `DriverBuddyPlugin.run()`).

### Compatibility layer (ida_compat.py)
All IDA-version-divergent API calls go through `ida_compat.py`. No other module should:
- import `ida_struct` or `ida_enum` (removed in IDA 9.0)
- call `idaapi.get_inf_structure()` (removed in IDA 9.0)
- branch on `idaapi.IDA_SDK_VERSION` directly

`ida_compat.IS_IDA9` is the single branch point. Minimum supported version is IDA 7.6.

### Feature flags
`config.Feature` class controls every optional analysis stage. Flip a flag to `False` to disable the stage without touching pipeline logic. `SEGMENT_OPCODE_SCAN` defaults to `False` (noisy). Adding a new stage: add a `Feature.X` flag, gate the call in `analysis.run_analysis()`, document it in `README.MD`.

### AnalysisContext
`utils.AnalysisContext` (dataclass) holds all per-run mutable state (maps populated by `utils.populate_data_structures()`, discovered DDC addresses, etc.). It is created fresh at the top of `run_analysis()` and threaded through all modules. Never store analysis state in module-level mutable variables.

### IOCTL decoding
Two complementary strategies, both in `ioctl_decoder.py`:
1. `find_ioctls()` - text/pattern search for CMP/SUB/MOV with immediate operands across all functions.
2. `scan_dispatchers(rep, ddc_addresses)` - flow-chart scan of the specific identified dispatcher EAs. Runs automatically when `ctx.ddc_addresses` is non-empty.

NTSTATUS filter uses `_get_ntstatus_values()` which queries the IDA type DB first, falls back to a small hardcoded set. Result is cached for the run.

### Pure-Python test harness
`tests/test_dbr.py` installs in-memory IDA stubs via `sys.modules` before any import of the plugin package. The `DBR_SDK` environment variable sets the simulated `IDA_SDK_VERSION`. Tests cover only logic that has no live-database dependency. IDA-side behaviour (structure labelling, enum creation, cross-reference walks) must be verified inside IDA via `tests/ida_smoke.py`.

### Function-name sets
All heuristic, callchain, and scoring function-name lists live in `config.py` (not scattered across modules): `DANGEROUS_SINKS`, `VALIDATION_FUNCS`, `PRIVILEGE_GATE_FUNCS`, `PRIVILEGED_SENSITIVE_OPS`, `IRQL_RAISING_FUNCS`, `MDL_USER_FUNCS`, `COPY_SINKS`, `ALLOCA_FUNCS`, `POOL_ALLOC_FUNCS`. Add to the relevant set in `config.py` when expanding coverage; modules import the set by name.

### Vulnerable function lists
`DriverBuddyReloaded/vulnerable_functions_lists/` contains four lists (`c.py`, `winapi.py`, `opcode.py`, `custom.py`) consumed by `utils.get_xrefs()` for the "flagged functions" findings. `custom.py` is the user-editable list. `winapi_function_prefixes` entries do prefix matching; `winapi_functions` entries do exact matching.
