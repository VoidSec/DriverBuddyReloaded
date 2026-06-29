# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Run pure-Python regression tests (no IDA required)
```
python tests/test_dbr.py
DBR_SDK=900 python tests/test_dbr.py    # simulate IDA 9.0 import paths
```
27 checks, all logic that does not touch the live IDA database. Run both variants on every change.

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
        +-- utils.py              device/WDM/WDF identification, AnalysisContext, ACL audit (find_device_create_calls)
        +-- wdm.py / wdf.py       structure labelling, DDC address discovery
        +-- device_name_finder.py unicode device paths, symbolic link tracking (find_symbolic_links)
        +-- dump_pool_tags.py     pool tag extraction
        +-- irp_mj.py             IRP_MJ_FUNCTION IDA enum (WDM only)
        +-- ioctl_decoder.py      find_ioctls + scan_dispatchers (auto flow-chart scan)
        +-- callchain.py          BFS handler -> dangerous sink tracing
        +-- heuristics.py         nine checks: copy-validation, priv-gate, IRQL, MDL,
        |                         alloca, pool-alloc-trust, physical-mem-ref, double-fetch (TOCTOU),
        |                         use-after-free (UAF CFG walk)
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
`utils.AnalysisContext` (dataclass) holds all per-run mutable state (maps populated by `utils.populate_data_structures()`, discovered DDC addresses, `real_entry_addr` for the real DriverEntry after stripping any GsDriverEntry stub, etc.). It is created fresh at the top of `run_analysis()` and threaded through all modules. Never store analysis state in module-level mutable variables.

### HexRays enum annotations (irp_mj.py)
`irp_mj.py` writes `user_numforms` entries so the decompiler renders
`MajorFunction[IRP_MJ_CREATE]` instead of `MajorFunction[0]`. Three non-obvious
requirements discovered through live debugging:

1. **Enum flag**: `number_format_t.flags` must have bit 23 set (`0x00800000`) for
   `type_name` to survive a `save_user_numforms` / `restore_user_numforms`
   round-trip. Without it IDA silently discards `type_name` during serialisation.
2. **opnum = 0**: synthesised array-index constants (the `2` in `MajorFunction[2]`)
   use `opnum=0` in `operand_locator_t` -- matching what IDA's own `M` key stores.
   Inserting at `OPND_OUTER` (0xFFFE) as well causes silent save corruption in
   IDA 7.6, so only `opnum=0` is used.
3. **Standalone API**: `cfuncptr_t.user_numforms` is not exposed as a Python
   attribute in IDA 7.6. Use the standalone `restore_user_numforms(func_ea)` /
   `save_user_numforms(func_ea, nf_map)` instead.

`ctx.real_entry_addr` (set in `get_driver_id()` via `check_for_fake_driver_entry()`)
is passed to `irp_mj.run()` instead of the raw `driver_entry_addr`. Some drivers
export a tiny `/GS` security-cookie stub (`GsDriverEntry`) that contains no
`MajorFunction` assignments; the ctree visitor finds nothing in the stub.

### IOCTL decoding
Two complementary entry points, both in `ioctl_decoder.py`. `analysis.run_analysis()` runs `scan_dispatchers()` **first** (precise) and only falls back to `find_ioctls()` (fuzzy) when the dispatcher scan recovered nothing:

1. `scan_dispatchers(rep, ddc_addresses)` - the primary path; runs three collectors per dispatcher EA and merges them through `_emit_ioctl()` (single dedup + validation funnel):
   - `_collect_hexrays_consts()` - decompiles the dispatcher and walks the ctree for switch-case labels and `==`/`!=` comparison constants. This is the only method that recovers codes the compiler did not leave as immediates: **jump-table dispatch** (only the table base/bound survive as immediates; e.g. ALSysIO64) and **binary-search comparison trees** (intermediate codes survive only as deltas; e.g. 21 of HEVD's 28). Gated on `config.Feature.IOCTL_DECOMPILER` + HexRays availability.
   - `_collect_switch_cases()` - IDA `get_switch_info` + `calc_switch_cases`, excluding the `defjump` group (so the dense filler values between real cases are dropped). Recovers jump-table dispatch **without** the decompiler.
   - `_collect_immediates()` - the original `cmp`/`sub`/`mov` immediate-operand flow-chart scan. Low precision (cannot distinguish an IOCTL from an NTSTATUS code moved into a register), so it runs **only as a last resort** when the two structured collectors found nothing for that dispatcher.
2. `find_ioctls()` - walks `IoControlCode` matches that IDA resolved from struct type info; a fuzzy whole-binary text scan kept as a fallback for when dispatcher detection fails (no DDC / stripped). It can mistake data constants for IOCTLs, which is why it no longer runs when `scan_dispatchers()` succeeds.

**Decompiler comparison anchoring**: switch-case labels are always trusted; `==`/`!=` constants are not. When the dispatcher contains a switch, only comparisons against a switch-selector variable are kept (a `status == STATUS_BUFFER_TOO_SMALL` check on an unrelated lvar is ignored). When there is no switch to anchor on (pure if-chain dispatcher, e.g. beep), every comparison constant is taken and left to the structural/NTSTATUS/sentinel filter.

Every candidate runs through `_is_valid_ctl_code()`, which validates the CTL_CODE structure (DeviceType bits[31:16] must be non-zero), rejects the `0xFFFFFFFF` (`== -1`) sentinel via `_SENTINEL_REJECTS`, and rejects known NTSTATUS values via `_get_ntstatus_values()`. The structural check is equivalent to the old `>= 0x10000` floor but expresses the intent explicitly. `config.IOCTL_MIN_VALUE` was removed -- the check now lives entirely in `_is_valid_ctl_code()`.

Validated exact recovery (full pipeline, IDA 7.6 SP1 + 8.4): HEVD 28/28, ALSysIO64 17/17, WinRing0x64 18/18, beep 2/2, no false positives. IDA Free 9.x cannot be driven headlessly (`-S` batch scripting is disabled in the Free edition), so cross-version smoke for 9.x must be run interactively; the new code uses only 7.6-9.x-stable APIs (`ida_nalt.get_switch_info`, `idaapi.calc_switch_cases`, `ida_hexrays` ctree), each getattr-guarded with graceful `[]` fallback.

NTSTATUS filter queries the IDA type DB first (`NTSTATUS` / `_NTSTATUS` enum), falls back to a small hardcoded set. Result is cached for the run.

### Pure-Python test harness
`tests/test_dbr.py` installs in-memory IDA stubs via `sys.modules` before any import of the plugin package. The `DBR_SDK` environment variable sets the simulated `IDA_SDK_VERSION`. Tests cover only logic that has no live-database dependency. IDA-side behaviour (structure labelling, enum creation, cross-reference walks) must be verified inside IDA via `tests/ida_smoke.py`.

### IDA smoke test modes (T5-T7)
`tests/ida_smoke.py` supports three optional check modes passed via `idc.ARGV`:
- `--golden <ref.json>`: order-insensitive comparison of findings against a reference JSON (category, title, severity, IOCTL code/method/access).
- `--ioctl-count <N>`: assert exactly N unique IOCTL codes found (use for ALSysIO64 17, HEVD 28).
- `--expect-heuristic <pattern>`: assert at least one heuristic finding title contains the pattern (e.g. "TOCTOU" for HEVD).
Each check result lands in the output JSON under `checks`; exit code is non-zero on any failure.

### Function-name sets
All heuristic, callchain, and scoring function-name lists live in `config.py` (not scattered across modules): `DANGEROUS_SINKS`, `VALIDATION_FUNCS`, `PRIVILEGE_GATE_FUNCS`, `PRIVILEGED_SENSITIVE_OPS`, `IRQL_RAISING_FUNCS`, `MDL_USER_FUNCS`, `COPY_SINKS`, `ALLOCA_FUNCS`, `POOL_ALLOC_FUNCS`. Add to the relevant set in `config.py` when expanding coverage; modules import the set by name.

### Vulnerable function lists
`DriverBuddyReloaded/vulnerable_functions_lists/` contains four lists (`c.py`, `winapi.py`, `opcode.py`, `custom.py`) consumed by `utils.get_xrefs()` for the "flagged functions" findings. `custom.py` is the user-editable list. `winapi_function_prefixes` entries do prefix matching; `winapi_functions` entries do exact matching.
