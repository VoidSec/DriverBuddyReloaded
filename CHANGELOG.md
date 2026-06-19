# Changelog

## v1.1.0 - 2026-06-19 - Professional overhaul, heuristics, IDA 9.3 support, bug fixes

### New features
- **Heuristic vulnerability checks** (`heuristics.py`): five checks run over each identified dispatch handler -
  unvalidated user-copy (missing `ProbeForRead`/`ProbeForWrite`/safe-string guard near a copy sink), missing
  privilege gate (privileged kernel op with no `SeSinglePrivilegeCheck`/`SeAccessCheck`), IRQL mismatch
  (pageable/`Zw*` call when an IRQL-raising function is present), unsafe MDL mapping (`MmMapLockedPages` etc.
  with `UserMode` in disassembly), and stack allocation (`_alloca`/`_chkstk`).
- **Exports audit** (`exports_audit.py`): flags driver exports with zero internal cross-references - possible
  hidden attack surface not reachable from `DriverEntry`.
- **Auto IOCTL dispatcher scan** (`ioctl_decoder.scan_dispatchers`): flow-chart scan over the identified
  `DispatchDeviceControl`/`DispatchInternalDeviceControl` handlers runs automatically during analysis, without
  requiring the user to place the cursor in the function first.
- **IRP_MJ_FUNCTION IDA enum** (`irp_mj.py`): creates the 28-member `IRP_MJ_FUNCTION` enum in the local type
  database and applies it to `MajorFunction` array operands in `DriverEntry` (WDM drivers; gated on
  `Feature.IRP_MJ_ENUM`). Uses `idc.add_enum` on IDA < 9.0 and `ida_typeinf.parse_decls` on IDA 9.0+.
- **Dynamic NTSTATUS lookup**: IOCTL false-positive filter now resolves NTSTATUS values from the IDA type DB
  (`idc.get_enum("NTSTATUS")`) instead of the deleted static `NTSTATUS.py` list. Falls back to a small
  hardcoded set when the enum is absent (minimal IDA setups).
- **Pool tag register-propagated fallback** (`dump_pool_tags.collect_fallback`): when the import-based scan
  finds no tags, a backward register-walk finds tags staged in a `mov reg, 'ABCD'` before the alloc call.
- **Device name EA**: when a device name is resolved via the IDA Strings DB the finding now records the
  source address so it is navigable in the results window.
- **Per-run timestamped output files**: all artefacts use `<DRIVER_NAME>-YYYY-MM-DD-TIMESTAMP-` prefix so
  multiple analysis runs on the same driver do not overwrite each other.
- **IDA 9.3 support**: tested against IDA Free 9.3; `ida_compat.py` handles all version-divergent paths.
- **`ida-plugin.json` manifest**: IDA 9.x plugin manifest at repo root for automatic plugin discovery.
- **Version metadata**: `__version__` in `DriverBuddyReloaded/__init__.py`; surfaced in the `init()` banner.

### Bug fixes (GitHub issues)
- **#31**: `GsDriverEntry` (IDA 8.2+ security-cookie wrapper) not recognised as driver entry point; `is_driver()`
  now scans for all three names (`DriverEntry`, `DriverEntry_0`, `GsDriverEntry`).
- **#30**: `DeviceName` finding now includes source address when resolved via the IDA Strings DB.
- **#29**: Driver type reported as "WDF" instead of "KMDF" / "UMDF"; fixed by inspecting the library prefix
  character from the WDF version struct.
- **#27**: Crash instead of actionable error on IDA < 7.6; `ida_compat.py` now emits a clear warning and the
  minimum supported version (7.6) is documented.
- **#25**: `IRP_MJ_FUNCTION` enum created and applied to `MajorFunction` array operands in `DriverEntry`.
- **#16**: Pool tags propagated via a register were missed; fixed by the register-propagated fallback scanner.
- **#15**: NTSTATUS filter replaced with dynamic IDA enum lookup (no longer a static maintenance burden).

### Refactor
- Extracted `run_analysis()` entry point to `analysis.py`; `DriverBuddyReloaded.py` is a thin UI wrapper.
- `AnalysisContext` dataclass in `utils.py` replaces module-level mutable dicts; isolates per-run state.
- All magic numbers (WDM struct offsets, IOCTL floor, pool-tag lookback) extracted to named constants in
  `config.py` and `wdm.py`.
- Type hints (`from __future__ import annotations`) and module docstrings across all modules.
- `device_name_finder.py`: fixed `REPEATS` bytes/str mismatch (`buf[0:1]` vs `buf[0]`); added `\\?\\` prefix.

### Tests
- `tests/test_dbr.py` extended with regression tests for: REPEATS bytes fix (3 cases), new `idc` enum stubs
  exercising the NTSTATUS fallback path, and `ida_strlist` stub for device-name DB scan.
- Cross-version smoke harness: `tests/ida_smoke.py` (headless IDA runner) and
  `tests/run_cross_version.ps1` (PowerShell matrix over IDA 7.6/8.4/9.3).

---

## v1.0.0 - IDA 8.4/9.0 port, refactor and feature absorption

### Compatibility
- **Runs on IDA 7.x, 8.x (incl. 8.4) and 9.0+ (Python 3).** Previously the WDF path crashed on IDA 9.0.
- Added `DriverBuddyReloaded/ida_compat.py`, a single compatibility layer for every version-divergent
  IDA API. All struct/type handling is version-branched behind it: the proven legacy `idc.*struc*`
  path for IDA < 9.0, and `ida_typeinf` for IDA 9.0+ (where `ida_struct` and the `idc` struct
  wrappers were removed).
- Replaced removed/deprecated APIs: `idaapi.get_inf_structure().is_64bit()` -> `ida_ida.inf_is_64bit()`;
  `idc.get_struc_id/add_struc/add_struc_member/get_struc_size` and `idc.SetType` -> compat helpers;
  `idc.import_type` -> `ida_compat.import_std_type`; `idc.GetDisasm` -> `ida_compat.disasm_text`;
  `ida_search.find_binary`/`idc.ida_search.find_text` -> `ida_bytes.bin_search`-based helpers.

### New features
- **IOCTL risk scoring** (`scoring.py`): severity from transfer method / access mode, with a bump when
  the handler reaches a dangerous sink. `METHOD_NEITHER` + reachable sink => Critical.
- **Findings window**: a single `ida_kernwin.Choose` listing all findings by severity; double-click jumps.
- **Call-chain tracing** (`callchain.py`): heuristic, name-based reachability from handlers to sinks.
- **Reporting** (`reporting.py`): machine-readable `findings.json`, a standalone `report.html`, and a
  generated C/C++ `DeviceIoControl` PoC harness (`ioctl_pocs.c`, severity-sorted).

### Refactor
- Introduced a shared `Finding` model and a `Reporter` spine; analysis modules now emit findings instead
  of duplicating every `print()` with a matching `log_file.write()`.
- New `config.py` centralises tunables, the severity/risk model, feature toggles and output paths.
  Output files now land in the **IDB directory** (via `ida_loader`), not `os.getcwd()`.
- `DriverBuddyReloaded.py` `run()` reduced to a thin orchestrator; the duplicated IOCTL table renderer
  was de-duplicated into `ioctl_decoder.format_row` / `IOCTL_TABLE_HEADER`.
- `ExAllocatePool2/3` pool-tag APIs centralised in `dump_pool_tags.POOL_TAG_FUNCS`.

### Bug fixes
- `wdm.py`: fixed a no-op `"...".format()` statement, a broken chained comparison
  (`io_stack_reg in "+10h" in disasm`), and a copy/paste `op_stroff` operand index.
- `ioctl_decoder.py`: removed the `idc.ida_nalt.` / `idc.ida_ida.` / `idc.ida_search.` indirection.
- `find_opcodes.py`: dropped the obsolete Python 2/3 shim and dead chooser code.

### Tests
- Added `tests/test_dbr.py`: self-contained, IDA-free regression tests for IOCTL decoding, risk scoring
  and JSON/HTML/PoC generation (runs under plain CPython; simulate IDA 9.0 paths with `DBR_SDK=900`).
