# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `ioctl_decoder.py` `scan_dispatchers()`: now recovers IOCTL codes that never appear as
  immediate operands in the disassembly. Previously the dispatcher scan only matched literal
  immediates in `cmp`/`sub`/`mov`, so it missed every code the compiler hid inside a jump table
  (only the table base/bound remain as immediates) or a binary-search comparison tree
  (intermediate codes survive only as deltas). Two new collectors run per dispatcher and merge
  with the immediate scan through a single `_emit_ioctl()` validation/dedup funnel:
  - `_collect_hexrays_consts()` decompiles the dispatcher and reads switch-case labels and
    `==`/`!=` comparison constants from the ctree. Comparison constants are anchored to a
    switch-selector variable when a switch is present (so an unrelated `status == STATUS_*`
    check is ignored); with no switch present (if-chain dispatcher) every comparison constant
    is taken. Gated on the new `config.Feature.IOCTL_DECOMPILER` flag + HexRays availability.
  - `_collect_switch_cases()` reads IDA's recovered switch metadata
    (`get_switch_info` + `calc_switch_cases`), excluding the default-jump group so the dense
    filler values between real cases are dropped. Works without the decompiler.
  The raw immediate scan is now a last resort, used only when both structured collectors
  recover nothing for a dispatcher. Measured recovery on the test corpus rose from 7/28 to
  **28/28** (HEVD) and 4/17 to **17/17** (ALSysIO64); WinRing0x64 (18) and beep (2) unchanged,
  all with no false positives (verified full-pipeline on IDA 7.6 SP1 and 8.4).

### Changed

- `analysis.run_analysis()`: the precise dispatcher scan now runs before `find_ioctls()`, and
  the fuzzy whole-binary `IoControlCode` text scan only runs as a fallback when the dispatcher
  scan found nothing. `find_ioctls()` can mistake data constants for IOCTLs (e.g. a misread
  `0x0032C004`), so skipping it when the structured decode succeeds removes those false positives.
- `ioctl_decoder.py` `_is_valid_ctl_code()`: now also rejects the `0xFFFFFFFF` (`(DWORD)-1` /
  `INVALID_HANDLE_VALUE`) sentinel, which is structurally a valid CTL_CODE but surfaces from
  `== -1` checks inside dispatchers (observed in WinRing0x64).

### Fixed

- `DriverBuddyReloaded.py` `make_comment()`: fixed an `AttributeError: module 'idc'
  has no attribute 'add_extra_cmt'` crash that aborted `plugin_t.run()` whenever
  auto-analysis tried to write an IOCTL anterior comment. `add_extra_cmt` does not
  exist in `idc` on any supported build (it lives only in `ida_lines`/`idaapi`,
  unlike its siblings `get_extra_cmt` / `del_extra_cmt` / `E_PREV`, which `idc` does
  expose). Anterior-comment handling now routes through two new `ida_compat` helpers,
  `get_anterior_cmt()` and `add_anterior_cmt()`. The duplicate-guard now scans all
  anterior lines instead of only the first (`E_PREV + 0`), so a pre-existing
  IDA-placed anterior line can no longer push DBR's comment past the check and cause
  it to be re-appended on every re-run.

- `ioctl_decoder.py` `scan_dispatchers()`: replaced `range(block.start_ea, block.end_ea)`
  with a `while instr < block.end_ea: ... instr = idc.next_head(instr, block.end_ea)` loop.
  The old byte-level iteration asked IDA to decode every interior byte of a multi-byte x64
  instruction as if it were an instruction start; depending on IDA version, this could
  produce spurious mnemonics, incorrect finding EAs (pointing inside an instruction rather
  than at its start), or false-positive IOCTL findings from garbage operand values.
  Instruction-level iteration via `idc.next_head()` is the correct pattern (used by
  `iter_text_matches()` and all other walkers in the codebase).

- `wdm.py` `locate_ddc()` experimental path: the xref filter previously required that the
  DDC candidate be called **directly** from DriverEntry's own instructions
  (`reffunc.start_ea == driver_entry_address`). Many real drivers initialise
  `MajorFunction[]` in a helper function called from DriverEntry; those DDC addresses were
  never added to `ctx.ddc_addresses`, so `scan_dispatchers()` silently skipped the entire
  dispatcher scan. The filter now builds the set of functions reachable in one call step
  from DriverEntry (`entry_callees`) and accepts any DDC whose xref comes from that set.
  Also deduplicates `ddc_list` with `set()` before walking xrefs to avoid processing the
  same candidate multiple times when the pattern matched more than once in the same function.

### Added

- `tests/ida_smoke.py`: extended with three optional check modes (T5-T7):
  - `--golden <ref.json>` (T5): compare findings against a reference JSON
    order-insensitively on (category, title, severity, code, method, access).
    Designed for beep.sys and WinRing0x64.sys regression guards.
  - `--ioctl-count <N>` (T6): assert that exactly N unique IOCTL codes are
    present after analysis (e.g. 17 for ALSysIO64.sys, 28 for HEVD.sys).
  - `--expect-heuristic <pattern>` (T7): assert at least one heuristic finding
    title contains the pattern (e.g. "TOCTOU" for HEVD.sys).
  Each check result is recorded in the output JSON under `checks`; the overall
  exit code is 0 only when all checks pass.

- `tests/test_dbr.py`: four new pure-Python unit tests (T1-T4), bringing total
  to 27 checks.
  - T1: mocks `idaapi.get_func`, `idc.prev_head`, `idc.print_insn_mnem`,
    `idc.get_name_ea_simple` to simulate a GsDriverEntry stub ending with
    `jmp real_entry`; asserts `check_for_fake_driver_entry()` returns the
    real DriverEntry EA.
  - T2: five boundary calls to `_is_valid_ctl_code()`: verifies 0x00010000
    (device_type=1) and 0x00222003/0x0022e004 are valid; 0x00000000
    (device_type=0) and 0xC0000005 (STATUS_ACCESS_VIOLATION) are rejected.
  - T3: mocks `idautils.FuncItems`, `idautils.CodeRefsFrom`,
    `ida_funcs.get_func_name`, and `idc.print_operand` so that a synthetic
    handler calls `KeRaiseIrql` then `ZwOpenProcess`; asserts
    `check_irql()` emits an IRQL mismatch finding.
  - T4: pre-seeds Reporter with IOCTL 0x222003; runs `scan_dispatchers()`
    against a mocked FlowChart block that would emit the same code; asserts
    count stays at 1 (dedup by code value, not EA).

- `heuristics.py` `check_use_after_free()`: use-after-free heuristic (N6).
  Forward-walks the basic-block CFG via `idaapi.FlowChart`; tracks the argument
  register (RCX on x64, ECX on x86) after each `ExFreePool`/`ExFreePoolWithTag`/
  `ExFreePool2` call; emits HIGH when that register is read before being
  overwritten by a write instruction. Set propagates across block successors.
  Gated on `Feature.UAF_DETECT = True`.

- `device_name_finder.py` `find_symbolic_links()`: Symbolic link tracking (N4).
  Walks xrefs to `IoCreateSymbolicLink`; attempts to decode the target path by
  scanning backwards from each call site for UNICODE_STRING buffer references.
  Decoded paths are stored in `ctx.symbolic_links`; an INFO finding is emitted
  per call site regardless of whether the path was recovered. Gated on
  `Feature.SYMLINK_TRACK = True`.
- `utils.py` `AnalysisContext`: added `symbolic_links: list` field (N4).

- `utils.py` `find_device_create_calls()`: Device ACL audit (N3).
  Walks xrefs to `IoCreateDevice` (LOW: no security descriptor, world-accessible
  by default) and `IoCreateDeviceSecure` (scans the calling function for a
  UTF-16 SDDL string via IDA data-xrefs; MEDIUM if it contains a world SID --
  `WD`, `S-1-1-0`, `BU`, or `S-1-5-32-545` -- LOW if the SDDL cannot be
  statically recovered). Gated on `Feature.ACL_AUDIT = True`; wired into
  `analysis.py` before the callchain stage.

- `heuristics.py` `check_double_fetch()`: TOCTOU/double-fetch heuristic (N1).
  Walks the instruction stream of each handler; groups `mov reg, [src+offset]`
  loads by `(src_register, offset)`; flags any pair with 2+ occurrences that has
  no `ProbeForRead`/`ProbeForWrite` or copy-sink call between them (MEDIUM).
  Gated on `Feature.TOCTOU_CHECK = True`.
- `config.py`: new feature flags `TOCTOU_CHECK`, `ACL_AUDIT`, `SYMLINK_TRACK`,
  `UAF_DETECT`; new function-name sets `PROBE_FUNCS`, `DEVICE_CREATE_FUNCS`,
  `SYMLINK_FUNCS`, `FREE_POOL_FUNCS`.

- `config.py` `Feature.validate()`: startup classmethod that raises `ValueError`
  for incoherent feature-flag combinations. Currently checks that
  `Feature.CALLCHAIN` is not enabled when `Feature.IOCTL_SCAN` is disabled
  (callchain needs IOCTL findings as seeds). Called in `DriverBuddyPlugin.init()`.
- `config.py` `Feature.IOCTL_SCAN = True`: new flag that gates both
  `find_ioctls()` and `scan_dispatchers()` in `analysis.py`.

- `callchain.py` `trace()`: progress line every 10 seeds so long runs are visible
  in the output log (`[callchain] N/M handlers traced`).
- `ioctl_decoder.py` `scan_dispatchers()`: per-dispatcher progress line
  (`[scan] dispatcher 0xXXXX (N/M)`) before processing each entry point.

- `dump_pool_tags.py`: extracted `_collect_tags_for_imports(import_names, decode_fn)`
  helper that owns the outer import-enumeration loop and per-call-site backward walk.
  `find_pool_tags()` and `collect_fallback()` now each supply only a small
  `decode_fn` closure that handles the tag-extraction logic specific to them.

- `analysis.py` `_stage()` helper: wraps each analysis stage in try/except so a
  single stage crash does not abort the rest of the pipeline; the exception is
  logged via `rep.info()` and execution continues. `populate_data_structures()` and
  the IOCTL-discovery path are not wrapped (their failures are handled explicitly).
- `analysis.py`: early-return guard after `populate_data_structures()` returns
  `False`; all downstream stages (callchain, heuristics, scoring, etc.) are now
  skipped rather than running against an empty function map.

- `wdf.py` `populate_wdf()`: emits a warning when no segment contains the
  `mdfLibrary` UTF-16 string so analysts know the `WDF` classification is a
  fallback, not a confirmed WDF version detection.

### Fixed

- `reporting.py` / `DriverBuddyReloaded.py`: `Reporter.remove_findings_at(ea)` and
  `Reporter.re_save()` added. Both `ResultsChooser` and `IOCTLChooser` now carry
  `CH_CAN_DEL` and override `OnDeleteLine()` so rows can be removed interactively;
  deletion propagates to the Reporter's findings list and re-writes JSON/HTML.
  `InvalidHandler.activate()` now also removes the anterior comment, calls
  `_last_rep.remove_findings_at()`, and live-refreshes the IOCTL chooser window.

- `DriverBuddyReloaded.py` `make_comment()`: IOCTL decode comments are now also
  written as anterior comments (`ida_compat.add_anterior_cmt(pos, string)`), making
  them visible in the HexRays decompiler pseudocode view. Non-repeatable
  disassembly-only comments (`idc.set_cmt`) were silently dropped by HexRays.
  A duplicate-guard prevents re-running decode from appending the same comment twice.

- `ioctl_decoder.py` `scan_dispatchers()`: deduplication now keyed on IOCTL code
  value instead of instruction EA. The old `already_seen = {f.ea for f in ...}`
  set compared instruction addresses against instruction addresses, so the same
  code value at two different EAs produced two findings; a code seen by
  `find_ioctls()` at one EA was not suppressed by `scan_dispatchers()` finding
  the same code at a different EA.

- `ida_compat.py` `is_64bit()`: added explicit `IS_IDA9` guard before calling the
  removed `get_inf_structure()` API. Without the guard, reaching the fallback path
  on IDA 9.0 raises `AttributeError` instead of a clear `RuntimeError`. The normal
  path (via `ida_ida.inf_is_64bit()`) is unaffected on all supported IDA versions.

- `irp_mj.py` `_create_enum_legacy()`: member-add loop now wrapped in try/except;
  any `add_enum_member` failure deletes the partially-created enum and returns
  `None` instead of leaving an orphaned enum in the IDA database.

- `ioctl_decoder.py` `find_ioctls()`: operand parsed with `int(raw, 16)` when IDA
  returns a hex string (e.g. `0x222003`); bare `int(raw)` raised `ValueError` and
  silently dropped the IOCTL. Occurs when `op_dec()` does not take effect before
  `print_operand()` is called.

- `wdm.py` `check_for_fake_driver_entry()`: replaced byte-decrement backward walk
  (`end_address -= 0x1`) with `idc.prev_head()` calls. The old loop landed in the
  middle of multi-byte instructions and read garbage mnemonics, silently breaking
  fake-DriverEntry detection on most real binaries. Walk now returns the real
  `DriverEntry` address on hitting a `jmp`/`call`, or the original address if the
  walk limit (64 steps) or a `BADADDR` boundary is reached.

## [2.0] - 2026-06-22

### Added

- `ida_compat.py`: single compatibility layer for every version-divergent IDA API.
  Struct and type handling is version-branched here; no other module imports
  `ida_struct` or `ida_enum` directly. Minimum supported IDA version is 7.6;
  a clear warning is raised on older installs instead of a cryptic traceback
  (issue #27).
- `analysis.py`: headless-callable analysis pipeline extracted from
  `DriverBuddyPlugin.run()`. Enables batch-mode and test-harness invocation
  without instantiating any UI hooks.
- `config.py`: centralised tunables, severity definitions, feature flags
  (`config.Feature`), output-path helpers, and every function-name set used by
  heuristics, callchain, and scoring (`DANGEROUS_SINKS`, `VALIDATION_FUNCS`,
  `PRIVILEGE_GATE_FUNCS`, `PRIVILEGED_SENSITIVE_OPS`, `IRQL_RAISING_FUNCS`,
  `MDL_USER_FUNCS`, `COPY_SINKS`, `ALLOCA_FUNCS`, `POOL_ALLOC_FUNCS`).
- `reporting.py`: shared `Finding` model and `Reporter` spine. All analysis
  modules emit findings via `rep.add_finding()` instead of duplicating every
  `print()` with a matching `log_file.write()`.
- `callchain.py`: heuristic BFS tracer from dispatch handlers to dangerous sinks;
  feeds the IOCTL risk scorer and all seven heuristics.
- `scoring.py`: per-IOCTL risk scoring. Base severity derived from transfer method
  and access mode; bumped to Critical when a handler reaches a dangerous sink
  (`METHOD_NEITHER` + reachable sink => Critical).
- `heuristics.py`: seven heuristic checks ported and extended from the Driver Buddy
  Revolutions fork: `check_user_copy_validation`, `check_privilege_gate`,
  `check_irql`, `check_mdl`, `check_alloca`, `check_pool_alloc_trust`,
  `check_physical_mem_ref` (BYOVD indicator via `\Device\PhysicalMemory` xrefs).
- `exports_audit.py`: flags driver exports with zero internal code references
  (excluding `DriverEntry` / `GsDriverEntry` / `start`) as potential hidden entry
  points.
- `irp_mj.py`: creates an `IRP_MJ_FUNCTION` enum in the IDA type database and
  annotates `MajorFunction` array assignments in `DriverEntry` (issue #25). When
  HexRays is loaded, also registers `number_format_t` (`user_numforms`) entries so
  the decompiler renders `MajorFunction[IRP_MJ_CREATE]` instead of
  `MajorFunction[0]`, and adds per-assignment end-of-line comments.
- `poc.py`: generates a severity-sorted `DeviceIoControl` PoC harness in C
  (`ioctl_pocs.c`) for all discovered IOCTLs.
- `IOCTLChooser`: severity-colored IDA chooser window with Severity, Address, Code,
  Device type, Method, Access, and Function number columns. Double-click jumps to
  the dispatcher EA. Opened automatically after auto-analysis and via `Ctrl+Alt+I`;
  reopenable at any time without re-running analysis.
- `ResultsChooser`: clickable findings window listing all findings by severity;
  double-click jumps to the relevant address. Opened via `Ctrl+Alt+W`.
- JSON export (`findings.json`) and HTML report (`report.html`) written to the IDB
  directory at the end of each run.
- `scan_dispatchers()` in `ioctl_decoder.py`: flow-chart brute-force scan of
  identified dispatcher entry points, complementing `find_ioctls()` for stripped or
  poorly-typed binaries where IDA has not applied `IO_STACK_LOCATION` struct types.
- Dynamic NTSTATUS filter in `ioctl_decoder.py`: queries the live IDA `NTSTATUS` /
  `_NTSTATUS` enum; falls back to a minimal 21-entry hardcoded set. Result is cached
  per run.
- `config.Feature` flags: every optional analysis stage can be disabled without
  touching pipeline logic. `SEGMENT_OPCODE_SCAN` defaults to `False`; all others
  default to `True`.
- Right-click menu additions in the disassembly view: Decode All IOCTLs in
  Function, Show all IOCTLs, Show Findings, Invalid IOCTL (context-sensitive).
- Hotkeys `Ctrl+Alt+I` (IOCTL window) and `Ctrl+Alt+W` (Findings window).
- `tests/ida_smoke.py`: in-IDA batch script that runs `run_analysis()` and writes a
  JSON summary for the cross-version matrix runner.
- `tests/run_cross_version.ps1`: PowerShell matrix runner over IDA 7.6 SP1, 8.4,
  and Free 9.3 against real `.sys` files; prints a coloured pass/fail table.
- `tests/test_dbr.py`: 17-check IDA-free regression suite covering IOCTL decode,
  risk scoring, `device_name_finder` bytes/str handling, JSON/HTML/PoC generation,
  NTSTATUS fallback, and pool-tag collection. Simulate IDA 9.0 import paths with
  `DBR_SDK=900`.
- IOCTL finding entries now include the address where each code was found (PR #28).
- `\??\` prefix added to `device_name_finder` search set; IDA Strings DB fallback
  with EA in findings (issue #30); segment-scan fallback reading IDA database bytes
  directly when the string DB returns nothing.
- Register-propagated pool-tag fallback (`collect_fallback()`) in
  `dump_pool_tags.py` for drivers where the primary import scan finds nothing
  (issue #16).

### Changed

- IDA 7.6 through 9.3 supported on Python 3. Previously the WDF analysis path
  crashed at load time on any IDA 9.x install.
- `AnalysisContext` dataclass in `utils.py` holds all per-run mutable state and is
  threaded through every analysis module; eliminates module-level mutable dicts that
  carried stale data between plugin re-runs.
- All heuristic and scoring function-name lists centralised in `config.py`; modules
  import the sets by name.
- Output files now land in the IDB directory (`<IDB_DIR>/<DRIVER_NAME>-<DATE>-<TS>-<suffix>`),
  replacing the previous fixed `DriverBuddyReloaded_autoanalysis.txt` in the
  working directory.
- `winapi.py`: replaced overbroad `Ob*`/`Rtl*`/`Mm*`/`Zw*` prefix matches with
  curated exact-match entries, eliminating a large class of false-positive flagged
  function findings.
- `vulnerable_functions_lists/c.py` list converted to `frozenset` for O(1) lookup.
- `poc.py`: de-duplicated IOCTL iteration; extracted `_build_c_source()`; normalised
  to f-strings; prefers `\\DosDevices\\` device path.
- `find_opcodes.py`: renamed `FindInstructions` to `find_instructions`; fixed
  variable shadowing; explicit opcode import.
- `UiAction` helper: `registerAction` -> `register_action`,
  `unregisterAction` -> `unregister_action`, `menuPath` -> `menu_path`.
- `ida-plugin.json` migrated to the official Hex-Rays publishing schema.
- `wdm.py`: dispatcher candidate search now excludes `GsDriverEntry`,
  `_guard_xfg_dispatch_icall_nop`, and other XFG/CFG stubs.
- `get_driver_id()` now detects `GsDriverEntry` as a valid driver entry point in
  IDA 8.2+ (issue #31).
- `wdf.populate_wdf()` now reads the `K`/`U` prefix from the `mdfLibrary` string
  to return `KMDF`, `UMDF`, or `WDF` instead of always defaulting to `WDF`
  (issue #29).

### Removed

- `NTSTATUS.py`: 204 hardcoded values replaced by dynamic IDA enum lookup.

### Fixed

- IDA 9.0 crash on WDF analysis (`ida_struct` removed in 9.0).
- `device_name_finder` crash on Python 3: `mmap` byte indexing returns `int`, not
  `bytes`; the repeat-buffer filter was silently broken. Fixed with `buf[0:1]` slice
  and `bytes` literals.
- `device_name_finder` dropping short device names (e.g. `\Device\Beep`) due to an
  over-strict prefix-length filter.
- `wdm.py` no-op `"...".format()` statement, broken chained comparison
  (`io_stack_reg in "+10h" in disasm`), and copy/paste `op_stroff` operand index.
- `wdm.py` using a 32-bit `BADADDR` sentinel; replaced with `idaapi.BADADDR` and
  added a `MAX_WALK=256` guard against unbounded traversal.
- `exports_audit.py` crash unpacking a 4-tuple from `idautils.Entries()`.
- 6-entry gap in the IOCTL device-type name table (indices 0x4A-0x4F).
- `irp_mj.py` receiving `GsDriverEntry` (a `/GS` stub with no `MajorFunction`
  assignments) instead of the real `DriverEntry`; `AnalysisContext.real_entry_addr`
  now stores the correct address.
- `irp_mj.py` HexRays `user_numforms` entries not surviving a save/restore
  round-trip: bit 23 of `number_format_t.flags` must be set for `type_name` to
  serialise; IDA silently dropped it without the flag.
- `analysis.py` `is False`/`is True` identity comparisons on pipeline return values.
- False-negative "Unable to find IOCTLs" message emitted before `scan_dispatchers()`
  had a chance to run; deferred until both strategies complete.
- Occasional error from a branch not executed in the IOCTL decode path (PR #35).
- `AnalysisContext` mutable state carried over between plugin re-runs in the same
  IDA session.
- `IOCTLTracker.remove_ioctl()` used `set.remove()` (raises on missing key);
  replaced with `set.discard()`.
- `find_all_ioctls()` registered the same IDA action twice.

## [1.6] - 2022-08-09

### Added

- `ZwTerminateProcess` added to the dangerous functions list (PR #26).
- Arbitrary memory read/write functions added to the dangerous functions list.

### Fixed

- IOCTL code table correction.

## [1.5] - 2022-05-07

### Added

- Additional WDF versions and WDF data/code separation (PR #24).

### Fixed

- `is_driver()` function fix.
- Issue #15 (partial fix).

## [1.4] - 2022-04-25

### Added

- IOCTL device-type table expanded with entries from h0mbre/ioctl.py.
- Function name in output for interesting cross-reference hits (PR #19).

### Changed

- IDA API upgrades: `idc.Dword` -> `idc.get_wide_dword` and related.

### Fixed

- Issue #22.
- Issue #21.
- Issue #15 (partial fix).
- Issue #4: WDF driver structure implementation (PR #20).

## [1.3] - 2021-12-10

### Added

- Deprecated/banned function list expanded from Windows SDK `dontuse.h` and
  `banned.h` (PR #14).

### Fixed

- Bug where IOCTLs found via `IoControlCode` were not saved to the log file.
- Issue #13.

## [1.2] - 2021-11-04

### Added

- `Rtl*` API entries to the dangerous functions list.
- Arbitrary memory read/write function entries.

## [1.1] - 2021-10-27

### Changed

- Windows API functions reorganised into correct categories.

## [1.0] - 2021-10-22

Initial release.

[Unreleased]: https://github.com/VoidSec/DriverBuddyReloaded/compare/2.0...HEAD
[2.0]: https://github.com/VoidSec/DriverBuddyReloaded/compare/1.6...2.0
[1.6]: https://github.com/VoidSec/DriverBuddyReloaded/compare/1.5...1.6
[1.5]: https://github.com/VoidSec/DriverBuddyReloaded/compare/1.4...1.5
[1.4]: https://github.com/VoidSec/DriverBuddyReloaded/compare/1.3...1.4
[1.3]: https://github.com/VoidSec/DriverBuddyReloaded/compare/1.2...1.3
[1.2]: https://github.com/VoidSec/DriverBuddyReloaded/compare/1.1...1.2
[1.1]: https://github.com/VoidSec/DriverBuddyReloaded/compare/1.0...1.1
[1.0]: https://github.com/VoidSec/DriverBuddyReloaded/releases/tag/1.0
