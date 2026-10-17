# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Run pure-Python regression tests (no IDA required)
```
python tests/test_dbr.py
DBR_SDK=900 python tests/test_dbr.py    # simulate IDA 9.0 import paths
```
71 checks, all logic that does not touch the live IDA database. Run both variants on every change.

### Run cross-version smoke tests (requires all three IDA installs)
```
pwsh tests\run_cross_version.ps1
pwsh tests\run_cross_version.ps1 -Timeout 180 -KeepTemp
```
Launches IDA 7.6 SP1, 8.4, and Free 9.3 in batch mode against real `.sys` files and prints a pass/fail matrix. Results land in `smoke_results/`.

### Run golden-output regression (the FP/FN guard)
```
pwsh tests\run_golden.ps1
```
For every `tests/drivers/<driver>.golden.json`, copies the matching `.i64` plus its golden to a temp dir, runs the full pipeline headless, and compares the fresh findings to the golden order-insensitively on (category, title, severity, IOCTL code/method/access). Any added finding (false positive), missing finding (false negative) or severity change fails the cell. The eight goldens (`beep`, `HEVD`, `ALSysIO64`, `WinRing0x64`, plus `zam64` (minifilter + control device), `amp` (outbound-IOCTL filter), `MODAPI` (monolithic multi-case dispatcher), and `IObitUnlocker` (sub+cmp adjacent-code dispatch, negative-literal comparison guard -- issue #41)) are the captured output of the current pipeline and are the authoritative regression baseline. Run after every change to detection logic.

Regenerate a golden ONLY when a change intentionally alters findings: run the analysis on a fresh copy of the `.i64` and overwrite `<driver>.golden.json` with the new findings (same shape as `Reporter.to_json`), then review the diff. Goldens are tied to the IDA 8.4 decompiler build they were captured with; a different decompiler can legitimately change heuristic findings, so run the regression with that version.

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
        +-- callchain.py          BFS handler -> dangerous sink tracing; transitive_callees() helper
        +-- heuristics.py         checks: copy-validation, priv-gate (path-level), IRQL, MDL,
        |                         alloca, pool-alloc-trust, physical-mem-ref, double-fetch (TOCTOU),
        |                         privileged-instructions (port-IO / mov cr*), write-primitives
        |                         (write-what-where), use-after-free (register CFG walk + global)
        +-- registers.py          pure x86/x64 register-alias + operand-base helpers
        |                         (no IDA import) shared by the UAF register tracking
        +-- exports_audit.py      zero-xref export detection
        +-- find_opcodes.py       opcode scan (off by default: Feature.SEGMENT_OPCODE_SCAN)
        +-- scoring.py            IOCTL risk scoring + severity bump
        +-- reporting.py          JSON / HTML / results window / IOCTL window
```

### The Reporter spine
Every module emits `Finding` objects (defined in `reporting.py`) via `rep.add_finding(category, title, ...)` instead of bare `print()`. `rep.info()` writes INFO-level lines. At the end of a run the Reporter renders the clickable findings window (`ResultsChooser`), the IOCTL recap window (`IOCTLChooser`), `findings.json`, and `report.html`. Never bypass the Reporter with direct `print()` calls.

**Finding ordering** is shared by the HTML report and the `ResultsChooser` window via `reporting.default_sort_key`: severity descending, then `_CATEGORY_PRIORITY` (so confirmed `callchain` findings -- provable user-input -> dangerous-sink paths -- lead their severity tier, ahead of `ioctl`/`heuristic`/`opcode`/etc.), then address as a stable tie-break. Address-less findings sort last within their group. Adjust `_CATEGORY_PRIORITY` to re-rank a category within its tier.

**HTML report** (`_render_html` + `_HTML_SCRIPT`) has client-side sortable columns: clicking any header sorts by that column (click again to reverse), dependency-free vanilla JS so it works from a local file with no network. Severity and Address sort numerically via a per-row `data-sort` attribute (severity rank; numeric EA, `-1` for address-less rows) rather than by displayed label text; the other columns sort as text. Row/badge backgrounds run the full severity scale `.s4..s0` (red/orange/yellow/green/blue); the `ResultsChooser` `_SEVERITY_COLORS` mirrors the same RGB values in BGR. Keep the two color tables in sync when changing either.

### Plugin UI layer (DriverBuddyReloaded.py)
`DriverBuddyReloaded.py` owns all IDA UI concerns and delegates analysis to `analysis.run_analysis()`.

- **Hotkeys**: `Ctrl+Alt+A` auto-analysis (shows settings dialog first), `Ctrl+Alt+D` decode IOCTL at cursor, `Ctrl+Alt+I` open IOCTLs window, `Ctrl+Alt+F` open findings window.
- **Right-click menu** (disassembly view): Show all IOCTLs, Show Findings, Decode IOCTL (when cursor is on an immediate), Invalid IOCTL (when already decoded).
- **`IOCTLChooser`**: severity-colored chooser showing Severity / Address / Code / Device / Method / Access / Fn# columns. Populated from `rep.by_category("ioctl")` after auto-analysis, or from `IOCTLChooser.from_pairs(ioctl_tracker.ioctls)` for the interactive decode session.
- **`_last_rep`**: module-level variable storing the Reporter from the most recent auto-analysis run. `show_all_ioctls()` and `show_findings()` use it so both windows can be reopened at any time without re-running analysis.
- **`IOCTLTracker`**: tracks interactively-decoded IOCTL codes (address, value) across the session; separate from the Reporter findings.

### Settings dialog (settings_ui.py)
`show_settings()` opens the pre-analysis settings dialog (feature flags + tuning constants) and returns whether analysis should proceed. It has two implementations of the same dialog and picks one at runtime:

- **Primary**: `_show_settings_qt()` -- the PyQt5 dialog (`_SettingsDialog`). Preferred for its `QFormLayout`/tooltip layout. This is what IDA 8.4 uses.
- **Fallback**: `_show_settings_kernwin()` -- an `ida_kernwin.Form`, opened automatically when the PyQt path raises. PyQt fails when the IDA build's bundled PyQt5 was compiled for a different Python than idapyswitch selected (e.g. IDA 7.6 SP1 bundles a `python38` PyQt5 but the interpreter is Python 3.10 -> `ImportError: DLL load failed while importing sip`), and on IDA 9.x which ships PySide6 instead of PyQt5. Do **not** remove the PyQt path to "simplify" -- 8.4 relies on it.

Both paths expose the same controls and enforce the same coherence rules via `config.Feature.validate()`. The fallback form string is generated from the shared `_FEATURE_GROUPS`/`_TUNING` tables by `_kernwin_format_string()` (checkboxes `c0..cN` grouped per category, tuning fields `i0..iM`); `ida_kernwin.Form` lays widgets out on a character grid, so tuning labels are padded to a common width to keep the input boxes aligned. Only if *both* dialogs are unavailable is a warning logged and analysis allowed to proceed with the current config. `settings_ui` imports cleanly outside IDA (PyQt import deferred in the Qt path, `import ida_kernwin` deferred in the fallback) so the pure-Python harness can import it.

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

### Dispatcher discovery (get_driver_id + wdm.py)
`utils.get_driver_id()` classifies the driver type (Mini-Filter / WDF / Stream / AVStream / PortCls / WDM) for reporting, then discovers the `IRP_MJ_DEVICE_CONTROL` dispatcher(s) **for every driver type**, not only WDM. Minifilter/WDF drivers routinely also expose a legacy control device whose IOCTL handler is the real attack surface; gating discovery behind the WDM label used to leave `ctx.ddc_addresses` empty for them and skip the entire IOCTL/callchain/heuristic pipeline (e.g. zam64's 31 IOCTLs were all missed).

Discovery order:
1. `wdm.find_majorfunction_dispatchers()` (primary) - scans the whole binary for a store into `MajorFunction[IRP_MJ_DEVICE_CONTROL]` (`+0E0h`) / `[..._INTERNAL_...]` (`+0E8h`) whose target is `lea`-loaded (or a direct offset), and names the target `DispatchDeviceControl` / `DispatchInternalDeviceControl`. Works regardless of driver type and regardless of whether the assignment lives in DriverEntry or a helper it calls (zam64's `DriverInit`, amp's `DriverCreateDevice`).
2. `locate_ddc()` (fallback) - the entry-scoped struct-store scan + experimental IO_STACK search, used only when the store scan finds nothing.
3. `find_dispatch_function()` (last fallback) - the `find_dispatch_by_cfg` / `by_struct_index` guesses. These "calls-many, not-called" heuristics readily mis-select statically-linked library/CRT helpers (RTCore's `SepSddlGetAclForString`, dbutil's `__GSHandlerCheckCommon`); `FUNC_LIB` and an expanded `excluded_functions` list filter the obvious ones.

`wdm.references_iocontrolcode(func_ea)` is the corroboration predicate: True when the function loads the IRP's IO_STACK_LOCATION (`+0B8h`) and reads the control code (`+18h`), matching the raw-offset (`[rdx+0B8h]`), the struct-annotated (`IoControlCode` / `CurrentStackLocation`) **and the partially-annotated** (`[rdx+(IRP.Tail+40h)]`, i.e. IRP struct applied without IO_STACK_LOCATION) renderings - the iostack load is recognised by its operand *offset* (`o_displ == 0xB8`), not by member-name text (issue #41: the pure-text gate false-negatived on annotated databases and skipped the immediate scan entirely). It is **not** used to hard-filter dispatch candidates (a struct-annotated real dispatcher would fail a strict text match), and it only gates the low-precision immediate-operand IOCTL scan for *unproven* candidates: dispatchers resolved by the MajorFunction[]/struct-store scans skip the gate (provenance is tracked in `ctx.ddc_confirmed`, set by `get_driver_id()`), since a proven dispatcher whose control-code read renders through an unexpected union member must not be dropped.

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

1. `scan_dispatchers(rep, ddc_addresses, confirmed_eas=None)` - the primary path; runs three collectors per dispatcher EA and merges them through `_emit_ioctl()` (single dedup + validation funnel):
   - `_collect_hexrays_consts()` - decompiles the dispatcher and walks the ctree for switch-case labels, `==`/`!=` comparison constants, and **base+delta pairs** (issue #41: `v = selector - base` followed by `==`/`!=` against a delta dispatches `base + delta` even though neither code appears as a comparison operand or an immediate - IObitUnlocker encodes `0x222124`/`0x222128` as `sub esi, 222124h` / `cmp esi, 4`). Comparison constants against a *negative* literal are rejected at collection time (`cexpr_t.is_negative_const()`), since their masked value passes the structural CTL_CODE check (device type 0xFFFF) yet is never a dispatch code (the `ptr == -528` overflow guard). This is the only method that recovers codes the compiler did not leave as immediates: **jump-table dispatch** (only the table base/bound survive as immediates; e.g. ALSysIO64), **binary-search comparison trees** (intermediate codes survive only as deltas; e.g. 21 of HEVD's 28) and **sub+cmp adjacent-code pairs**. Gated on `config.Feature.IOCTL_DECOMPILER` + HexRays availability.
   - `_collect_switch_cases()` - IDA `get_switch_info` + `calc_switch_cases`, excluding the `defjump` group (so the dense filler values between real cases are dropped). Recovers jump-table dispatch **without** the decompiler.
   - `_collect_immediates()` - the original `cmp`/`sub`/`mov` immediate-operand flow-chart scan. Low precision (cannot distinguish an IOCTL from an NTSTATUS code, a pool tag, or a division magic constant moved into a register), so it runs **only as a last resort**: when the two structured collectors found nothing for that dispatcher **and** (`confirmed_eas` proves the EA came from a MajorFunction[]/struct-store scan **or**) `wdm.references_iocontrolcode(func_ea)` confirms the function actually reads the IRP's IoControlCode. Without that gate a CFG-misidentified library helper leaks its internal constants as false-positive IOCTLs (RTCore's `SepSddlGetAclForString` produced `0xCCCCCCCD`, a pool tag, and NTSTATUS codes).
2. `find_ioctls()` - walks `IoControlCode` matches that IDA resolved from struct type info; a fuzzy whole-binary text scan kept as a fallback for when dispatcher detection fails (no DDC / stripped). It can mistake data constants for IOCTLs, which is why it no longer runs when `scan_dispatchers()` succeeds. It also skips any `IoControlCode` immediate that feeds an **outbound** request builder (`signatures.OUTBOUND_IOCTL_BUILDERS`: `IoBuildDeviceIoControlRequest`, `ZwDeviceIoControlFile`, `FltDeviceIoControlFile`, ...) via `_precedes_outbound_builder()`, so codes the driver *sends* downstream are not reported as its own dispatch surface (amp.sys sent five disk IOCTLs this way).

**Decompiler comparison anchoring**: switch-case labels are always trusted; `==`/`!=` constants are not. When the dispatcher contains a switch, only comparisons against a switch-selector variable are kept (a `status == STATUS_BUFFER_TOO_SMALL` check on an unrelated lvar is ignored). When there is no switch to anchor on (pure if-chain dispatcher, e.g. beep), every comparison constant is taken and left to the structural/NTSTATUS/sentinel filter.

Every candidate runs through `_is_valid_ctl_code()`, which validates the CTL_CODE structure (DeviceType bits[31:16] must be non-zero), rejects the `0xFFFFFFFF` (`== -1`) sentinel via `_SENTINEL_REJECTS`, and rejects known NTSTATUS values via `_get_ntstatus_values()`. The structural check is equivalent to the old `>= 0x10000` floor but expresses the intent explicitly. `config.IOCTL_MIN_VALUE` was removed -- the check now lives entirely in `_is_valid_ctl_code()`.

Validated exact recovery (full pipeline, IDA 7.6 SP1 + 8.4): HEVD 28/28, ALSysIO64 17/17, WinRing0x64 18/18, beep 2/2, plus zam64 31 (minifilter control device), amp 2 (real inbound handlers, outbound disk IOCTLs excluded), MODAPI 18, no false positives. IDA Free 9.x cannot be driven headlessly (`-S` batch scripting is disabled in the Free edition), so cross-version smoke for 9.x must be run interactively; the new code uses only 7.6-9.x-stable APIs (`ida_nalt.get_switch_info`, `idaapi.calc_switch_cases`, `ida_hexrays` ctree), each getattr-guarded with graceful `[]` fallback.

NTSTATUS filter queries the IDA type DB first (`NTSTATUS` / `_NTSTATUS` enum), falls back to a hardcoded set (`_NTSTATUS_FALLBACK`, expanded to cover the common `0xC00000xx` error range incl. `STATUS_INSUFFICIENT_RESOURCES` 0xC000009A / `STATUS_INVALID_ACL` 0xC0000077). Result is cached for the run. It never blanket-rejects high-bit values: real vendor IOCTLs use device types 0x8000+ (zam64/RTCore `0x8000xxxx`, MODAPI/SSPORT `0x9C40xxxx`).

### Pure-Python test harness
`tests/test_dbr.py` installs in-memory IDA stubs via `sys.modules` before any import of the plugin package. The `DBR_SDK` environment variable sets the simulated `IDA_SDK_VERSION`. Tests cover only logic that has no live-database dependency. IDA-side behaviour (structure labelling, enum creation, cross-reference walks) must be verified inside IDA via `tests/ida_smoke.py`.

### IDA smoke test modes (T5-T7)
`tests/ida_smoke.py` supports three optional check modes passed via `idc.ARGV`:
- `--golden <ref.json>`: order-insensitive comparison of findings against a reference JSON (category, title, severity, IOCTL code/method/access).
- `--ioctl-count <N>`: assert exactly N unique IOCTL codes found (use for ALSysIO64 17, HEVD 28).
- `--expect-heuristic <pattern>`: assert at least one heuristic finding title contains the pattern (e.g. "TOCTOU" for HEVD).
Each check result lands in the output JSON under `checks`; exit code is non-zero on any failure.

When no explicit args are passed, `ida_smoke.py` derives the result path from the IDB (`<idb>.smoke.json`) and auto-discovers an adjacent golden reference (`<idb>.golden.json`), running the golden comparison automatically. This is what `tests/run_golden.ps1` relies on (it avoids passing a `-S` argument with a space, which PowerShell's `Start-Process` mangles). The golden run must use a pristine `.i64` copy each time: re-opening a database IDA has already saved can shift decompiler output and drift the findings.

### Function-name sets
All heuristic, callchain, and scoring function-name lists live in `signatures.py` (the single source of truth, not scattered across modules), imported by convention as `from DriverBuddyReloaded import signatures as sig`: `DANGEROUS_SINKS`, `VALIDATION_FUNCS`, `PRIVILEGE_GATE_FUNCS`, `PRIVILEGED_SENSITIVE_OPS`, `IRQL_RAISING_FUNCS`, `MDL_USER_FUNCS`, `COPY_SINKS`, `ALLOCA_FUNCS`, `POOL_ALLOC_FUNCS`, `PROBE_FUNCS`, `FREE_POOL_FUNCS`. Opcode/instruction severities live in `OPCODE_SEVERITY` (named-opcode scan) and `PRIV_INSN_SEVERITY` (in/out/`mov cr*`/etc. flagged by `heuristics.check_privileged_instructions`). Add to the relevant set in `signatures.py` when expanding coverage; modules import the set by name. `OUTBOUND_IOCTL_BUILDERS` (consumed by `ioctl_decoder.find_ioctls`) lists the request-builder APIs whose `IoControlCode` argument marks an outbound (driver-issued) IOCTL to exclude from the dispatch surface. The two audit checks have their own name sets in `signatures.py`: `DEVICE_CREATE_UNSECURED_FUNCS` (ACL audit, `utils.find_device_create_calls`) and `SYMLINK_CREATE_FUNCS` (symlink-exposure audit, `device_name_finder.find_symbolic_links`); both resolve names via `ctx.functions_map` (superset of `imports_map`) so WDF named functions are covered alongside ntoskrnl imports. The severity constants (`SEV_*`), feature flags, and tuning constants those sets reference remain in `config.py`.

Heuristic callee matching is import-aware: `heuristics._callee_name()` strips the `cs:__imp_` decoration so a config-set name matches whether the callee is a local function or an import (imports otherwise disassemble as `call cs:__imp_<Name>` and silently fail a `print_operand`/`get_func_name` comparison).

### Handler scope and per-IOCTL attribution
The deep heuristics (copy-validation, double-fetch, UAF, pool-alloc-trust, privilege-gate, IRQL, MDL, alloca, privileged-instructions, write-primitives) scan the dispatcher **and its transitive callees**: `heuristics.run()` expands `callchain.handler_seed_eas()` via `callchain.transitive_callees(..., config.HANDLER_SEED_DEPTH)` (library/thunk leaves excluded). `check_user_copy_validation` iterates only that handler-reachable set (not the whole binary), so internal/logging/library copies unrelated to the dispatch surface are not flagged (formerly the dominant copy false-positive class: amp's log builders, RTCore's SDDL helpers). Double-fetch is additionally gated on `_user_pointer_tainted()` (only handlers reachable from a METHOD_NEITHER IOCTL) and a single-path CFG check, so METHOD_BUFFERED kernel-buffer re-reads are not flagged. `check_privilege_gate` is path-level: a privilege gate anywhere on a dispatcher subtree suppresses the whole subtree.

`ioctl_decoder` resolves each switch case's handler function (first in-binary call in the case body) into `finding.data['handler_ea']` / `handler_name`, and the case body's own address span(s) into `finding.data['case_range']` (a *list* of `[lo,hi)` spans; a code that maps to several case labels via a `goto`-shared handler, e.g. WinRing0's `0x9C4060CC/D0`, carries the union of them so an inline opcode/sink in the shared body is still attributed). `callchain.trace` seeds from those handlers, and `scoring.score` attributes danger per IOCTL in three tiers (`data['sink_attribution']`):

- **`handler`** (precise): the case routes to a resolved handler function; sinks reached by that handler are attributed, and `METHOD_NEITHER` + sink forces CRITICAL.
- **`case-inline`**: no callee handler, but the code's own case body span(s) are known; `scoring._inline_reach()` scans those spans for dangerous-sink call sites and inline privileged opcodes (port I/O / `hlt` / etc.) and attributes only what is *inside the case*. `METHOD_NEITHER` + an in-case sink still forces CRITICAL (the sink is provably this code's).
- **`dispatcher-wide`** (imprecise fallback: if-chain dispatchers, immediate recovery): the dispatcher's whole sink union is used but the bump is **capped at HIGH** and never forces CRITICAL, since the evidence is not attributable to the specific code.

This replaced the old behaviour where every IOCTL in a monolithic dispatcher inherited the union of all sinks reachable from the dispatcher and was marked CRITICAL (MODAPI/RTCore/dbutil formerly flagged ~all IOCTLs CRITICAL). `scoring.score()` also emits a driver-level `heuristic` finding "Privileged primitive present; IOCTL linkage unconfirmed" when a HIGH/CRITICAL inline primitive (wrmsr/port-IO) exists but no IOCTL scored HIGH+, so an arbitrary-MSR/physmem driver whose linkage was not established (e.g. BS_RVSIO64) is not left looking benign.

The two "handler-subtree reach" queries that are *not* the heuristic seed expansion -- `scoring._opcode_reach_sev()` and `heuristics._user_pointer_tainted()` -- reach `max(CALLCHAIN_MAX_DEPTH, HANDLER_SEED_DEPTH)` so they never fall short of the depth at which handler bodies were discovered, even if the two depths are tuned independently in the settings UI.

### Register-tracking helpers (registers.py)
`registers.py` is pure Python (no IDA import, unit-tested offline) and is the single home for x86/x64 register knowledge used by the dataflow heuristics. `aliases(reg)` returns every width alias sharing one physical register (`rcx`/`ecx`/`cx`/`cl`/`ch`) so a write to any alias clears the whole tracked group; `memory_base(op)` returns the *base* register of a memory operand, distinguished from a scaled index, so a freed pointer used only as an index (`[rdx+rcx*8]`) is not mistaken for a dereference. `heuristics.check_use_after_free` is built on these: it flags a UAF only when a freed register (seeded from a `FREE_POOL_FUNCS` call matched via `_callee_name`, so imports count) is dereferenced as a memory base before being reassigned or clobbered by an intervening call. Do not reintroduce raw substring matching on operand text for register comparisons -- use these helpers.

### Vulnerable function lists
The surface-scan lists consumed by `utils.get_xrefs()` for the "flagged functions" findings live in `signatures.py`: `C_FUNCTIONS`, `WINAPI_FUNCTIONS`, `WINAPI_FUNCTION_PREFIXES`, and `OPCODES`. The user-editable list is `DriverBuddyReloaded/custom.py` (`driver_functions`), imported into `signatures.py` as `DRIVER_FUNCTIONS`. `WINAPI_FUNCTION_PREFIXES` entries do prefix matching; `WINAPI_FUNCTIONS` entries do exact matching.
