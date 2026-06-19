# Changelog

## Unreleased - IDA 8.4/9.0 port, refactor and feature absorption

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
