"""
settings_ui.py: scan-settings dialog for Driver Buddy Reloaded.

Uses PyQt5 (bundled with IDA 7.6+) rather than ida_kernwin.Form, which has
fragile format-string semantics that differ across IDA versions.

Importing this module outside IDA is safe; all Qt imports are deferred inside
show_settings() so the pure-Python test harness can import it without side
effects.
"""

from __future__ import annotations

from DriverBuddyReloaded import config

# ---------------------------------------------------------------------------
# Metadata tables -- keep in sync with config.py
# ---------------------------------------------------------------------------

# Groups of (Feature class attribute, display label, tooltip).
# Tooltip is shown on hover; use "" to suppress it for self-explanatory items.
_FEATURE_GROUPS = [
    ("IOCTL", [
        ("IOCTL_SCAN",
         "IOCTL scan",
         "Primary IOCTL discovery: dispatcher scan plus immediate-operand search"),
        ("IOCTL_DECOMPILER",
         "IOCTL decompiler (HexRays)",
         "Use HexRays ctree to recover codes from switch-case labels and comparison "
         "constants; required to handle jump-table and binary-search dispatch patterns"),
    ]),
    ("Deep Analysis", [
        ("CALLCHAIN",
         "Callchain tracing",
         "Trace call paths from each IOCTL handler to dangerous sinks; requires IOCTL scan"),
        ("HEURISTICS",
         "Heuristics",
         "Structural checks: copy-validation, IRQL, MDL, alloca, pool-alloc-trust, "
         "write-primitives, and privileged instructions"),
        ("TOCTOU_CHECK",
         "TOCTOU / double-fetch",
         "Flag double-fetch of a user-mode pointer within a single dispatch path "
         "(time-of-check / time-of-use race condition); gated on METHOD_NEITHER IOCTLs"),
        ("UAF_DETECT",
         "Use-after-free",
         "Detect use-after-free patterns via per-register CFG walk and a backward "
         "global instruction scan"),
        ("RISK_SCORING",
         "Risk scoring",
         "Assign a severity level to each IOCTL based on reachable dangerous sinks "
         "and heuristic hits"),
    ]),
    ("Audit & Discovery", [
        ("EXPORTS_AUDIT",
         "Exports audit",
         "Report exported functions with zero cross-references "
         "(dead or unexplained entry points)"),
        ("ACL_AUDIT",
         "ACL audit",
         "Flag DeviceCreate calls that pass an open (world-accessible) security descriptor"),
        ("SYMLINK_TRACK",
         "Symbolic link tracking",
         "Trace symbolic link registrations to map device aliases reachable from user mode"),
        ("SEGMENT_OPCODE_SCAN",
         "Segment opcode scan (slow)",
         "Scan every code segment for opcode patterns of interest; "
         "can be slow on large binaries -- disabled by default"),
    ]),
    ("Annotation", [
        ("IRP_MJ_ENUM",
         "IRP_MJ enum annotation",
         "Annotate the decompiler output so MajorFunction[IRP_MJ_CREATE] appears "
         "instead of MajorFunction[0]"),
        ("POOLTAG_FALLBACK",
         "Pool-tag fallback",
         "When no import-annotated tags are found, scan backward from each pool-alloc "
         "call site for immediate operands staged in registers that IDA does not annotate automatically"),
    ]),
    ("Output", [
        ("JSON_EXPORT",
         "JSON export",
         "Write findings to a .json file next to the IDB"),
        ("HTML_REPORT",
         "HTML report",
         "Write findings to a browsable .html report next to the IDB"),
        ("RESULTS_WINDOW",
         "Results window",
         "Open the findings chooser window inside IDA after analysis completes"),
    ]),
]

# Flat list derived from groups -- used for defaults capture and _checks order.
_FEATURES = [(attr, label) for _, items in _FEATURE_GROUPS for attr, label, _ in items]

# (config module attribute, display label, tooltip)
_TUNING = [
    ("CALLCHAIN_MAX_DEPTH",
     "Callchain max depth",
     "Maximum recursion depth when following call chains from IOCTL handlers to sinks"),
    ("HANDLER_SEED_DEPTH",
     "Handler seed depth",
     "Call levels expanded from the IOCTL handler when seeding deep heuristics "
     "(double-fetch, UAF, pool-alloc-trust, etc.)"),
    ("POOLTAG_LOOKBACK",
     "Pool-tag lookback (instrs)",
     "Instructions scanned backward from a pool allocation to find the tag constant"),
    ("COPY_VALIDATION_LOOKBACK",
     "Copy validation lookback (instrs)",
     "Instructions scanned backward from a copy sink to find a size validation check"),
    ("COPY_VALIDATION_LOOKAHEAD",
     "Copy validation lookahead (instrs)",
     "Instructions scanned forward from a copy sink to find a size validation check"),
    ("UAF_GLOBAL_BACKWALK",
     "UAF global back-walk (instrs)",
     "Instructions scanned backward in the function when searching for a free before a use"),
    ("SYMLINK_DECODE_LOOKBACK",
     "Symlink decode lookback (instrs)",
     "Instructions scanned backward from a symlink registration to decode the device path"),
]

# Captured once at import time (before any runtime mutations) so "Reset to
# Defaults" always means the values shipped in config.py.
_FEATURE_DEFAULTS = {attr: bool(getattr(config.Feature, attr)) for attr, _ in _FEATURES}
_TUNING_DEFAULTS  = {attr: int(getattr(config, attr))          for attr, label, _ in _TUNING}


class _SettingsDialog:
    """
    PyQt5 modal dialog. Constructed lazily so the module can be imported in
    environments where Qt is unavailable (e.g. the pure-Python test harness).
    """

    def __init__(self):
        from PyQt5 import QtCore, QtWidgets

        dlg = QtWidgets.QDialog()
        dlg.setWindowTitle("Driver Buddy Reloaded - Settings")
        dlg.setWindowFlags(
            dlg.windowFlags() & ~QtCore.Qt.WindowContextHelpButtonHint
        )
        dlg.setMinimumWidth(560)
        self._dlg = dlg

        root = QtWidgets.QVBoxLayout(dlg)

        # --- Analysis stages (one QGroupBox per logical group, 2-column grid) --
        self._checks = {}
        for group_name, items in _FEATURE_GROUPS:
            grp = QtWidgets.QGroupBox(group_name)
            grid = QtWidgets.QGridLayout(grp)
            grid.setColumnStretch(0, 1)
            grid.setColumnStretch(1, 1)
            for i, (attr, label, tip) in enumerate(items):
                cb = QtWidgets.QCheckBox(label)
                cb.setChecked(bool(getattr(config.Feature, attr)))
                if tip:
                    cb.setToolTip(tip)
                self._checks[attr] = cb
                grid.addWidget(cb, i // 2, i % 2)
            root.addWidget(grp)

        # --- Tuning constants (labelled spinboxes) ---------------------------
        tuning_group = QtWidgets.QGroupBox("Tuning")
        tuning_form = QtWidgets.QFormLayout(tuning_group)
        tuning_form.setLabelAlignment(QtCore.Qt.AlignLeft)

        self._spins = {}
        for attr, label, tip in _TUNING:
            spin = QtWidgets.QSpinBox()
            spin.setRange(1, 9999)
            spin.setValue(int(getattr(config, attr)))
            spin.setFixedWidth(80)
            if tip:
                spin.setToolTip(tip)
            self._spins[attr] = spin
            lbl = QtWidgets.QLabel(label + ":")
            if tip:
                lbl.setToolTip(tip)
            tuning_form.addRow(lbl, spin)

        root.addWidget(tuning_group)

        # --- Buttons ---------------------------------------------------------
        buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel
        )
        # Validate before accepting so the dialog stays open on invalid input.
        ok_btn = buttons.button(QtWidgets.QDialogButtonBox.Ok)
        ok_btn.clicked.connect(self._on_ok)
        buttons.rejected.connect(dlg.reject)

        reset_btn = QtWidgets.QPushButton("Reset to Defaults")
        reset_btn.clicked.connect(self._on_reset)
        buttons.addButton(reset_btn, QtWidgets.QDialogButtonBox.ResetRole)

        root.addWidget(buttons)

    def _on_ok(self):
        """Validate proposed feature-flag combination; accept only when coherent."""
        from PyQt5 import QtWidgets
        proposed = {attr: cb.isChecked() for attr, cb in self._checks.items()}
        if proposed.get("CALLCHAIN") and not proposed.get("IOCTL_SCAN"):
            QtWidgets.QMessageBox.warning(
                self._dlg,
                "Driver Buddy Reloaded",
                "Callchain tracing requires IOCTL scan to be enabled.",
            )
            return
        if proposed.get("IOCTL_DECOMPILER") and not proposed.get("IOCTL_SCAN"):
            QtWidgets.QMessageBox.warning(
                self._dlg,
                "Driver Buddy Reloaded",
                "IOCTL decompiler requires IOCTL scan to be enabled.",
            )
            return
        self._dlg.accept()

    def _on_reset(self):
        """Restore all controls to the config.py defaults (does not save until OK)."""
        for attr, cb in self._checks.items():
            cb.setChecked(_FEATURE_DEFAULTS[attr])
        for attr, spin in self._spins.items():
            spin.setValue(_TUNING_DEFAULTS[attr])

    def exec_(self) -> int:
        return self._dlg.exec_()

    def apply(self) -> None:
        """Write dialog values to config. Only called after accept() -- always valid."""
        for attr, cb in self._checks.items():
            setattr(config.Feature, attr, cb.isChecked())
        for attr, spin in self._spins.items():
            setattr(config, attr, spin.value())


def show_settings() -> bool:
    """
    Show the scan-settings dialog. Returns True if analysis should proceed.

    On OK the chosen values are written to config and True is returned; on Cancel
    False is returned so the caller aborts the run. If the dialog cannot be shown
    (e.g. Qt unavailable), a warning is logged and True is returned so analysis
    proceeds with the current config settings rather than being silently disabled.
    """
    try:
        dlg = _SettingsDialog()
        from PyQt5 import QtWidgets
        accepted = dlg.exec_() == QtWidgets.QDialog.Accepted
    except Exception as exc:
        print("[Driver Buddy Reloaded] Settings dialog unavailable ({}); "
              "proceeding with current settings.".format(exc))
        return True

    if accepted:
        dlg.apply()
        return True
    return False
