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

# (Feature class attribute, display label)
_FEATURES = [
    ("IOCTL_SCAN",          "IOCTL scan"),
    ("IOCTL_DECOMPILER",    "IOCTL decompiler (HexRays ctree)"),
    ("CALLCHAIN",           "Callchain tracing"),
    ("HEURISTICS",          "Heuristics"),
    ("TOCTOU_CHECK",        "TOCTOU / double-fetch"),
    ("UAF_DETECT",          "Use-after-free"),
    ("RISK_SCORING",        "Risk scoring"),
    ("EXPORTS_AUDIT",       "Exports audit"),
    ("ACL_AUDIT",           "ACL audit"),
    ("SYMLINK_TRACK",       "Symbolic link tracking"),
    ("IRP_MJ_ENUM",         "IRP_MJ enum annotation"),
    ("SEGMENT_OPCODE_SCAN", "Segment opcode scan (slow)"),
    ("JSON_EXPORT",         "JSON export"),
    ("HTML_REPORT",         "HTML report"),
    ("RESULTS_WINDOW",      "Results window"),
    ("POOLTAG_FALLBACK",    "Pool-tag fallback"),
]

# (config module attribute, display label)
_TUNING = [
    ("CALLCHAIN_MAX_DEPTH",       "Callchain max depth"),
    ("HANDLER_SEED_DEPTH",        "Handler seed depth"),
    ("POOLTAG_LOOKBACK",          "Pool-tag lookback (instrs)"),
    ("COPY_VALIDATION_LOOKBACK",  "Copy validation lookback (instrs)"),
    ("COPY_VALIDATION_LOOKAHEAD", "Copy validation lookahead (instrs)"),
    ("UAF_GLOBAL_BACKWALK",       "UAF global back-walk (instrs)"),
    ("SYMLINK_DECODE_LOOKBACK",   "Symlink decode lookback (instrs)"),
]

# Captured once at import time (before any runtime mutations) so "Reset to
# Defaults" always means the values shipped in config.py.
_FEATURE_DEFAULTS = {attr: bool(getattr(config.Feature, attr)) for attr, _ in _FEATURES}
_TUNING_DEFAULTS  = {attr: int(getattr(config, attr))          for attr, _ in _TUNING}


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
        dlg.setMinimumWidth(520)
        self._dlg = dlg

        root = QtWidgets.QVBoxLayout(dlg)

        # --- Analysis stages (checkboxes in a 2-column grid) -----------------
        feat_group = QtWidgets.QGroupBox("Analysis Stages")
        feat_grid = QtWidgets.QGridLayout(feat_group)
        feat_grid.setColumnStretch(0, 1)
        feat_grid.setColumnStretch(1, 1)

        self._checks = {}
        for i, (attr, label) in enumerate(_FEATURES):
            cb = QtWidgets.QCheckBox(label)
            cb.setChecked(bool(getattr(config.Feature, attr)))
            self._checks[attr] = cb
            feat_grid.addWidget(cb, i // 2, i % 2)

        root.addWidget(feat_group)

        # --- Tuning constants (labelled spinboxes) ---------------------------
        tuning_group = QtWidgets.QGroupBox("Tuning")
        tuning_form = QtWidgets.QFormLayout(tuning_group)
        tuning_form.setLabelAlignment(QtCore.Qt.AlignLeft)

        self._spins = {}
        for attr, label in _TUNING:
            spin = QtWidgets.QSpinBox()
            spin.setRange(1, 9999)
            spin.setValue(int(getattr(config, attr)))
            spin.setFixedWidth(80)
            self._spins[attr] = spin
            tuning_form.addRow(label + ":", spin)

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
    Show the scan-settings dialog. On OK writes the chosen values to config.
    Returns True if the user confirmed, False if they cancelled.
    """
    try:
        dlg = _SettingsDialog()
    except Exception as exc:
        print("[Driver Buddy Reloaded] Could not open settings dialog: {}".format(exc))
        return False

    from PyQt5 import QtWidgets
    if dlg.exec_() == QtWidgets.QDialog.Accepted:
        dlg.apply()
        return True
    return False
