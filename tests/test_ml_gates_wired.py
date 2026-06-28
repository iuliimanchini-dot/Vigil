"""P1-fix regression guard: ml gates must fire END-TO-END via run_forensic_audit.

ml_checks was registered in GATE_SPECS but MISSING from _FILE_BASED_GATES, so the
full audit skipped it as 'not_file_based' — the ML feature was dead despite 13
green unit tests (which called the check functions directly, never through the
audit). This test exercises the real integration path so the wiring can't regress.
"""
from __future__ import annotations

from vigil_forensic import run_forensic_audit
from vigil_forensic.self_audit import _FILE_BASED_GATES


def test_ml_checks_wired_into_file_based_gates():
    assert "ml_checks" in _FILE_BASED_GATES, (
        "ml_checks must be in _FILE_BASED_GATES or the full audit skips it as "
        "'not_file_based' (dead feature)"
    )


def test_all_four_ml_gates_fire_end_to_end(tmp_path):
    f = tmp_path / "model.py"
    f.write_text(
        "import numpy as np\n"
        "from sklearn.preprocessing import StandardScaler\n"
        "from sklearn.model_selection import train_test_split\n"
        "def go(df, X, y, X_test):\n"
        "    df['t'] = df['p'].shift(-1)\n"          # lookahead
        "    train_test_split(X, y)\n"               # no random_state
        "    StandardScaler().fit(X_test)\n"          # leakage
        "    return np.random.rand(5)\n",             # rng no seed
        encoding="utf-8",
    )
    r = run_forensic_audit(str(tmp_path))
    fired = {
        str(x.get("check_id"))
        for x in r["findings"]
        if str(x.get("check_id", "")).startswith("ml.")
    }
    for expected in (
        "ml.lookahead_negative_shift",
        "ml.nondeterministic_split",
        "ml.scaler_fit_on_test",
        "ml.missing_random_seed",
    ):
        assert expected in fired, f"{expected} did not fire e2e (fired: {sorted(fired)})"
