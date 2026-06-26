"""Oracle sample: SECURITY problems.

Each offending line carries a `# EXPECT: <tag>` marker. Tags are the oracle's
own labels; the reviewer maps them to the auditor's real check_ids
(security_scan, secrets_scan, boundary_validation_scan, ...).

This file is intentionally NOT named ``test_*`` so the auditor's per-file
content checks (which skip ``test_``/``conftest`` basenames) still run on it.
The code here is never imported or executed -- it exists only to be scanned.
"""
from __future__ import annotations

import os
import pickle
import subprocess

import yaml


def get_user_by_concat(cur, uid):
    # SQL literal carries real clause structure (SELECT ... FROM ... WHERE) and a
    # non-literal operand (uid), so the AST concat rule fires.
    cur.execute("SELECT * FROM users WHERE id=" + uid)  # EXPECT: sqli
    return cur.fetchone()


def get_user_by_fstring(cur, uid):
    cur.execute(f"SELECT * FROM users WHERE id={uid}")  # EXPECT: sqli
    return cur.fetchone()


def get_user_by_percent(cur, uid):
    cur.execute("SELECT * FROM accounts WHERE id=%s" % uid)  # EXPECT: sqli
    return cur.fetchone()


def get_user_by_format(cur, uid):
    cur.execute("SELECT * FROM members WHERE id={}".format(uid))  # EXPECT: sqli
    return cur.fetchone()


# Hardcoded credential. Value is a synthetic dummy (NOT a live token, NOT a
# real provider key format such as ghp_/sk-/AKIA), but it is token-shaped and
# long enough to match the generic ``token = "<16+ chars>"`` secret rule.
# This line deliberately avoids the auditor's skip-words so it is NOT
# suppressed; see MANIFEST for the FAKE_/secret-scanner tension.
SESSION_TOKEN = "ZmFrZWR1bW15c2VjcmV0MDF2YWx1ZQ"  # EXPECT: secret


def run_user_expression(user_input):
    return eval(user_input)  # EXPECT: eval_exec


def run_user_statement(user_code):
    exec(user_code)  # EXPECT: eval_exec


def run_shell_command(cmd):
    os.system(cmd)  # EXPECT: shell


def run_shell_subprocess(cmd):
    subprocess.run(cmd, shell=True)  # EXPECT: shell


def load_pickled_blob(raw_bytes):
    return pickle.loads(raw_bytes)  # EXPECT: unsafe_deser


def load_yaml_doc(raw_text):
    return yaml.load(raw_text)  # EXPECT: unsafe_deser
