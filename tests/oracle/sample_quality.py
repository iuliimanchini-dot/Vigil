"""Oracle sample: QUALITY problems.

Each offending line carries a `# EXPECT: <tag>` marker. Not named ``test_*`` so
per-file content checks run. Never imported or executed.
"""
from __future__ import annotations

import json  # EXPECT: unused_import
import logging

_log = logging.getLogger(__name__)


def append_item(item, bucket=[]):  # EXPECT: mutable_default
    bucket.append(item)
    return bucket


def read_config_file(path):
    handle = open(path)  # EXPECT: resource_leak
    data = handle.read()
    return data


def swallow_broadly(value):
    try:
        return int(value)
    except Exception:  # EXPECT: broad_swallow
        pass


def log_only_no_reraise(value):
    try:
        return int(value)
    except Exception:  # EXPECT: broad_swallow
        _log.error("conversion failed")


def swallow_bare(value):
    try:
        return int(value)
    except:  # EXPECT: bare_except
        pass


def _never_called(x):  # EXPECT: dead_code
    # Private helper that nothing in the project references.
    return x * x


def is_expired(elapsed_seconds):
    if elapsed_seconds > 86400:  # EXPECT: magic_number
        return True
    return False


def compute_total(values):
    # TODO: handle empty input before summing  # EXPECT: todo
    return sum(values)


def trace_value(x):
    print("DEBUG", x)  # EXPECT: debug_print
    return x


def transform(values):
    result = []
    # legacy implementation kept around just in case:
    # for v in values:
    #     acc = acc + v * 2
    #     result.append(acc)
    # return result
    return [v * 2 for v in values]  # commented block above -> EXPECT: commented_code


def stamp_now():
    from datetime import datetime
    return datetime.now()  # EXPECT: naive_tz


def build_log_path(base_dir, name):
    return base_dir + "/" + name + ".log"  # EXPECT: path_concat
