"""Runtime oracle: __main__ guard + entry-function cross-reference.

Pins _RuntimeVisitor._handle_main_block + _check_function entry-function
cross-ref: the `main` def invoked from the guard must surface as an
entry_function node, and the guard itself as a main_entrypoint node.
"""
from __future__ import annotations


def main() -> None:
    print("running")
    helper()


def helper() -> None:
    # ordinary helper: must NOT become an entrypoint
    pass


if __name__ == "__main__":
    main()
