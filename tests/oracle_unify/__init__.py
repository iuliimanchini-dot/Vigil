# Oracle corpus for the authority+runtime adapter-unification refactor.
#
# These fixtures DELIBERATELY exercise the relocated Python resolver/visitor
# logic that the vigil_mapper / vigil_forensic source trees do not (their write
# sites resolve to __unknown_target__ and they have no __main__ guards / merged
# side-effect modules). They are the real verification gate for the refactor:
# building the authority + runtime maps on this directory before and after the
# relocation must produce byte-identical Python entries.
#
# DO NOT "simplify" these files — each construct pins a specific code path
# (alias chains, os.replace atomic trio, provenance variants, side-effect merge,
# entrypoint cross-ref). See tests/test_oracle_unify_maps.py for the assertions.
