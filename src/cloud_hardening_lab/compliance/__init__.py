"""CIS control mapping for synthetic findings."""

from cloud_hardening_lab.compliance.cis_mapping import (
    CIS_MAPPING_BY_RULE_ID,
    CisMapping,
    apply_cis_mapping,
    cis_mapping_for_rule,
)

__all__ = ["CIS_MAPPING_BY_RULE_ID", "CisMapping", "apply_cis_mapping", "cis_mapping_for_rule"]
