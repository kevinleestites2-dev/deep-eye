"""Compliance mapper — vuln type → control IDs across frameworks."""
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

_FRAMEWORKS_DIR = Path(__file__).parent / "frameworks"

# Keys map config-friendly names to JSON filenames + display names
FRAMEWORK_KEYS = {
    "pci_dss": ("pci_dss_v4.json", "PCI-DSS"),
    "soc2": ("soc2_cc.json", "SOC 2"),
    "iso_27001": ("iso_27001_2022.json", "ISO 27001"),
}

_cache: Dict[str, Dict] = {}


def load_frameworks(framework_keys: Optional[List[str]] = None) -> Dict[str, Dict]:
    """Load framework JSONs, with cache.

    Args:
        framework_keys: List of config keys (e.g. ["pci_dss", "soc2"]). None loads all.

    Returns:
        Dict mapping display name → framework dict.
    """
    if framework_keys is None:
        framework_keys = list(FRAMEWORK_KEYS.keys())

    loaded: Dict[str, Dict] = {}
    for key in framework_keys:
        if key not in FRAMEWORK_KEYS:
            logger.warning(f"Unknown compliance framework key: {key}")
            continue

        if key in _cache:
            loaded[FRAMEWORK_KEYS[key][1]] = _cache[key]
            continue

        filename, display_name = FRAMEWORK_KEYS[key]
        path = _FRAMEWORKS_DIR / filename
        if not path.exists():
            logger.warning(f"Framework file missing: {path}")
            continue

        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            _cache[key] = data
            loaded[display_name] = data
        except (OSError, json.JSONDecodeError) as e:
            logger.error(f"Failed to load framework {key}: {e}")
            continue

    return loaded


def map_vuln(
    vuln_type: str, framework_keys: Optional[List[str]] = None
) -> Dict[str, List[Dict]]:
    """Map a vulnerability type to control IDs across frameworks.

    Args:
        vuln_type: Vuln type string (e.g. "SQL Injection").
        framework_keys: Subset of frameworks. None = all.

    Returns:
        {framework_display_name: [{"control_id", "title", "category"}, ...]}
        Empty list per framework if vuln type unknown.
    """
    frameworks = load_frameworks(framework_keys)
    result: Dict[str, List[Dict]] = {}

    for display_name, fw_data in frameworks.items():
        control_ids = fw_data.get("vuln_mappings", {}).get(vuln_type, [])
        controls_meta = fw_data.get("controls", {})
        result[display_name] = [
            {
                "control_id": cid,
                "title": controls_meta.get(cid, {}).get("title", ""),
                "category": controls_meta.get(cid, {}).get("category", ""),
            }
            for cid in control_ids
        ]

    return result


def enrich_vulnerabilities(
    vulnerabilities: List[Dict], framework_keys: Optional[List[str]] = None
) -> None:
    """Add `compliance` field to each vuln in-place.

    Args:
        vulnerabilities: List of vuln dicts (mutated in place).
        framework_keys: Frameworks to include.
    """
    for vuln in vulnerabilities:
        vuln_type = vuln.get("type", "")
        vuln["compliance"] = map_vuln(vuln_type, framework_keys)
