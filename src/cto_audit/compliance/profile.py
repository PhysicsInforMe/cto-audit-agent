"""
Loader per profili di compliance da YAML.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from cto_audit.compliance.models import ComplianceControl, ComplianceProfile


def _find_profile_path(profile_name: str) -> Path:
    """Trova il file YAML del profilo compliance."""
    from cto_audit._data import get_data_dir
    profiles_dir = get_data_dir("compliance-profiles")
    candidates = [
        profiles_dir / f"{profile_name}.yml",
        profiles_dir / f"{profile_name}.yaml",
    ]
    for path in candidates:
        if path.exists():
            return path
    raise FileNotFoundError(
        f"Profilo compliance '{profile_name}' non trovato. "
        f"Cercato in: {', '.join(str(p) for p in candidates)}"
    )


def load_compliance_profile(profile_name: str) -> ComplianceProfile:
    """Carica un profilo di compliance da file YAML."""
    path = _find_profile_path(profile_name)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))

    controls = []
    for ctrl_data in raw.get("controls", []):
        controls.append(ComplianceControl(
            control_id=ctrl_data["control_id"],
            title=ctrl_data["title"],
            article_ref=ctrl_data["article_ref"],
            description=ctrl_data.get("description", ""),
            required_rules=ctrl_data.get("required_rules", []),
            contributing_rules=ctrl_data.get("contributing_rules", []),
        ))

    return ComplianceProfile(
        name=raw.get("name", profile_name),
        description=raw.get("description", ""),
        version=raw.get("version", "1.0"),
        controls=controls,
    )
