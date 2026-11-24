"""Load compliance frameworks supplied at runtime by the CLI.

Prowler packages can contribute compliance JSON through the
``prowler.compliance`` entry point, but users often need to run a local
baseline without packaging it first. This module loads those files, supporting
both the legacy provider schema and the universal schema, and validates that
the framework belongs to the provider being scanned.
"""

import json
from pathlib import Path

from pydantic.v1 import ValidationError

from prowler.lib.check.compliance_models import (
    Compliance,
    ComplianceFramework,
    OutputsConfig,
    TableConfig,
)


class CustomComplianceError(ValueError):
    """Raised when a custom compliance file cannot be used by this scan."""


def _framework_name(path: Path) -> str:
    return path.stem


def _load_legacy_framework(path: Path, provider: str) -> Compliance:
    try:
        framework = Compliance.parse_file(path)
    except (ValidationError, OSError) as error:
        raise CustomComplianceError(
            f"Invalid custom compliance framework '{path}': {error}"
        ) from error

    if framework.Provider.lower() != provider.lower():
        raise CustomComplianceError(
            f"Custom compliance framework '{path}' targets provider "
            f"'{framework.Provider}', not '{provider}'"
        )
    return framework


def _load_universal_framework(path: Path, provider: str) -> ComplianceFramework:
    try:
        with path.open() as file:
            framework = ComplianceFramework(**json.load(file))
    except (ValidationError, OSError, ValueError) as error:
        raise CustomComplianceError(
            f"Invalid custom compliance framework '{path}': {error}"
        ) from error

    if not framework.supports_provider(provider):
        raise CustomComplianceError(
            f"Custom compliance framework '{path}' does not support provider "
            f"'{provider}'"
        )

    # The universal output pipeline expects a table config. Local examples
    # often omit it; default to grouping by Section so the framework still
    # produces the same CSV/OCSF outputs as packaged universal frameworks.
    if framework.outputs is None:
        framework.outputs = OutputsConfig()
    if framework.outputs.table_config is None:
        framework.outputs.table_config = TableConfig(group_by="Section")
    return framework


def _is_universal_framework(path: Path) -> bool:
    with path.open() as file:
        data = json.load(file)
    return "requirements" in data or "attributes_metadata" in data


def load_custom_compliance_frameworks(
    provider: str, compliance_files: list[str]
) -> tuple[dict[str, Compliance], dict[str, ComplianceFramework]]:
    """Load custom compliance files for *provider*.

    Legacy and universal frameworks are returned separately because the CLI
    keeps both loaders and output pipelines apart. The filename stem is the
    framework selector used by ``--compliance`` internally.
    """
    legacy_frameworks = {}
    universal_frameworks = {}
    seen_names = set()

    for compliance_file in compliance_files:
        path = Path(compliance_file)
        name = _framework_name(path)
        if name in seen_names:
            raise CustomComplianceError(
                f"Duplicate custom compliance framework name '{name}'"
            )
        seen_names.add(name)

        try:
            is_universal = _is_universal_framework(path)
        except (json.JSONDecodeError, OSError) as error:
            raise CustomComplianceError(
                f"Invalid custom compliance framework '{path}': {error}"
            ) from error

        if is_universal:
            universal_frameworks[name] = _load_universal_framework(path, provider)
        else:
            legacy_frameworks[name] = _load_legacy_framework(path, provider)

    return legacy_frameworks, universal_frameworks


def merge_custom_compliance_frameworks(
    bulk_compliance_frameworks: dict,
    universal_frameworks: dict,
    custom_compliance_frameworks: dict,
    custom_universal_frameworks: dict,
) -> tuple[dict, dict]:
    """Merge custom frameworks into the built-in registries.

    Name collisions are rejected instead of silently overriding a built-in
    framework: a custom baseline with a name such as ``cis_1.5_aws`` would
    otherwise change which checks run for an existing selector.
    """
    collisions = set()
    custom_names = set(custom_compliance_frameworks) | set(custom_universal_frameworks)
    for name in custom_names:
        # A built-in framework can appear in both the legacy and universal
        # registries; that is expected. Only a custom name is a collision.
        if (
            name in bulk_compliance_frameworks
            or name in universal_frameworks
            or (
                name in custom_compliance_frameworks
                and name in custom_universal_frameworks
            )
        ):
            collisions.add(name)

    if collisions:
        raise CustomComplianceError(
            "Custom compliance framework name(s) already exist: "
            + ", ".join(sorted(collisions))
        )

    merged_legacy = {**bulk_compliance_frameworks, **custom_compliance_frameworks}
    merged_universal = {**universal_frameworks, **custom_universal_frameworks}
    return merged_legacy, merged_universal
