import json

import pytest

from prowler.lib.check.custom_compliance import (
    CustomComplianceError,
    load_custom_compliance_frameworks,
    merge_custom_compliance_frameworks,
)


def _write_json(path, payload):
    path.write_text(json.dumps(payload))
    return str(path)


def _legacy_framework(provider="AWS", framework="CUSTOM-CSB"):
    return {
        "Framework": framework,
        "Name": "Custom Cloud Security Baseline",
        "Provider": provider,
        "Version": "1.0",
        "Description": "Organization-specific cloud security controls.",
        "Requirements": [
            {
                "Id": "CSB-1",
                "Description": "S3 buckets must have versioning enabled.",
                "Attributes": [
                    {
                        "ItemId": "CSB-1",
                        "Section": "Storage Security",
                        "Service": "s3",
                    }
                ],
                "Checks": ["s3_custom_bucket_versioning_enabled"],
            }
        ],
    }


def _universal_framework(provider="aws"):
    return {
        "framework": "CUSTOM-UNIVERSAL",
        "name": "Custom Universal Baseline",
        "provider": provider,
        "version": "1.0",
        "description": "Organization-specific controls in the universal schema.",
        "requirements": [
            {
                "id": "CU-1",
                "description": "EC2 instances must require IMDSv2.",
                "checks": {
                    "aws": ["ec2_custom_instance_imdsv2_required"],
                },
            }
        ],
    }


class TestLoadCustomComplianceFrameworks:
    def test_loads_legacy_and_universal_frameworks(self, tmp_path):
        legacy_file = _write_json(
            tmp_path / "custom_cloud_security_baseline_aws.json",
            _legacy_framework(),
        )
        universal_file = _write_json(
            tmp_path / "custom_universal_aws.json", _universal_framework()
        )

        legacy, universal = load_custom_compliance_frameworks(
            "aws", [legacy_file, universal_file]
        )

        assert set(legacy) == {"custom_cloud_security_baseline_aws"}
        assert legacy["custom_cloud_security_baseline_aws"].Requirements[0].Checks == [
            "s3_custom_bucket_versioning_enabled"
        ]
        assert set(universal) == {"custom_universal_aws"}
        assert universal["custom_universal_aws"].requirements[0].checks == {
            "aws": ["ec2_custom_instance_imdsv2_required"]
        }
        assert (
            universal["custom_universal_aws"].outputs.table_config.group_by == "Section"
        )

    def test_rejects_framework_for_another_provider(self, tmp_path):
        legacy_file = _write_json(
            tmp_path / "azure_baseline.json", _legacy_framework(provider="Azure")
        )

        with pytest.raises(CustomComplianceError, match="Azure"):
            load_custom_compliance_frameworks("aws", [legacy_file])

    def test_rejects_duplicate_framework_names(self, tmp_path):
        first = _write_json(tmp_path / "baseline.json", _legacy_framework())
        second = _write_json(tmp_path / "baseline.json", _legacy_framework())

        with pytest.raises(CustomComplianceError, match="baseline"):
            load_custom_compliance_frameworks("aws", [first, second])


class TestMergeCustomComplianceFrameworks:
    def test_merges_without_mutating_inputs(self):
        builtin_legacy = {"cis_aws": "builtin"}
        builtin_universal = {"universal_aws": "builtin"}
        custom_legacy = {"custom_aws": "custom"}
        custom_universal = {"custom_universal_aws": "custom"}

        legacy, universal = merge_custom_compliance_frameworks(
            builtin_legacy,
            builtin_universal,
            custom_legacy,
            custom_universal,
        )

        assert legacy == {"cis_aws": "builtin", "custom_aws": "custom"}
        assert universal == {
            "universal_aws": "builtin",
            "custom_universal_aws": "custom",
        }
        assert builtin_legacy == {"cis_aws": "builtin"}
        assert builtin_universal == {"universal_aws": "builtin"}

    def test_rejects_collisions_with_built_in_frameworks(self):
        with pytest.raises(CustomComplianceError, match="cis_aws"):
            merge_custom_compliance_frameworks(
                {"cis_aws": "builtin"},
                {},
                {"cis_aws": "custom"},
                {},
            )

    def test_allows_built_in_frameworks_in_both_schemas(self):
        legacy, universal = merge_custom_compliance_frameworks(
            {"cis_aws": "legacy"},
            {"cis_aws": "universal"},
            {"custom_aws": "custom"},
            {},
        )

        assert legacy["cis_aws"] == "legacy"
        assert universal["cis_aws"] == "universal"
