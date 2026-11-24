import importlib
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest import mock

import pytest
from moto import mock_aws

from prowler.lib.check.check import execute_checks
from prowler.lib.check.checks_loader import load_checks_to_execute
from prowler.lib.check.compliance import update_checks_metadata_with_compliance
from prowler.lib.check.custom_compliance import load_custom_compliance_frameworks
from prowler.lib.check.models import CheckMetadata
from prowler.lib.check.utils import _recover_ep_checks
from prowler.lib.outputs.compliance.generic.generic import GenericCompliance
from prowler.lib.outputs.csv.csv import CSV
from prowler.lib.outputs.finding import Finding
from prowler.lib.outputs.ocsf.ocsf import OCSF
from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

REPO_ROOT = Path(__file__).resolve().parents[4]
PLUGIN_ROOT = REPO_ROOT / "examples" / "custom_checks"
PLUGIN_SRC = PLUGIN_ROOT
PLUGIN_PACKAGE = "prowler_custom_checks"
COMPLIANCE_FILE = (
    PLUGIN_SRC
    / PLUGIN_PACKAGE
    / "compliance"
    / "aws"
    / "custom_cloud_security_baseline_aws.json"
)

CHECK_MODULES = {
    "s3_custom_bucket_versioning_enabled": (
        f"{PLUGIN_PACKAGE}.services.s3.s3_custom_bucket_versioning_enabled."
        "s3_custom_bucket_versioning_enabled"
    ),
    "ec2_custom_instance_imdsv2_required": (
        f"{PLUGIN_PACKAGE}.services.ec2.ec2_custom_instance_imdsv2_required."
        "ec2_custom_instance_imdsv2_required"
    ),
    "iam_custom_root_mfa_enabled": (
        f"{PLUGIN_PACKAGE}.services.iam.iam_custom_root_mfa_enabled."
        "iam_custom_root_mfa_enabled"
    ),
}


class _EntryPoint:
    def __init__(self, name, value, group):
        self.name = name
        self.value = value
        self.group = group

    def load(self):
        return importlib.import_module(self.value)


class _Resource:
    def __init__(self, **attributes):
        self.__dict__.update(attributes)

    def dict(self):
        return dict(self.__dict__)


def _entry_points(group):
    if group == "prowler.checks.aws":
        return [
            _EntryPoint(name, value, group) for name, value in CHECK_MODULES.items()
        ]
    return []


def _metadata_paths():
    return {
        name: PLUGIN_SRC / Path(module.replace(".", "/")).with_suffix(".metadata.json")
        for name, module in CHECK_MODULES.items()
    }


def _fake_client_modules(s3_client, ec2_client, iam_client):
    modules = {}
    for module_name, client_name, client in (
        ("prowler.providers.aws.services.s3.s3_client", "s3_client", s3_client),
        ("prowler.providers.aws.services.ec2.ec2_client", "ec2_client", ec2_client),
        ("prowler.providers.aws.services.iam.iam_client", "iam_client", iam_client),
    ):
        module = ModuleType(module_name)
        setattr(module, client_name, client)
        modules[module_name] = module
    return modules


def _load_plugin_modules(s3_client, ec2_client, iam_client):
    fake_modules = _fake_client_modules(s3_client, ec2_client, iam_client)
    modules = {}
    with mock.patch.dict(sys.modules, fake_modules):
        for check_name, module_name in CHECK_MODULES.items():
            sys.modules.pop(module_name, None)
            modules[check_name] = importlib.import_module(module_name)
    # patch.dict restores sys.modules on exit, so re-register the imported
    # check modules. Check.__init__ resolves its metadata through sys.modules.
    for module_name, module in zip(CHECK_MODULES.values(), modules.values()):
        sys.modules[module_name] = module
    return modules


def _plugin_metadata():
    metadata = {}
    for name, path in _metadata_paths().items():
        metadata[name] = CheckMetadata.parse_file(path)
    return metadata


def _clients():
    bucket_pass = _Resource(
        id="compliant-bucket",
        name="compliant-bucket",
        arn="arn:aws:s3:::compliant-bucket",
        region=AWS_REGION_US_EAST_1,
        versioning=True,
        versioning_retrieved=True,
    )
    bucket_fail = _Resource(
        id="noncompliant-bucket",
        name="noncompliant-bucket",
        arn="arn:aws:s3:::noncompliant-bucket",
        region=AWS_REGION_US_EAST_1,
        versioning=False,
        versioning_retrieved=True,
    )
    s3_client = SimpleNamespace(buckets={"pass": bucket_pass, "fail": bucket_fail})

    instance = _Resource(
        id="i-custom",
        arn=f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:123456789012:instance/i-custom",
        region=AWS_REGION_US_EAST_1,
        state="running",
        http_endpoint="enabled",
        http_tokens="optional",
    )
    ec2_client = SimpleNamespace(instances=[instance])

    iam_client = SimpleNamespace(
        region=AWS_REGION_US_EAST_1,
        credential_report=[
            {
                "user": "<root_account>",
                "arn": "arn:aws:iam::123456789012:root",
                "mfa_active": "false",
            }
        ],
    )
    return s3_client, ec2_client, iam_client


@pytest.fixture
def custom_checks_plugin():
    sys.path.insert(0, str(PLUGIN_SRC))
    yield
    sys.path.remove(str(PLUGIN_SRC))
    for module_name in CHECK_MODULES.values():
        sys.modules.pop(module_name, None)


@mock_aws
def test_three_custom_checks_execute_and_keep_standard_report_contract(
    custom_checks_plugin,
):
    s3_client, ec2_client, iam_client = _clients()
    _load_plugin_modules(s3_client, ec2_client, iam_client)

    with mock.patch(
        "prowler.lib.check.utils.importlib.metadata.entry_points",
        side_effect=_entry_points,
    ):
        discovered = _recover_ep_checks("aws")

    assert {check_name for check_name, _ in discovered} == set(CHECK_MODULES)

    bulk_checks_metadata = _plugin_metadata()
    legacy, _ = load_custom_compliance_frameworks("aws", [str(COMPLIANCE_FILE)])
    bulk_checks_metadata = update_checks_metadata_with_compliance(
        legacy, bulk_checks_metadata
    )
    framework_name = "custom_cloud_security_baseline_aws"

    checks_to_execute = load_checks_to_execute(
        provider="aws",
        bulk_checks_metadata=bulk_checks_metadata,
        bulk_compliance_frameworks=legacy,
        compliance_frameworks=[framework_name],
    )
    assert checks_to_execute == set(CHECK_MODULES)

    provider = set_mocked_aws_provider(
        [AWS_REGION_US_EAST_1], mutelist=SimpleNamespace(mutelist={})
    )
    output_options = SimpleNamespace(
        only_logs=True,
        verbose=False,
        status=None,
        fixer=False,
        bulk_checks_metadata=bulk_checks_metadata,
        unix_timestamp=False,
    )

    with mock.patch(
        "prowler.lib.check.check.importlib.metadata.entry_points",
        side_effect=_entry_points,
    ):
        findings = execute_checks(
            sorted(checks_to_execute),
            provider,
            None,
            "config.yaml",
            output_options,
        )

    assert len(findings) == 4
    by_check = {}
    for finding in findings:
        by_check.setdefault(finding.check_metadata.CheckID, []).append(finding)

    assert {
        finding.status for finding in by_check["s3_custom_bucket_versioning_enabled"]
    } == {
        "PASS",
        "FAIL",
    }
    assert by_check["ec2_custom_instance_imdsv2_required"][0].status == "FAIL"
    assert by_check["iam_custom_root_mfa_enabled"][0].status == "FAIL"

    finding_outputs = [
        Finding.generate_output(provider, finding, output_options)
        for finding in findings
    ]
    csv_output = CSV(findings=finding_outputs)
    assert len(csv_output.data) == 4
    assert {row["CHECK_ID"] for row in csv_output.data} == set(CHECK_MODULES)
    assert all("CUSTOM-CSB-1.0" in row["COMPLIANCE"] for row in csv_output.data)

    ocsf_output = OCSF(findings=finding_outputs)
    assert len(ocsf_output.data) == 4
    assert {finding.metadata.event_code for finding in ocsf_output.data} == set(
        CHECK_MODULES
    )

    compliance_output = GenericCompliance(
        findings=finding_outputs,
        compliance=legacy[framework_name],
    )
    assert len(compliance_output.data) == 4
    assert {row.Requirements_Id for row in compliance_output.data} == {
        "CSB-1",
        "CSB-2",
        "CSB-3",
    }
