from unittest import mock

from prowler.providers.aws.services.organizations.organizations_service import (
    Organization,
    OrganizationAccount,
)
from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

CHECK_PATH = (
    "prowler.providers.aws.services.organizations."
    "organizations_accounts_have_baseline_scp."
    "organizations_accounts_have_baseline_scp.organizations_client"
)


def _account(account_id: str, baseline_scps=None) -> OrganizationAccount:
    return OrganizationAccount(
        id=account_id,
        arn=f"arn:aws:organizations::123456789012:account/o-abcde12345/{account_id}",
        name=f"account-{account_id}",
        email=f"{account_id}@example.com",
        status="ACTIVE",
        joined_method="CREATED",
        baseline_scps=baseline_scps,
    )


def _run_check(accounts, organization_status="ACTIVE"):
    organizations_client = mock.MagicMock()
    organizations_client.region = AWS_REGION_US_EAST_1
    organizations_client.organization = Organization(
        arn="arn:aws:organizations::123456789012:organization/o-abcde12345",
        id="o-abcde12345",
        status=organization_status,
        master_id="123456789012",
    )
    organizations_client.accounts = accounts

    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ),
        mock.patch(CHECK_PATH, new=organizations_client),
    ):
        from prowler.providers.aws.services.organizations.organizations_accounts_have_baseline_scp.organizations_accounts_have_baseline_scp import (
            organizations_accounts_have_baseline_scp,
        )

        return organizations_accounts_have_baseline_scp().execute()


class Test_organizations_accounts_have_baseline_scp:
    def test_no_active_organization(self):
        assert (
            _run_check([_account("111111111111", ["Baseline"])], "NOT_AVAILABLE") == []
        )

    def test_no_accounts(self):
        assert _run_check([]) == []

    def test_accounts_pass_fail_and_unreadable(self):
        accounts = [
            _account("111111111111", ["BaselineGuardrails"]),
            _account("222222222222", []),
            _account("333333333333", None),
        ]

        findings = _run_check(accounts)

        assert len(findings) == 2

        passed = findings[0]
        assert passed.status == "PASS"
        assert passed.account_uid == "111111111111"
        assert passed.account_name == "account-111111111111"
        assert passed.resource_id == "111111111111"
        assert passed.region == AWS_REGION_US_EAST_1
        assert "BaselineGuardrails" in passed.status_extended

        failed = findings[1]
        assert failed.status == "FAIL"
        assert failed.account_uid == "222222222222"
        assert "no service control policy other than FullAWSAccess" in (
            failed.status_extended
        )

    def test_handles_100_accounts(self):
        accounts = [
            _account(f"{index:012d}", ["BaselineGuardrails"]) for index in range(100)
        ]

        findings = _run_check(accounts)

        assert len(findings) == 100
        assert {finding.account_uid for finding in findings} == {
            account.id for account in accounts
        }
        assert all(finding.status == "PASS" for finding in findings)
