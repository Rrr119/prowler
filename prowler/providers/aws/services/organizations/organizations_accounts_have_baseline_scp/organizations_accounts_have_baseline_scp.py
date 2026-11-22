from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.organizations.organizations_client import (
    organizations_client,
)


class organizations_accounts_have_baseline_scp(Check):
    """AWS Organizations member accounts have a baseline SCP attached."""

    def execute(self) -> list[Check_Report_AWS]:
        findings = []

        if (
            not organizations_client.organization
            or organizations_client.organization.status != "ACTIVE"
            or not organizations_client.accounts
        ):
            return findings

        for account in organizations_client.accounts:
            if account.baseline_scps is None:
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=account)
            report.account_uid = account.id
            report.account_name = account.name
            report.account_email = account.email
            report.resource_id = account.id
            report.resource_arn = account.arn
            report.region = organizations_client.region

            if account.baseline_scps:
                report.status = "PASS"
                report.status_extended = (
                    f"AWS Organizations account {account.id} ({account.name}) has "
                    f"baseline service control policies attached directly or "
                    f"inherited: {', '.join(account.baseline_scps)}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"AWS Organizations account {account.id} ({account.name}) has "
                    "no service control policy other than FullAWSAccess attached "
                    "directly or inherited."
                )

            findings.append(report)

        return findings
