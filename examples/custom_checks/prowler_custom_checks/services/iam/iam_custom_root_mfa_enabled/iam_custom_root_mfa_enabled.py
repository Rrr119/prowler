from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_custom_root_mfa_enabled(Check):
    """The AWS account root user has MFA enabled."""

    def execute(self):
        findings = []
        if not iam_client.credential_report:
            return findings

        for user in iam_client.credential_report:
            if user.get("user") != "<root_account>":
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=user)
            report.resource_id = user["user"]
            report.resource_arn = user.get("arn", "")
            report.region = iam_client.region
            if user.get("mfa_active") == "true":
                report.status = "PASS"
                report.status_extended = "MFA is enabled for the AWS root account."
            else:
                report.status = "FAIL"
                report.status_extended = "MFA is not enabled for the AWS root account."
            findings.append(report)

        return findings
