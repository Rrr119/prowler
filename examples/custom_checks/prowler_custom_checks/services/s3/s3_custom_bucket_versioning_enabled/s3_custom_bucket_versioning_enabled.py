from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.s3.s3_client import s3_client


class s3_custom_bucket_versioning_enabled(Check):
    """S3 buckets have object versioning enabled."""

    def execute(self):
        findings = []
        for bucket in s3_client.buckets.values():
            if not bucket.versioning_retrieved:
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=bucket)
            if bucket.versioning:
                report.status = "PASS"
                report.status_extended = (
                    f"S3 bucket {bucket.name} has versioning enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"S3 bucket {bucket.name} does not have versioning enabled."
                )
            findings.append(report)

        return findings
