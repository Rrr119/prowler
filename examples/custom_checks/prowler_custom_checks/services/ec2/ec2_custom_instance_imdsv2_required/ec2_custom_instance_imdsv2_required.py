from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_custom_instance_imdsv2_required(Check):
    """EC2 instances require IMDSv2 or disable the metadata service."""

    def execute(self):
        findings = []
        for instance in ec2_client.instances:
            if instance.state == "terminated":
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=instance)
            if instance.http_endpoint == "disabled" or (
                instance.http_endpoint == "enabled"
                and instance.http_tokens == "required"
            ):
                report.status = "PASS"
                report.status_extended = (
                    f"EC2 instance {instance.id} requires IMDSv2 or disables "
                    "the instance metadata service."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"EC2 instance {instance.id} permits IMDSv1."
            findings.append(report)

        return findings
