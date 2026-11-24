# Prowler Custom Checks Example

This package is a minimal, installable Prowler check plug-in. It adds three
AWS checks and a custom compliance framework without modifying the Prowler
source tree.

## Package Layout

```text
prowler_custom_checks/
├── services/
│   ├── ec2/ec2_custom_instance_imdsv2_required/
│   ├── iam/iam_custom_root_mfa_enabled/
│   └── s3/s3_custom_bucket_versioning_enabled/
└── compliance/aws/custom_cloud_security_baseline_aws.json
```

Each check follows the built-in contract:

- The class, module and check ID share the same name.
- `ServiceName` matches the first segment of the check ID.
- A `<check_id>.metadata.json` file sits next to the module.
- The check returns the provider-specific `Check_Report_AWS` findings.

## Install And Run

From this directory:

```bash
pip install -e .
prowler aws --compliance-file \
  prowler_custom_checks/compliance/aws/custom_cloud_security_baseline_aws.json
```

Or install the package and select the framework through the entry point:

```bash
prowler aws --compliance custom_cloud_security_baseline_aws
```

The checks emit the standard Prowler findings, so CSV, JSON-OCSF, ASFF, HTML,
SARIF and compliance outputs work without any custom formatter.
