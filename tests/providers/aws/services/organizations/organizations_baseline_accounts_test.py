import threading
import time
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

from prowler.providers.aws.services.organizations.organizations_service import (
    OrganizationAccount,
    Organizations,
)


def _account(account_id: str) -> OrganizationAccount:
    return OrganizationAccount(
        id=account_id,
        arn=f"arn:aws:organizations::123456789012:account/o-abcde12345/{account_id}",
        name=f"account-{account_id}",
        email=f"{account_id}@example.com",
        status="ACTIVE",
        joined_method="CREATED",
    )


class TestOrganizationsBaselineAccounts:
    def test_get_account_baseline_scps_includes_inherited_policies(self):
        service = object.__new__(Organizations)
        service.region = "us-east-1"
        service.client = mock.MagicMock()
        service.client.list_parents.side_effect = [
            {"Parents": [{"Id": "ou-abcd-12345678", "Type": "ORGANIZATIONAL_UNIT"}]},
            {"Parents": [{"Id": "r-abcd", "Type": "ROOT"}]},
            {"Parents": []},
        ]

        policies_paginator = mock.MagicMock()

        def paginate(TargetId, **_kwargs):
            policies = {
                "111111111111": [{"Id": "p-FullAWSAccess", "Name": "FullAWSAccess"}],
                "ou-abcd-12345678": [{"Id": "p-baseline", "Name": "Baseline"}],
                "r-abcd": [{"Id": "p-root", "Name": "RootGuardrail"}],
            }
            return [{"Policies": policies[TargetId]}]

        policies_paginator.paginate.side_effect = paginate
        service.client.get_paginator.return_value = policies_paginator

        result = service._get_account_baseline_scps(_account("111111111111"))

        assert result == ["Baseline", "RootGuardrail"]

    def test_get_account_baseline_scps_filters_full_access(self):
        service = object.__new__(Organizations)
        service.region = "us-east-1"
        service.client = mock.MagicMock()
        service.client.list_parents.return_value = {"Parents": []}
        policies_paginator = mock.MagicMock()
        policies_paginator.paginate.return_value = [
            {"Policies": [{"Id": "p-FullAWSAccess", "Name": "FullAWSAccess"}]}
        ]
        service.client.get_paginator.return_value = policies_paginator

        assert service._get_account_baseline_scps(_account("111111111111")) == []

    def test_get_account_baseline_scps_unreadable_returns_none(self):
        service = object.__new__(Organizations)
        service.region = "us-east-1"
        service.client = mock.MagicMock()
        service.client.list_parents.side_effect = RuntimeError("denied")

        assert service._get_account_baseline_scps(_account("111111111111")) is None

    def test_populates_100_accounts_concurrently(self):
        service = object.__new__(Organizations)
        service.region = "us-east-1"
        service.accounts = [_account(f"{index:012d}") for index in range(100)]
        service.thread_pool = ThreadPoolExecutor(max_workers=10)

        active_calls = 0
        max_active_calls = 0
        lock = threading.Lock()

        def resolve_account(account):
            nonlocal active_calls, max_active_calls
            with lock:
                active_calls += 1
                max_active_calls = max(max_active_calls, active_calls)
            time.sleep(0.01)
            with lock:
                active_calls -= 1
            return ["Baseline"]

        try:
            with mock.patch.object(
                service,
                "_get_account_baseline_scps",
                side_effect=resolve_account,
            ):
                service._populate_accounts_baseline_scps()
        finally:
            service.thread_pool.shutdown()

        assert max_active_calls > 1
        assert len(service.accounts) == 100
        assert all(
            account.baseline_scps == ["Baseline"] for account in service.accounts
        )
