# AWS IAM connector using boto3.
#
# Only touches users under the /accessflow/ path, so anything created some
# other way (terraform users etc.) is ignored.
#
# IAM doesn't have a "disabled" flag, so to disable someone I:
#   - delete their console password (login profile)
#   - deactivate their access keys
#   - tag them accessflow:status=disabled
from __future__ import annotations

import boto3
from botocore.exceptions import ClientError

from ..models import Account, Employee
from .base import Connector

MANAGED_PATH = "/accessflow/"
STATUS_TAG = "accessflow:status"


class AwsIamConnector(Connector):
    name = "aws_iam"

    def __init__(self, client=None, session: boto3.Session | None = None):
        self.iam = client or (session or boto3.Session()).client("iam")

    def list_accounts(self) -> dict[str, Account]:
        accounts: dict[str, Account] = {}
        for page in self.iam.get_paginator("list_users").paginate(PathPrefix=MANAGED_PATH):
            for user in page["Users"]:
                name = user["UserName"]
                tags = {t["Key"]: t["Value"] for t in
                        self.iam.list_user_tags(UserName=name).get("Tags", [])}
                groups = set()
                for gpage in self.iam.get_paginator("list_groups_for_user").paginate(UserName=name):
                    groups.update(g["GroupName"] for g in gpage["Groups"])
                accounts[name] = Account(
                    username=name,
                    groups=groups,
                    enabled=tags.get(STATUS_TAG, "active") != "disabled",
                    managed=True,
                )
        return accounts

    def create_account(self, employee: Employee) -> None:
        self.iam.create_user(
            Path=MANAGED_PATH,
            UserName=employee.username,
            Tags=[
                {"Key": "accessflow:employee_id", "Value": employee.employee_id},
                {"Key": "accessflow:email", "Value": employee.email},
                {"Key": "accessflow:department", "Value": employee.department},
                {"Key": STATUS_TAG, "Value": "active"},
            ],
        )

    def enable_account(self, username: str) -> None:
        # just flips the tag back. they need new credentials through normal onboarding
        self.iam.tag_user(UserName=username, Tags=[{"Key": STATUS_TAG, "Value": "active"}])

    def disable_account(self, username: str) -> None:
        try:
            self.iam.delete_login_profile(UserName=username)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        for key in self.iam.list_access_keys(UserName=username)["AccessKeyMetadata"]:
            self.iam.update_access_key(
                UserName=username, AccessKeyId=key["AccessKeyId"], Status="Inactive"
            )
        self.iam.tag_user(UserName=username, Tags=[{"Key": STATUS_TAG, "Value": "disabled"}])

    def add_to_group(self, username: str, group: str) -> None:
        self.iam.add_user_to_group(GroupName=group, UserName=username)

    def remove_from_group(self, username: str, group: str) -> None:
        self.iam.remove_user_from_group(GroupName=group, UserName=username)
