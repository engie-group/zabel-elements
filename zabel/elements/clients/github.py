# Copyright (c) 2019 Martin Lafaix (martin.lafaix@external.engie.com)
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

"""GitHub.

A class wrapping GitHub APIs.

There can be as many GitHub instances as needed.

This module depends on the #::.base.github module.
"""

from typing import Any, Dict, List, Optional

import csv
import time

from base64 import b64decode, b64encode
from nacl import public, encoding

from zabel.commons.exceptions import ApiError
from zabel.commons.utils import (
    api_call,
    ensure_in,
    ensure_instance,
    ensure_nonemptystring,
    ensure_noneorinstance,
    ensure_noneornonemptystring,
    join_url,
)

from .base.github import GitHub as Base


MAX_ATTEMPTS = 3


class GitHub(Base):
    """GitHub Low-Level Wrapper.

    There can be as many GitHub instances as needed.

    This class depends on the public **requests** library.  It also
    depends on three **zabel-commons** modules,
    #::zabel.commons.exceptions, #::zabel.commons.sessions,
    and #::zabel.commons.utils.

    # Reference URLs

    - <https://developer.github.com/v3/>
    - <https://docs.github.com/en/enterprise-server@3.10/rest/orgs/orgs>
    - <https://stackoverflow.com/questions/10625190>

    # Implemented features

    - users
    - organizations
    - repositories
    - branches
    - pullrequests
    - references
    - hooks
    - copilot
    - misc. operations (version, staff reports & stats)

    Some methods require an Enterprise Cloud account.

    # Sample use

    ```python
    # standard use
    from zabel.elements.clients import GitHub

    url = 'https://github.example.com/api/v3/'
    gh = GitHub(url, basic_auth=(user, token))
    gh.list_users()

    # enabling management features
    from zabel.elements import clients

    mngt = 'https://github.example.com/'
    gh = clients.GitHub(url, bearer_auth=token, management_url=mngt)
    gh.create_organization('my_organization', 'admin')
    ```
    """

    ####################################################################
    # GitHub misc. operations
    #
    # get_staff_report

    @api_call
    def get_staff_report(self, report: str) -> List[List[str]]:
        """Return staff report.

        # Required parameters

        - report: a non-empty string

        # Returned value

        A list of lists, one entry per line in the report. All items in
        the sub-lists are strings.
        """
        ensure_nonemptystring('report')
        if self.management_url is None:
            raise ApiError('Management URL is not defined')

        while True:
            rep = self.session().get(join_url(self.management_url, report))
            if rep.status_code == 202:
                print('Sleeping...')
                time.sleep(5)
            else:
                break

        what = list(csv.reader(rep.text.split('\n')[1:], delimiter=','))
        if not what[-1]:
            what = what[:-1]
        return what

    ####################################################################
    # GitHub branch
    #
    # create_branch_from_default
    # delete_branch

    @api_call
    def create_branch_from_default(
        self, organization_name: str, repository_name: str, branch: str
    ) -> Dict[str, Any]:
        """Create a branch from the head of the default branch.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string
        - branch: a non-empty string

        # Returned value

        A _reference_.  A reference is a dictionary with the following
        entries:

        - ref: a string
        - node_id: a string
        - url: a string
        - object: a dictionary

        The `object` dictionary has the following entries:

        - type: a string
        - sha: a string
        - url: a string
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')
        ensure_nonemptystring('branch')

        repo = self.get_repository(organization_name, repository_name)
        default = self.get_repository_reference(
            organization_name,
            repository_name,
            f'heads/{repo["default_branch"]}',
        )
        result = self.create_repository_reference(
            organization_name,
            repository_name,
            f'refs/heads/{branch}',
            default['object']['sha'],
        )
        return result

    @api_call
    def delete_branch(
        self, organization_name: str, repository_name: str, branch: str
    ) -> None:
        """Delete a branch.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string
        - branch: a non-empty string

        # Returned value

        No content.
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')
        ensure_nonemptystring('branch')

        return self.delete_repository_reference(
            organization_name, repository_name, f'refs/heads/{branch}'
        )

    ####################################################################
    # GitHub repository contents
    #
    # get_repository_textfile
    # create_repository_textfile
    # update_repository_textfile

    def get_repository_textfile(
        self,
        organization_name: str,
        repository_name: str,
        path: str,
        ref: Optional[str] = None,
    ) -> Any:
        """Return the text file content.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string
        - path: a string

        # Optional parameters

        - ref: a non-empty string or None (None by default)

        # Returned value

        A dictionary with the following entries:

        - name: a string
        - path: a string
        - sha: a string
        - size: an integer
        - content: a string
        - url, html_url, git_url, download_url: strings
        - _links: a dictionary
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')
        ensure_instance('path', str)
        ensure_noneornonemptystring('ref')

        result = self.get_repository_content(
            organization_name, repository_name, path, ref
        )
        if result.get('encoding') != 'base64':
            raise ApiError('Content not in base64')
        if result.get('type') != 'file':
            raise ApiError('Content is not a file')
        result['content'] = str(b64decode(result['content']), 'utf-8')
        del result['encoding']
        return result

    def create_repository_textfile(
        self,
        organization_name: str,
        repository_name: str,
        path: str,
        message: str,
        content: str,
        branch: Optional[str] = None,
        committer: Optional[Dict[str, str]] = None,
        author: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Create a new repository text file.

        The created text file must not already exist.  `content` is
        expected to be an utf-8-encoded string.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string
        - path: a string
        - message: a string
        - content: a string

        # Optional parameters

        - branch: a string or None (None by default)
        - committer: a dictionary or None (None by default)
        - author: a dictionary or None (None by default)

        # Returned value

        A dictionary.
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')
        ensure_instance('path', str)
        ensure_instance('message', str)
        ensure_instance('content', str)
        ensure_noneornonemptystring('branch')
        ensure_noneorinstance('committer', dict)
        ensure_noneorinstance('author', dict)

        return self.create_repository_file(
            organization_name,
            repository_name,
            path,
            message,
            str(b64encode(bytes(content, encoding='utf-8')), 'utf-8'),
            branch,
            committer,
            author,
        )

    def update_repository_textfile(
        self,
        organization_name: str,
        repository_name: str,
        path: str,
        message: str,
        content: str,
        sha: Optional[str] = None,
        branch: Optional[str] = None,
        committer: Optional[Dict[str, str]] = None,
        author: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Update a repository text file.

        The file must already exist on the repository.  `content` is
        expected to be an utf-8-encoded string.

        You must specify at least `sha` or `branch` (you can specify
        both).

        If `sha` is not specified, the sha is retrieved from the
        `branch` branch, and up to `MAX_ATTMEPTS` attempts are made to
        update the file, in case the branch is updated between the
        retrieval of the sha and the update of the file.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string
        - path: a string
        - message: a string
        - content: a string

        # Optional parameters

        - sha: a non-empty string or None (None by default)
        - branch: a string or None (None by default)
        - committer: a dictionary or None (None by default)
        - author: a dictionary or None (None by default)

        # Returned value

        A dictionary.
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')
        ensure_instance('path', str)
        ensure_instance('message', str)
        ensure_instance('content', str)
        ensure_noneornonemptystring('sha')
        ensure_noneornonemptystring('branch')
        ensure_noneorinstance('committer', dict)
        ensure_noneorinstance('author', dict)
        if sha is None and branch is None:
            raise ValueError('You must specify at least one of: sha, branch.')

        attempts = 0
        content = str(b64encode(bytes(content, encoding='utf-8')), 'utf-8')
        while True:
            if sha is None:
                file: Dict[str, str] = self.get_repository_content(
                    organization_name,
                    repository_name,
                    path,
                    ref=f'refs/heads/{branch}',
                )
                effective_sha = file['sha']
            else:
                effective_sha = sha

            try:
                result = self.update_repository_file(
                    organization_name,
                    repository_name,
                    path,
                    message,
                    content,
                    effective_sha,
                    branch,
                    committer,
                    author,
                )
                return result  # type: ignore
            except ApiError:
                if sha is None and attempts < MAX_ATTEMPTS:
                    attempts += 1
                    continue
                raise

    ####################################################################
    # GitHub license (Enterprise cloud)
    #
    # list_consumed_licenses_users

    @api_call
    def list_consumed_licenses_users(
        self, enterprise_name: str
    ) -> List[Dict[str, Any]]:
        """Return consumed licenses.

        # Required parameters

        - enterprise_name: a non-empty string

        # Returned value

        A list of dictionaries, one per user.  Each dictionary has the
        following entries:

        - github_com_login: a string
        - github_com_name: a string
        - enterprise_server_user_ids: a list of strings
        - github_com_user: a boolean
        - enterprise_server_user: a boolean
        - visual_studio_subscription_user: a boolean
        - license_type: a string
        - github_com_profile: a string
        - github_com_member_roles: a list of strings
        - github_com_enterprise_roles: a list of strings
        - github_com_verified_domain_emails: a list of strings
        - github_com_saml_name_id: a string
        - github_com_orgs_with_pending_invites: a list of strings
        - github_com_two_factor_auth: a boolean
        - github_com_two_factor_auth_required_by_date: a datetime as a
          string
        - enterprise_server_primary_emails: a list of stringsF
        - visual_studio_license_status: a string
        - visual_studio_subscription_email: a string
        - total_user_accounts: an integer
        """
        api_url = join_url(
            self.url, f'enterprises/{enterprise_name}/consumed-licenses'
        )
        collected: List[Dict[str, Any]] = []
        while True:
            response = self.session().get(api_url)
            if response.status_code // 100 != 2:
                raise ApiError(response.text)
            try:
                data = response.json()
                collected += data['users']
            except Exception as exception:
                raise ApiError(exception)
            if 'next' in response.links:
                api_url = response.links['next']['url']
            else:
                break

        return collected

    ####################################################################
    # GitHub organization secret
    #
    # create_or_update_organization_secret

    @api_call
    def create_or_update_organization_secret(
        self,
        organization_name: str,
        secret_name: str,
        secret_value: str,
        visibility: str = 'all',
        repositories_ids: Optional[List[int]] = None,
    ) -> bool:
        """Create or update the organization's secret.

        # Required parameters

        - organization_name: a non-empty string
        - secret_name: a non-empty string
        - secret_value: a non-empty string

        # Optional parameters

        - visibility: a string, one of 'all', 'private', or 'selected' ('all' by default)

        # Returned value

        A dictionary with the following entries:

        - name: a string
        - created_at: a string
        - updated_at: a string
        - visibility: a string
        - selected_repositories_url: a string
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('secret_name')
        ensure_nonemptystring('secret_value')
        ensure_in('visibility', ('all', 'private', 'selected'))

        orga_key = self.get_organization_public_key(organization_name)

        public_key_bytes = b64decode(orga_key['key'])

        public_key_obj = public.PublicKey(public_key_bytes)
        sealed_box = public.SealedBox(public_key_obj)
        encrypted_value = sealed_box.encrypt(secret_value.encode())
        encrypted_value_base64 = b64encode(encrypted_value).decode()

        data = {
            'encrypted_value': encrypted_value_base64,
            'key_id': orga_key['key_id'],
            'visibility': visibility,
        }

        if visibility == 'selected':
            data['selected_repository_ids'] = repositories_ids

        response = self._put(
            f'orgs/{organization_name}/actions/secrets/{secret_name}',
            json=data,
        )

        if response.status_code in [201, 204]:
            return True
