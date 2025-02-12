# Copyright (c) 2019 Martin Lafaix (martin.lafaix@external.engie.com)
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0
"""GitHubCloud.

A class wrapping the GitHub Cloud APIs.

This module depends ont the **requests** public library. It also depends
on three **zabel-commons** modules, #::zabel.commons.exceptions,
#::zabel.commons.sessions, and #::zabel.commons.utils.
"""


from typing import Dict, List, Optional, Mapping, Union, Any

import requests

from zabel.commons.exceptions import ApiError
from zabel.commons.sessions import prepare_session
from zabel.commons.utils import (
    api_call,
    ensure_instance,
    ensure_nonemptystring,
    ensure_in,
    add_if_specified,
    BearerAuth,
    join_url,
)


class GitHubCloud:
    """GitHubCloud Low-Level Wrapper.

    There can be as many GitHub instances as needed.

    A class wrapping the GitHub Cloud APIs.

    This module depends ont the **requests** public library. It also depends
    on three **zabel-commons** modules, #::zabel.commons.exceptions,
    #::zabel.commons.sessions, and #::zabel.commons.utils.

    # Reference URLs

    - <https://docs.github.com/en/enterprise-cloud@latest/rest?apiVersion=2022-11-28>
    - <https://docs.github.com/en/enterprise-cloud@latest/graphql>

    # Sample use

    ```python
    # standard use
    from zabel.elements.clients import GitHubCloud

    url = 'https://api.github.com'
    ghc = GitHubCloud(url, bearer_auth=token)
    ghc.list_organizations('my_enterprise')
    ```
    """

    def __init__(self, url: str, bearer_auth: str):
        """Create a GitHubCloud instance object.

        # Required parameters:

        - url: The URL of the GitHub Cloud instance
        - bearer_auth: The bearer token to authenticate the user
        """
        ensure_nonemptystring('url')
        ensure_nonemptystring('bearer_auth')

        self.url = url
        self.auth = BearerAuth(bearer_auth)
        self.session = prepare_session(self.auth)

    def __str__(self) -> str:
        return f'{self.__class__.__name__}: {self.url}'

    def __repr__(self) -> str:
        url, auth = self.url, self.auth[0]
        return f'<{self.__class__.__name__}: {url!r}, {auth!r}>'

    ####################################################################
    # GitHubCloud organizations
    #
    # list_organizations
    # create_organization
    # get_organization
    # list_organization_repositories
    # list_organization_members
    # add_organization_membership
    # remove_organization_membership

    @api_call
    def list_organizations(self, enterprise_name: str) -> List[Dict[str, Any]]:
        """List the organizations in an enterprise.

        # Required parameters:

        - enterprise_name: a string

        # Return value:

        - a list of organizations
        """

        ensure_nonemptystring('enterprise_name')

        query = """
        query($enterprise: String!) {
            enterprise(slug: $enterprise) {
                organizations(first: 100) {
                    nodes {
                        login
                        id
                        name
                        url
                        archivedAt
                        createdAt
                        updatedAt
                        description
                    }
                }
            }
        }
        """
        result = self._post(
            'graphql',
            json={
                "query": query,
                "variables": {"enterprise": enterprise_name},
            },
        ).json()

        return (
            result.get('data')
            .get('enterprise')
            .get('organizations')
            .get('nodes', [])
        )

    @api_call
    def create_organization(
        self,
        organization_name: str,
        enterprise_id: str,
        admins: List[str],
        billing_email: str,
        profile_name: Optional[str] = '',
    ):
        """Create an organization in an enterprise.

        # Required parameters:

        - organization_name: a non-empty string
        - enterprise_id: a non-empty string
        - admins: a list of strings
        - billing_email: a non-empty string

        # Optional parameters:

        - profile_name: a string

        # Returned value

        An _organization_. An organization is a dictionary.

        """

        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('enterprise_id')
        ensure_instance('admins', list)
        ensure_nonemptystring('billing_email')
        ensure_instance('profile_name', str)

        query = '''
        mutation($organization:CreateEnterpriseOrganizationInput!) {
            createEnterpriseOrganization(input:$organization) {
                    organization {
                        id
                        login
                        url
                        name
                        description
                }
            }
        }'''
        organization = {
            'adminLogins': admins,
            'billingEmail': billing_email,
            'enterpriseId': enterprise_id,
            'login': organization_name,
        }

        add_if_specified(organization, 'profileName', profile_name)
        return self._post(
            'graphql',
            json={'query': query, 'variables': {'organization': organization}},
        ).json()

    @api_call
    def get_organization(self, organization_name: str) -> Dict[str, Any]:
        """Return extended information on organization.

        # Required parameters

        - organization_name: a non-empty string

        # Returned value

        A dictionary with the following keys:

        - login
        - id
        - node_id
        - url
        - repos_url
        - events_url
        - hooks_url
        - issues_url
        - members_url
        - public_members_url
        - avatar_url
        - description
        - name
        - company
        - blog
        - location
        - email
        - twitter_username
        - is_verified
        - has_organization_projects
        - has_repository_projects
        - public_repos
        - public_gists
        - followers
        - following
        - html_url
        - created_at
        - type
        - total_private_repos
        - owned_private_repos
        - private_gists
        - disk_usage
        - collaborators
        - billing_email
        - plan
        - default_repository_permission
        - members_can_create_repositories
        - two_factor_requirement_enabled
        - members_allowed_repository_creation_type
        - members_can_create_public_repositories
        - members_can_create_private_repositories
        - members_can_create_internal_repositories
        - members_can_create_pages
        - members_can_create_public_pages
        - members_can_create_private_pages
        - members_can_fork_private_repositories
        - web_commit_signoff_required
        - updated_at
        - archived_at
        - deploy_keys_enabled_for_repositories
        - dependency_graph_enabled_for_new_repositories
        - dependabot_alerts_enabled_for_new_repositories
        - dependabot_security_updates_enabled_for_new_repositories
        - advanced_security_enabled_for_new_repositories
        - secret_scanning_enabled_for_new_repositories
        - secret_scanning_push_protection_enabled_for_new_repositories
        - secret_scanning_push_protection_custom_link
        - secret_scanning_push_protection_custom_link_enabled
        - secret_scanning_validity_checks_enabled_for_new_repositories
        """
        ensure_nonemptystring('organization_name')

        return self._get(f'orgs/{organization_name}')  # type: ignore

    @api_call
    def list_organization_repositories(
        self, organization: str
    ) -> List[Dict[str, Any]]:
        """List the repositories in an organization.

        # Required parameters:

        - organization: a non-empty string

        # Returned value:

        - a list of repositories
        """
        ensure_nonemptystring('organization')

        return self._collect_data(f'orgs/{organization}/repos')

    @api_call
    def list_organization_members(
        self, organization: str, role='all'
    ) -> List[Dict[str, Any]]:
        """List the members of an organization.

        # Required parameters:

        - organization: a non-empty string

        # Optional parameters

        - role: a non-empty string, one of 'all', 'member', or 'admin'
          ('all' by default)

        # Returned value:

        - a list of members
        """
        ensure_nonemptystring('organization')
        ensure_in('role', ('all', 'member', 'admin'))
        return self._collect_data(
            f'orgs/{organization}/members', params={'role': role}
        )

    @api_call
    def add_organization_membership(
        self,
        organization: str,
        username: str,
        role: Optional[str] = 'member',
    ):
        """Add a user to an organization.

        # Required parameters:

        - organization: a non-empty string
        - username: a non-empty string

        # Optional parameters:

        - role: a string, either 'member' or 'admin'

        """
        ensure_nonemptystring('organization')
        ensure_nonemptystring('username')
        ensure_in('role', ['member', 'admin'])

        return self._put(
            f'orgs/{organization}/memberships/{username}',
            json={'role': role},
        )

    @api_call
    def rm_organization_membership(
        self,
        organization: str,
        username: str,
    ):
        """Remove a user from an organization.

        # Required parameters:

        - organization: a non-empty string
        - username: a non-empty string

        """
        ensure_nonemptystring('organization')
        ensure_nonemptystring('username')

        result = self._delete(f'orgs/{organization}/memberships/{username}')
        return (result.status_code // 100) == 2


    ####################################################################
    # GitHub secrets
    #
    # list_organization_secrets
    # get_organization_public_key
    # get_organization_secret
    # delete_organization_secret

    @api_call
    def list_organization_secrets(
        self, organization_name: str
    ) -> Dict[str, Any]:
        """Return the organization's secrets.

        # Required parameters

        - organization_name: a non-empty string

        # Returned value

        A dictionary with the following entries:

        - total_count: an integer
        - secrets: a list of dictionaries

        Each secret is a dictionary with the following entries:

        - name: a string
        - created_at: a string
        - updated_at: a string
        - visibility: a string
        - selected_repositories_url: a string
        """
        ensure_nonemptystring('organization_name')

        api_url = join_url(
            self.url, f'orgs/{organization_name}/actions/secrets'
        )
        org_secrets = {'total_count': 0, 'secrets': []}
        while True:
            response = self.session().get(api_url)
            if response.status_code // 100 != 2:
                raise ApiError(response.text)
            try:
                response_data = response.json()
                org_secrets['total_count'] = response_data['total_count']
                org_secrets['secrets'] += response_data['secrets']
            except Exception as exception:
                raise ApiError(exception)
            if 'next' in response.links:
                api_url = response.links['next']['url']
            else:
                break

        return org_secrets

    @api_call
    def get_organization_public_key(
        self, organization_name: str
    ) -> Dict[str, Any]:
        """Return the organization's public key.

        # Required parameters

        - organization_name: a non-empty string

        # Returned value

        A dictionary with the following entries:

        - key_id: a string
        - key: a string
        """
        ensure_nonemptystring('organization_name')

        return self._get(
            f'orgs/{organization_name}/actions/secrets/public-key'
        )

    @api_call
    def get_organization_secret(
        self, organization_name: str, secret_name: str
    ) -> Dict[str, Any]:
        """Return the organization's secret.

        # Required parameters

        - organization_name: a non-empty string
        - secret_name: a non-empty string

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

        return self._get(
            f'orgs/{organization_name}/actions/secrets/{secret_name}'
        )

    @api_call
    def delete_organization_secret(
        self, organization_name: str, secret_name: str
    ) -> bool:
        """Delete the organization's secret.

        # Required parameters

        - organization_name: a non-empty string
        - secret_name: a non-empty string

        # Returned value

        A boolean.  True if the secret has been deleted.
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('secret_name')

        return (
            self._delete(
                f'orgs/{organization_name}/actions/secrets/{secret_name}'
            ).status_code
            == 204
        )
    
    ####################################################################
    # GitHubCloud enterprise
    #
    # get_enterprise

    @api_call
    def get_enterprise(self, enterprise_name: str):
        """Returns the enterprise details

        # Required parameters:

        - enterprise_name: a non-empty string

        """
        ensure_nonemptystring('enterprise_name')

        query = """
        query($enterprise: String!) {
            enterprise(slug: $enterprise) {
                id
                name
                description
                url
                slug
                billingEmail
                createdAt
            }
        }"""
        result = self._post(
            'graphql',
            json={
                "query": query,
                "variables": {"enterprise": enterprise_name},
            },
        )
        return result['data']['enterprise']

    ####################################################################
    # GitHub helpers
    #
    # All helpers are api_call-compatibles (i.e., they can be used as
    # a return value)

    def _get(
        self,
        api: str,
        params: Optional[Mapping[str, Union[str, List[str], None]]] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> requests.Response:
        """Return GitHub API call results, as Response."""
        api_url = join_url(self.url, api)
        print(api_url)
        return self.session().get(api_url, headers=headers, params=params)

    def _post(
        self,
        api: str,
        json: Optional[Mapping[str, Any]] = None,
        params: Optional[Mapping[str, Union[str, List[str], None]]] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> requests.Response:
        api_url = join_url(self.url, api)
        return self.session().post(
            api_url, json=json, params=params, headers=headers
        )

    def _put(
        self,
        api: str,
        json: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> requests.Response:
        api_url = join_url(self.url, api)
        return self.session().put(api_url, json=json, headers=headers)

    def _delete(
        self,
        api: str,
        json: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> requests.Response:
        api_url = join_url(self.url, api)
        return self.session().delete(api_url, json=json, headers=headers)

    def _collect_data(
        self,
        api: str,
        params: Optional[Mapping[str, Union[str, List[str], None]]] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> List[Dict[str, Any]]:
        """Return GitHub API call results, collected.

        The API call is expected to return a list of items. If not,
        an _ApiError_ exception is raised.
        """
        api_url = join_url(self.url, api)
        collected: List[Dict[str, Any]] = []
        while True:
            response = self.session().get(
                api_url, params=params, headers=headers
            )
            if response.status_code // 100 != 2:
                raise ApiError(response.text)
            try:
                collected += response.json()
            except Exception as exception:
                raise ApiError(exception)
            if 'next' in response.links:
                api_url = response.links['next']['url']
            else:
                break

        return collected
