# Copyright (c) 2024 Martin Lafaix (martin.lafaix@external.engie.com)
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

from typing import Any, Dict, List, Mapping, Optional, Union

import requests

from zabel.commons.exceptions import ApiError
from zabel.commons.sessions import prepare_session
from zabel.commons.utils import (
    api_call,
    ensure_instance,
    ensure_nonemptystring,
    ensure_noneorinstance,
    ensure_in,
    add_if_specified,
    BearerAuth,
    join_url,
)


class GitHubCloud:
    """GitHubCloud Low-Level Wrapper.

    A class wrapping the GitHub Cloud APIs.

    There can be as many GitHub Cloud instances as needed.

    This module depends on the **requests** public library. It also
    depends on three **zabel-commons** modules,
    #::zabel.commons.exceptions, #::zabel.commons.sessions, and
    #::zabel.commons.utils.

    ## Reference URLs

    - <https://docs.github.com/en/enterprise-cloud@latest/rest?apiVersion=2022-11-28>
    - <https://docs.github.com/en/enterprise-cloud@latest/graphql>

    ## Examples

    ```python
    # standard use
    from zabel.elements.clients import GitHubCloud

    url = 'https://api.github.com'
    token = '...'
    ghc = GitHubCloud(url, bearer_auth=token)
    ghc.list_organizations('my_enterprise')
    ```
    """

    def __init__(self, url: str, bearer_auth: str) -> None:
        """Create a GitHub Cloud instance object.

        # Required parameters

        - url: The URL of the GitHub Cloud instance
        - bearer_auth: The bearer token to authenticate the user

        # Usage

        `url` must be a non-empty string representing the URL of the
        GitHub Cloud instance.  For example, if you are using the public
        `github.com` instance:

            'https://api.github.com'
        """
        ensure_nonemptystring('url')
        ensure_nonemptystring('bearer_auth')

        self.url = url
        self.auth = BearerAuth(bearer_auth)
        self.session = prepare_session(self.auth)

    def __str__(self) -> str:
        return f'{self.__class__.__name__}: {self.url}'

    def __repr__(self) -> str:
        url, auth = self.url, self.auth
        return f'<{self.__class__.__name__}: {url!r}, {auth!r}>'

    ####################################################################
    # GitHub users (that or organization members?)
    #
    # list_users
    # get_user

    @api_call
    def list_users(self) -> List[Dict[str, Any]]:
        """Return the list of users.

        This API returns users, bots and organizations.  Use the `type`
        entry in the returned items to distinguish (`'User'` or
        `'Organization'` or `'Bot'`).

        # Returned value

        A list of _users_.  A user is a dictionary with the following
        entries:

        - login: a string
        - id: an integer
        - node_id: a string
        - avatar_url: a string
        - gravatar_id: a string
        - url: a string
        - html_url: a string
        - followers_url: a string
        - following_url: a string
        - gist_url: a string
        - starred_url: a string
        - subscription_url: a string
        - organizations_url: a string
        - repos_url: a string
        - events_url: a string
        - received_events_url: a string
        - type: a string
        - user_view_type: a string
        - site_admin: a boolean
        """
        return self._collect_data('users')

    @api_call
    def get_user(self, user_name: str) -> Dict[str, Any]:
        """Return the user details.

        # Required parameters

        - user_name: a non-empty string

        # Returned value

        A dictionary with the following entries:

        - avatar_url: a string
        - bio:
        - blog:
        - company:
        - created_at: a string (a timestamp)
        - email:
        - events_url: a string
        - followers: an integer
        - followers_url: a string
        - following: an integer
        - following_url: a string
        - gist_url: a string
        - gravatar_id: a string
        - hireable:
        - html_url: a string
        - id: an integer
        - location:
        - login: a string
        - name:
        - node_id: a string
        - organizations_url: a string
        - public_gists: an integer
        - public_repos: an integer
        - received_events_url: a string
        - repos_url: a string
        - site_admin: a boolean
        - starred_url: a string
        - subscription_url: a string
        - twitter_username: a string
        - type: a string
        - updated_at:
        - url: a string
        - user_view_type: a string
        """
        ensure_nonemptystring('user_name')

        return self._get(f'users/{user_name}')  # type: ignore

    ####################################################################
    # GitHubCloud organizations
    #
    # list_organizations
    # create_organization
    # get_organization
    # get_organization_membership
    # list_organization_repositories
    # list_organization_members
    # add_organization_membership
    # remove_organization_membership
    # add_organization_outsidecollaborator
    # remove_organization_outsidecollaborator
    # list_organization_saml_identities
    # list_organization_invitations

    @api_call
    def list_organizations(self, enterprise_name: str) -> List[Dict[str, Any]]:
        """List the organizations in an enterprise.

        # Required parameters

        - enterprise_name: a string

        # Returned value

        A list of _organizations_.
        """
        ensure_nonemptystring('enterprise_name')

        query = '''
        query($enterprise: String!, $after: String) {
            enterprise(slug: $enterprise) {
                organizations(first: 100, after: $after) {
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
                    pageInfo {
                        endCursor
                        hasNextPage
                    }
                }
            }
        }
        '''

        after = None
        collected = []
        more = True

        while more:
            result = self.post_graphql_query(
                query,
                {
                    "enterprise": enterprise_name,
                    'after': after,
                },
            )
            organizations = result['data']['enterprise']['organizations']
            collected += organizations['nodes']
            page_info = self._get_page_info(organizations)
            more = page_info['hasNextPage']
            after = page_info['endCursor']

        return collected

    @api_call
    def create_organization(
        self,
        organization_name: str,
        enterprise_id: str,
        admins: List[str],
        billing_email: str,
        profile_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create an organization in an enterprise.

        # Required parameters

        - organization_name: a non-empty string
        - enterprise_id: a non-empty string
        - admins: a list of strings
        - billing_email: a non-empty string

        # Optional parameters

        - profile_name: a string or None (None by default)

        # Returned value

        An _organization_. An organization is a dictionary.
        """

        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('enterprise_id')
        ensure_instance('admins', list)
        ensure_nonemptystring('billing_email')
        ensure_noneorinstance('profile_name', str)

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
        return self.post_graphql_query(query, {'organization': organization})

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
    def get_organization_membership(
        self, organization_name: str, user: str
    ) -> Dict[str, Any]:
        """Get organization membership.

        # Required parameters

        - organization_name: a non-empty string
        - user: a non-empty string

        # Returned value

        A dictionary with the following entries:

        - url: a string
        - state: a string
        - role: a string
        - organization_url: a string
        - organization: a dictionary
        - user: a dictionary

        `role` is either `'admin'` or `'member'`.  `state` is either
        `'active'` or `'pending'`.

        # Raised exceptions

        Raises an _ApiError_ if the caller is not a member of the
        organization.
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('user')

        return self._get(f'orgs/{organization_name}/memberships/{user}')

    @api_call
    def list_organization_repositories(
        self, organization_name: str
    ) -> List[Dict[str, Any]]:
        """List the repositories in an organization.

        # Required parameters

        - organization_name: a non-empty string

        # Returned value

        A list of _repositories_.
        """
        ensure_nonemptystring('organization_name')

        return self._collect_data(f'orgs/{organization_name}/repos')

    @api_call
    def list_organization_members(
        self, organization_name: str, role: str = 'all'
    ) -> List[Dict[str, Any]]:
        """List the members of an organization.

        # Required parameters

        - organization_name: a non-empty string

        # Optional parameters

        - role: a non-empty string, one of `'all'`, `'member'`, or
          `'admin'` (`'all'` by default)

        # Returned value

        A list of _members_.  Members are dictionaries.
        """
        ensure_nonemptystring('organization_name')
        ensure_in('role', ('all', 'member', 'admin'))

        return self._collect_data(
            f'orgs/{organization_name}/members', params={'role': role}
        )

    @api_call
    def list_organization_outsidecollaborators(
        self, organization_name: str
    ) -> List[Dict[str, Any]]:
        """Return the list of organization outside collaborators.

        # Required parameters

        - organization_name: a non-empty string

        # Returned value

        A list of _members_ (outside collaborators).  Each member is a
        dictionary.
        """
        ensure_nonemptystring('organization_name')

        return self._collect_data(
            f'orgs/{organization_name}/outside_collaborators'
        )

    @api_call
    def add_organization_membership(
        self,
        organization_name: str,
        user_name: str,
        role: Optional[str] = 'member',
    ) -> None:
        """Add a user to an organization.

        # Required parameters

        - organization_name: a non-empty string
        - user_name: a non-empty string

        # Optional parameters

        - role: a string, either `'member'` or `'admin'` (`'member'` by
          default)
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('user_name')
        ensure_in('role', ('member', 'admin'))

        return self._put(
            f'orgs/{organization_name}/memberships/{user_name}',
            json={'role': role},
        )

    @api_call
    def remove_organization_membership(
        self, organization_name: str, user_name: str
    ) -> bool:
        """Remove a user from an organization.

        # Required parameters

        - organization_name: a non-empty string
        - user_name: a non-empty string

        # Returned value

        A boolean.  True if the user was removed from the organization.
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('user_name')

        result = self._delete(
            f'orgs/{organization_name}/memberships/{user_name}'
        )
        return (result.status_code // 100) == 2

    rm_organization_membership = remove_organization_membership

    @api_call
    def add_organization_outsidecollaborator(
        self, organization_name: str, user_name: str
    ) -> bool:
        """Add outside collaborator to organization.

        # Required parameters

        - organization_name: a non-empty string
        - user_name: a non-empty string, the login of the user

        # Returned value

        A boolean.  True if the outside collaborator was added to the
        organization.
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('user_name')

        result = self._put(
            f'orgs/{organization_name}/outside_collaborators/{user_name}'
        )
        return (result.status_code // 100) == 2

    @api_call
    def remove_organization_outsidecollaborator(
        self, organization_name: str, user_name: str
    ) -> bool:
        """Remove outside collaborator from organization.

        # Required parameters

        - organization_name: a non-empty string
        - user_name: a non-empty string, the login of the user

        # Returned value

        A boolean.  True if the outside collaborator was removed from
        the organization.
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('user_name')

        result = self._delete(
            f'orgs/{organization_name}/outside_collaborators/{user_name}'
        )
        return (result.status_code // 100) == 2

    @api_call
    def list_organization_saml_identities(
        self, organization_name: str
    ) -> List[Dict[str, Any]]:
        """List the SAML identities of an organization.

        # Required parameters

        - organization_name: a non-empty string

        # Returned value

        A list of _external identities_.  Each external identity is a
        dictionary with the following entries:

        - login: a string
        - name_id: a string
        """
        ensure_nonemptystring('organization_name')

        query = '''
        query($login: String!, $after: String) {
            organization(login: $login) {
                samlIdentityProvider {
                    externalIdentities(first: 100, after: $after) {
                        edges {
                            node {
                                samlIdentity {
                                    nameId
                                }
                                user {
                                    login
                                }
                            }
                        }
                        pageInfo {
                            endCursor
                            hasNextPage
                        }
                    }
                }
            }
        }'''
        after = None
        collected = []
        more = True

        while more:
            result = self.post_graphql_query(
                query, {'login': organization_name, 'after': after}
            )
            external_identities = result['data']['organization'][
                'samlIdentityProvider'
            ]['externalIdentities']
            collected += [
                {
                    'login': (
                        edge['node']['user']['login']
                        if edge['node']['user'] is not None
                        else None
                    ),
                    'name_id': edge['node']['samlIdentity']['nameId'],
                }
                for edge in external_identities['edges']
            ]
            page_info = self._get_page_info(external_identities)
            more = page_info['hasNextPage']
            after = page_info['endCursor']

        return collected

    @api_call
    def list_organization_invitations(
        self, organization_name: str
    ) -> List[Dict[str, Any]]:
        """Return list of pending invitations.

        # Required parameters

        - organization_name: a non-empty string

        # Returned value

        A list of _pending invitations_.  Each pending invitation is a
        dictionary with the following keys:

        - id: an integer
        - login: a string
        - node_id: a string
        - email: a string
        - role: a string
        - created_at: a string
        - failed_at: a string
        - failed_reason: a string
        - inviter: a dictionary
        - team_count: an integer
        - invitation_team_url: a string
        - invitation_source: a dictionary
        """
        ensure_nonemptystring('organization_name')

        return self._collect_data(f'orgs/{organization_name}/invitations')

    ####################################################################
    # GitHubCloud Copilot
    #
    # list_organization_copilot_seats

    @api_call
    def list_organization_copilot_seats(
        self, organization_name: str
    ) -> List[Dict[str, Any]]:
        """Return the list of all Copilot seat assignments for an organization

        # Required parameters

        - organization_name: a non-empty string

        # Returned value

        A list of _seat assignments_.  Each seat assignment is a
        dictionary with the following entries:

        - total_seats: an integer
        - created_at: a string
        - updated_at: a string
        - pending_cancellation_date: a string or null
        - last_activity_at: a string or null
        - last_activity_editor: a string
        - plan_type: a string,

        - assignee: a dictionary with user details:

            * login: a string
            * id: an integer
            * node_id: a string
            * avatar_url: a string
            * gravatar_id: a string
            * url: a string
            * html_url: a string
            * followers_url: a string
            * following_url: a string
            * gists_url: a string
            * starred_url: a string
            * subscriptions_url: a string
            * organizations_url: a string
            * repos_url: a string
            * events_url: a string
            * received_events_url: a string
            * type: a string
            * site_admin: a boolean

        - assigning_team: a dictionary with team details:

            * id: an integer
            * node_id: a string
            * url: a string
            * html_url: a string
            * name: a string
            * slug: a string
            * description: a string
            * privacy: a string
            * notification_setting: a string
            * permission: a string
            * members_url: a string
            * repositories_url: a string
            * parent: an object or null
        """
        ensure_nonemptystring('organization_name')

        return self._collect_data(
            f'orgs/{organization_name}/copilot/billing/seats', key='seats'
        )

    ####################################################################
    # GitHub organization action secrets
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
                raise ApiError from exception
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
    # GitHub repositories
    #
    # get_repository
    # create_repository
    # list_reporitory_teams
    # list_repository_collaborators
    # add_repository_collaborator
    # remove_repository_collaborator
    # list_repository_permissions_user

    @api_call
    def get_repository(
        self, organization_name: str, repository_name: str
    ) -> Dict[str, Any]:
        """Return extended information on a repository.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string

        # Returned value

        A dictionary with the following keys:

        - id
        - node_id
        - name
        - full_name
        - private
        - owner
        - html_url
        - description
        - fork
        - url
        - forks_url
        - keys_url
        - collaborators_url
        - teams_url
        - hooks_url
        - issue_events_url
        - events_url
        - assignees_url
        - branches_url
        - tags_url
        - blobs_url
        - git_tags_url
        - git_refs_url
        - trees_url
        - statuses_url
        - languages_url
        - stargazers_url
        - contributors_url
        - subscribers_url
        - subscription_url
        - commits_url
        - git_commits_url
        - comments_url
        - issue_comment_url
        - contents_url
        - compare_url
        - merges_url
        - archive_url
        - downloads_url
        - issues_url
        - pulls_url
        - milestones_url
        - notifications_url
        - labels_url
        - releases_url
        - deployments_url
        - created_at
        - updated_at
        - pushed_at
        - git_url
        - ssh_url
        - clone_url
        - svn_url
        - homepage
        - size
        - stargazers_count
        - watchers_count
        - language
        - has_issues
        - has_projects
        - has_downloads
        - has_wiki
        - has_pages
        - has_discussions
        - forks_count
        - mirror_url
        - archived
        - disabled
        - open_issues_count
        - license
        - allow_forking
        - is_template
        - web_commit_signoff_required
        - topics
        - visibility
        - forks
        - open_issues
        - watchers
        - default_branch
        - permissions
        - temp_clone_token
        - allow_squash_merge
        - allow_merge_commit
        - allow_rebase_merge
        - allow_auto_merge
        - delete_branch_on_merge
        - allow_update_branch
        - use_squash_pr_title_as_default
        - squash_merge_commit_message
        - squash_merge_commit_title
        - merge_commit_message
        - merge_commit_title
        - custom_properties
        - organization
        - security_and_analysis
        - network_count
        - subscribers_count
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')

        return self._get(f'repos/{organization_name}/{repository_name}')

    @api_call
    def create_repository(
        self,
        organization_name: str,
        repository_name: str,
        *,
        description: Optional[str] = None,
        private: bool = False,
        visibility: Optional[str] = None,
        has_issues: bool = True,
        has_projects: bool = True,
        has_wiki: bool = True,
        has_downloads: bool = True,
        is_template: bool = False,
        team_id: Optional[int] = None,
        auto_init: bool = False,
        gitignore_template: Optional[str] = None,
        license_template: Optional[str] = None,
        allow_squash_merge: bool = True,
        allow_merge_commit: bool = True,
        allow_rebase_merge: bool = True,
        allow_auto_merge: bool = True,
        delete_branch_on_merge: bool = False,
        use_squash_pr_title_as_default: bool = False,
        squash_merge_commit_title: Optional[str] = None,
        squash_merge_commit_message: Optional[str] = None,
        merge_commit_title: Optional[str] = None,
        merge_commit_message: Optional[str] = None,
        custom_properties: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a repository in an organization.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string

        # Optional parameters

        The optional parameters, if specified, must be keyword
        arguments.

        - description: a string
        - private: a boolean
        - visibility: a string, one of `'public'`, `'private'`, or
          `'internal'`
        - has_issues: a boolean
        - has_projects: a boolean
        - has_wiki: a boolean
        - has_downloads: a boolean
        - is_template: a boolean
        - team_id: an integer
        - auto_init: a boolean
        - gitignore_template: a string
        - license_template: a string
        - allow_squash_merge: a boolean
        - allow_merge_commit: a boolean
        - allow_rebase_merge: a boolean
        - allow_auto_merge: a boolean
        - delete_branch_on_merge: a boolean
        - use_squash_pr_title_as_default: a boolean
        - squash_merge_commit_title: a string
        - squash_merge_commit_message: a string
        - merge_commit_title: a string
        - merge_commit_message: a string
        - custom_properties: a dictionary

        # Returned value

        A _repository_. See #get_repository() for its content.
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')

        ensure_noneorinstance('description', str)
        ensure_instance('private', bool)
        ensure_noneorinstance('visibility', str)
        ensure_instance('has_issues', bool)
        ensure_instance('has_projects', bool)
        ensure_instance('has_wiki', bool)
        ensure_instance('has_downloads', bool)
        ensure_instance('is_template', bool)
        ensure_noneorinstance('team_id', int)
        ensure_instance('auto_init', bool)
        ensure_noneorinstance('gitignore_template', str)
        ensure_noneorinstance('license_template', str)
        ensure_instance('allow_squash_merge', bool)
        ensure_instance('allow_merge_commit', bool)
        ensure_instance('allow_rebase_merge', bool)
        ensure_instance('allow_auto_merge', bool)
        ensure_instance('delete_branch_on_merge', bool)
        ensure_instance('use_squash_pr_title_as_default', bool)
        ensure_noneorinstance('squash_merge_commit_title', str)
        ensure_noneorinstance('squash_merge_commit_message', str)
        ensure_noneorinstance('merge_commit_title', str)
        ensure_noneorinstance('merge_commit_message', str)
        ensure_noneorinstance('custom_properties', dict)

        data = {
            'name': repository_name,
            'private': private,
            'has_issues': has_issues,
            'has_projects': has_projects,
            'has_wiki': has_wiki,
            'auto_init': auto_init,
            'has_downloads': has_downloads,
            'is_template': is_template,
            'allow_squash_merge': allow_squash_merge,
            'allow_merge_commit': allow_merge_commit,
            'allow_rebase_merge': allow_rebase_merge,
            'allow_auto_merge': allow_auto_merge,
            'delete_branch_on_merge': delete_branch_on_merge,
            'use_squash_pr_title_as_default': use_squash_pr_title_as_default,
        }

        add_if_specified(data, 'description', description)
        add_if_specified(data, 'visibility', visibility)
        add_if_specified(data, 'team_id', team_id)
        add_if_specified(data, 'gitignore_template', gitignore_template)
        add_if_specified(data, 'license_template', license_template)
        add_if_specified(
            data, 'squash_merge_commit_title', squash_merge_commit_title
        )
        add_if_specified(
            data, 'squash_merge_commit_message', squash_merge_commit_message
        )
        add_if_specified(data, 'merge_commit_title', merge_commit_title)
        add_if_specified(data, 'merge_commit_message', merge_commit_message)
        add_if_specified(data, 'custom_properties', custom_properties)

        result = self._post(f'orgs/{organization_name}/repos', json=data)
        return result

    @api_call
    def list_repository_teams(
        self, organization_name: str, repository_name: str
    ) -> List[Dict[str, Any]]:
        """List the teams of a repository.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string

        # Returned value

        A list of _teams_.  Each team is a dictionary with the following
        keys:

        - name
        - id
        - node_id
        - slug
        - description
        - privacy
        - notification_setting
        - url
        - html_url
        - members_url
        - repositories_url
        - permission
        - permissions
        - parent
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')

        return self._collect_data(
            f'repos/{organization_name}/{repository_name}/teams'
        )

    @api_call
    def list_repository_collaborators(
        self, organization_name: str, repository_name: str
    ) -> List[Dict[str, Any]]:
        """List the collaborators of a repository.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string

        # Returned value

        A list of _members_.  Each member is a dictionary with the
        following entries:

        - login: a string
        - id: an integer
        - node_id: a string
        - avatar_url: a string
        - gravatar_id: a string
        - url: a string
        - html_url: a string
        - followers_url: a string
        - following_url: a string
        - gists_url: a string
        - starred_url: a string
        - subscriptions_url: a string
        - organizations_url: a string
        - repos_url: a string
        - events_url: a string
        - received_events_url: a string
        - type: a string
        - user_view_type: a string
        - site_admin: a boolean
        - permissions: a dictionary
        - role_name: a string
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')

        return self._collect_data(
            f'repos/{organization_name}/{repository_name}/collaborators'
        )

    @api_call
    def add_repository_collaborator(
        self,
        organization_name: str,
        repository_name: str,
        user_name: str,
        permission: str = 'pull',
    ) -> bool:
        """Add a collaborator to a repository.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string
        - user_name: a non-empty string

        # Optional parameters

        - permission: a non-empty string, one of `'pull'`, `'triage'`,
          `'push'`, `'maintain'`, or `'admin'` (`'pull'` by default)

        # Returned value

        A boolean.  True when successful.
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')
        ensure_nonemptystring('user_name')
        ensure_in(
            'permission', ('pull', 'triage', 'push', 'maintain', 'admin')
        )

        result = self._put(
            f'repos/{organization_name}/{repository_name}/collaborators/{user_name}',
            json={'permission': permission},
        )
        return (result.status_code // 100) == 2

    @api_call
    def remove_repository_collaborator(
        self, organization_name: str, repository_name: str, user_name: str
    ) -> bool:
        """Remove a collaborator from a repository.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string
        - user_name: a non-empty string

        # Returned value

        A boolean.  True when successful.
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')
        ensure_nonemptystring('user_name')

        result = self._delete(
            f'repos/{organization_name}/{repository_name}/collaborators/{user_name}'
        )
        return (result.status_code // 100) == 2

    rm_repository_collaborator = remove_repository_collaborator

    ####################################################################
    # GitHubCloud enterprise
    #
    # get_enterprise
    # get_consumed_licenses

    @api_call
    def get_enterprise(self, enterprise_name: str) -> Dict[str, Any]:
        """Returns the enterprise details

        # Required parameters

        - enterprise_name: a non-empty string

        # Returned value

        An _enterprise_. An enterprise is a dictionary.
        """
        ensure_nonemptystring('enterprise_name')

        query = '''
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
        }'''
        result = self.post_graphql_query(
            query, {'enterprise': enterprise_name}
        )
        return result['data']['enterprise']

    @api_call
    def get_consumed_licenses(self, enterprise_name: str) -> Dict[str, Any]:
        """Return consumed licenses.

        # Required parameters

        - enterprise_name: a non-empty string

        # Returned value

        A dictionary with the following entries:

        - total_seats_consumed: an integer
        - total_seats_purchased: an integer
        """
        ensure_nonemptystring('enterprise_name')

        response = self.session().get(
            join_url(
                self.url, f'enterprises/{enterprise_name}/consumed-licenses'
            )
        )

        data = response.json()
        return {
            'total_seats_consumed': data['total_seats_consumed'],
            'total_seats_purchased': data['total_seats_purchased'],
        }

    ####################################################################
    # GitHubCloud billing
    #
    # list_enterprise_consumedlicenses_users
    # list_enterprise_billing_usage
    # list_organization_billing_usage

    @api_call
    def list_enterprise_consumedlicenses_users(
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
        - enterprise_server_primary_emails: a list of strings
        - visual_studio_license_status: a string
        - visual_studio_subscription_email: a string
        - total_user_accounts: an integer
        """
        ensure_nonemptystring('enterprise_name')

        return self._collect_data(
            f'enterprises/{enterprise_name}/consumed-licenses', key='users'
        )

    @api_call
    def list_enterprise_billing_usage(
        self,
        enterprise_name: str,
        year: Optional[int] = None,
        month: Optional[int] = None,
        day: Optional[int] = None,
        cost_center_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List the billing usage of an enterprise.

        # Required parameters

        - enterprise_name: a non-empty string

        # Optional parameters

        - year: an integer, the year to filter by
        - month: an integer, the month to filter by
        - day: an integer, the day to filter by
        - cost_center_id: a string, the cost center ID to filter by

        # Returned value

        A list of dictionaries with the following entries:

        - date: a string
        - product: a string
        - sku: a string
        - quantity: an integer
        - unitType: a string
        - pricePerUnit: a float
        - grossAmount: a float
        - discountAmount: a float
        - netAmount: a float
        - organizationName: a string
        - repositoryName: a string
        """
        ensure_nonemptystring('enterprise_name')
        ensure_noneorinstance('year', int)
        ensure_noneorinstance('month', int)
        ensure_noneorinstance('day', int)
        ensure_noneorinstance('cost_center_id', str)

        params = {}
        add_if_specified(params, 'year', year)
        add_if_specified(params, 'month', month)
        add_if_specified(params, 'day', day)
        add_if_specified(params, 'cost_center_id', cost_center_id)
        response = self._get(
            f'enterprises/{enterprise_name}/settings/billing/usage',
            params=params,
        ).json()

        return response.get('usageItems', [])

    @api_call
    def list_organization_billing_usage(
        self,
        organization_name: str,
        year: Optional[int] = None,
        month: Optional[int] = None,
        day: Optional[int] = None,
        cost_center_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List the billing usage of an organization.

        # Required parameters

        - organization_name: a non-empty string

        # Optional parameters

        - year: an integer, the year to filter by
        - month: an integer, the month to filter by
        - day: an integer, the day to filter by
        - cost_center_id: a string, the cost center ID to filter by

        # Returned value

        A list of dictionaries with the following entries:

        - date: a string
        - product: a string
        - sku: a string
        - quantity: an integer
        - unitType: a string
        - pricePerUnit: a float
        - grossAmount: a float
        - discountAmount: a float
        - netAmount: a float
        - organizationName: a string
        - repositoryName: a string
        """
        ensure_nonemptystring('organization_name')
        ensure_noneorinstance('year', int)
        ensure_noneorinstance('month', int)
        ensure_noneorinstance('day', int)
        ensure_noneorinstance('cost_center_id', str)

        params = {}
        add_if_specified(params, 'year', year)
        add_if_specified(params, 'month', month)
        add_if_specified(params, 'day', day)
        add_if_specified(params, 'cost_center_id', cost_center_id)

        response = self._get(
            f'orgs/{organization_name}/settings/billing/usage',
            params=params,
        ).json()

        return response.get('usageItems', [])

    ####################################################################
    # GitHubCloud SCIM
    #
    # list_scim_users

    @api_call
    def list_scim_users(
        self,
        enterprise_name: str,
        start_index: int = 1,
        count: int = 100,
        filter: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List SCIM users in an enterprise.

        SCIM stands for _System for Cross-domain Identity Management_.

        Possible filters are on userName, externalId, id, or
        displayName.

        For example:

            userName eq "Octocat"

        # Required parameters

        - enterprise_name: a non-empty string

        # Optional parameters

        - start_index: an integer, the index of the first user to return
        - count: an integer, the number of users to return
        - filter: a string, a filter to apply to the list of users.

        # Returned value

        A list of SCIM users, each represented as a dictionary with the
        following entries:

        - schemas: a dictionary
        - active: a boolean
        - emails: a list of dictionaries, each with `value` and
          `primary` keys
        - ?externalId: a string
        - userName: a string
        - name: a dictionary with `givenName`, `familyName`, and
          `formatted` keys
        - ?displayName: a string
        - roles: a dictionary
        """
        ensure_nonemptystring('enterprise_name')
        ensure_instance('start_index', int)
        ensure_instance('count', int)
        ensure_noneorinstance('filter', str)

        params = {
            'startIndex': str(start_index),
            'count': str(count),
        }
        add_if_specified(params, 'filter', filter)

        return self._collect_resources_data(
            f'scim/v2/enterprises/{enterprise_name}/Users',
            params=params,
        )

    ####################################################################
    # GitHub GraphQL
    #
    # post_graphql_query

    @api_call
    def post_graphql_query(
        self, query: str, variables: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Post a GraphQL query to GitHub.

        # Required parameters

        - query: a non-empty string, the GraphQL query to execute

        # Optional parameters

        - variables: a dictionary, the variables to pass to the query

        # Returned value

        A dictionary with the result of the query.
        """
        ensure_nonemptystring('query')
        ensure_noneorinstance('variables', dict)

        json_data = {'query': query}
        add_if_specified(json_data, 'variables', variables)

        response = self._post('graphql', json=json_data)
        return response.json()

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
        key: Optional[str] = None,
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
                response_data = response.json()
                if key is not None:
                    collected += response_data.get(key, [])
                else:
                    collected += response.json()
            except Exception as exception:
                raise ApiError from exception
            if 'next' in response.links:
                api_url = response.links['next']['url']
            else:
                break

        return collected

    def _get_page_info(self, data: Dict[str, Any]) -> Optional[Any]:
        """Recursively search for the 'pageInfo' key in a nested dictionary."""
        if 'pageInfo' in data:
            return data['pageInfo']

        for _, value in data.items():
            if isinstance(value, dict):
                result = self._get_page_info(value)
                if result is not None:
                    return result
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        result = self._get_page_info(item)
                        if result is not None:
                            return result
        return None

    def _collect_resources_data(
        self,
        api: str,
        params: Optional[Mapping[str, Union[str, List[str], None]]] = None,
        start_index: str = 'startIndex',
        key: str = 'Resources',
    ):
        """Return GitHub API call results, collected.

        The API call is expected to return a list of items under the
        specified key. If not, an _ApiError_ exception is raised.
        """
        api_url = join_url(self.url, api)
        collected: List[Dict[str, Any]] = []
        more = True
        while more:
            response = self.session().get(api_url, params=params)
            if response.status_code // 100 != 2:
                raise ApiError(response.text)
            try:
                workload = response.json()
                values = workload[key]
                collected += values
            except Exception as exception:
                raise ApiError from exception
            more = (
                workload[start_index] + len(values) < workload['totalResults']
            )
            if more:
                params[start_index] = workload[start_index] + len(values)
        return collected
