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

This module depends on the **requests** public library.  It also depends
on three **zabel-commons** modules, #::zabel.commons.exceptions,
#::zabel.commons.sessions, and #::zabel.commons.utils.
"""

from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, Union

import requests

from zabel.commons.exceptions import ApiError
from zabel.commons.sessions import prepare_session
from zabel.commons.utils import (
    add_if_specified,
    api_call,
    ensure_in,
    ensure_instance,
    ensure_nonemptystring,
    ensure_noneorinstance,
    ensure_noneornonemptystring,
    ensure_onlyone,
    join_url,
    BearerAuth,
)


########################################################################
########################################################################

# GitHub low-level api


class GitHub:
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

    def __init__(
        self,
        url: str,
        user: Optional[str] = None,
        token: Optional[str] = None,
        *,
        basic_auth: Optional[Tuple[str, str]] = None,
        bearer_auth: Optional[str] = None,
        management_url: Optional[str] = None,
        verify: bool = True,
    ) -> None:
        """Create a GitHub instance object.

        The optional `management_url` is only required if
        'enterprise' features are used (staff reports, ...).

        Some methods require an Enterprise Cloud account.

        The legacy `user` and `token` parameters are still supported.

        # Required parameters

        - url: a non-empty string
        - basic_auth: a string tuple (user, token) or None (None by
          default)
        - bearer_auth: a string or None (None by default)

        # Optional parameters

        - management_url: a non-empty string or None (None by
          default)
        - verify: a boolean (True by default)

        `verify` can be set to False if disabling certificate checks for
        GitHub communication is required.  Tons of warnings will occur
        if this is set to False.
        """
        ensure_nonemptystring('url')
        ensure_noneorinstance('user', str)
        ensure_noneorinstance('token', str)
        ensure_noneorinstance('basic_auth', tuple)
        ensure_noneorinstance('bearer_auth', str)
        ensure_noneornonemptystring('management_url')

        self.url = url
        if basic_auth is not None or bearer_auth is not None:
            self.auth = basic_auth or BearerAuth(bearer_auth)
        else:
            self.auth = (user, token)
        self.management_url = management_url
        self.verify = verify
        self.session = prepare_session(self.auth, verify=verify)

    def __str__(self) -> str:
        return f'{self.__class__.__name__}: {self.url}'

    def __repr__(self) -> str:
        url, auth, mngt = self.url, self.auth[0], self.management_url
        return f'<{self.__class__.__name__}: {url!r}, {auth!r}, {mngt!r}>'

    ####################################################################
    # GitHub users (that or organization members?)
    #
    # list_users
    # get_user
    # create_user
    # update_user
    # delete_user
    # get_user_organizations
    # suspend_user
    # unsuspend_user

    @api_call
    def list_users(self) -> List[Dict[str, Any]]:
        """Return the list of users.

        This API returns users and organizations.  Use the `type` entry
        in the returned items to distinguish (`'User'` or
        `'Organization'`).

        # Returned value

        A list of _users_.  A user is a dictionary with the following
        entries:

        - avatar_url: a string
        - events_url: a string
        - followers_url: a string
        - following_url: a string
        - gist_url: a string
        - gravatar_id: a string
        - html_url: a string
        - id: an integer
        - login: a string
        - node_id: a string
        - organizations_url: a string
        - received_events_url: a string
        - repos_url: a string
        - site_admin: a boolean
        - starred_url: a string
        - subscription_url: a string
        - type: a string
        - url: a string
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
        - organizations_url: a string
        - public_gists: an integer
        - public_repos: an integer
        - received_events_url: a string
        - repos_url: a string
        - site_admin: a boolean
        - starred_url: a string
        - subscription_url: a string
        - suspend_at:
        - type: a string
        - updated_at:
        - url: a string
        """
        ensure_nonemptystring('user_name')

        return self._get(f'users/{user_name}')  # type: ignore

    @api_call
    def get_user_organizations(self, login: str) -> Dict[str, Any]:
        """Get the list of organizations for a specific user.

        # Required parameters
        - login: the login identifier of the user.

        # Returned value
        A dictionary containing the organizations the user belongs to.
        """
        ensure_nonemptystring('login')

        response = self._get(f'users/{login}/orgs')
        return response

    @api_call
    def create_user(
        self,
        login: str,
        email: Optional[str] = None,
        suspended: bool = False,
    ) -> Dict[str, Any]:
        """Create a new user on GitHub Enterprise.

        # Required parameters

        - login: a non-empty string

        # Optional parameters

        - email: a string or None (None by default)
        - suspended: a boolean (True by default)

        # Returned value

        A dictionary with the following entry:

        - user: a dictionary

        The `user` dictionary with the following entries:

        - login: a string
        - id: an integer
        - email: a string
        - scmAccount: a list of strings
        - active: a boolean
        - local: a boolean
        """
        ensure_nonemptystring('login')
        ensure_noneornonemptystring('email')

        data = {
            'login': login,
            'email': email,
        }

        result = self._post('admin/users', data)
        return result

    @api_call
    def update_user(
        self,
        current_username: str,
        new_username: str,
    ) -> Dict[str, Any]:
        """Update the username for a user on Github Enterprise.

        # Required parameters

        - current_username: a non-empty string
        - new_username: a non-empty string

        # Returned value

        A user object.  A user is a dictionary with the
        following keys:

        - login: a string
        - id: an integer
        - email: a string
        - scmAccount: a list of strings
        - active: a boolean
        - local: a boolean
        """

        ensure_nonemptystring('current_username')
        ensure_nonemptystring('new_username')

        data = {'login': new_username}

        resultat = self._patch(f'admin/users/{current_username}', data)
        return resultat

    @api_call
    def delete_user(self, username: str) -> None:
        """Delete a user from Github Entreprise

        # Required parameters

        - username: a string

        # Returned value

        - None
        """

        ensure_nonemptystring('username')
        result = self._delete(f'admin/users/{username}')
        return result

    @api_call
    def suspend_user(self, user_name: str) -> bool:
        """Suspend the specified user.

        Suspending an already suspended user is allowed.

        # Required parameters

        - user_name: a non-empty string

        # Returned value

        A boolean.  True if the operation was successful.
        """
        ensure_nonemptystring('user_name')

        return self._put(f'users/{user_name}/suspended').status_code == 204

    @api_call
    def unsuspend_user(self, user_name: str) -> bool:
        """Unsuspend the specified user.

        Unsuspending a non-suspended user is allowed.

        # Required parameters

        - user_name: a non-empty string

        # Returned value

        A boolean.  True if the operation was successful.
        """
        ensure_nonemptystring('user_name')

        return self._delete(f'users/{user_name}/suspended').status_code == 204

    ####################################################################
    # Personal access tokens
    #
    # list_tokens
    # delete_token

    @api_call
    def list_tokens(self) -> List[Dict[str, Any]]:
        """Return the list of personal access tokens.

        # Returned value

        A list of _tokens_.  A token is a dictionary with the following
        entries:

        - id: an integer
        - name: a string
        - url: a string
        - token_last_eight: a string
        - created_at: a string (a timestamp)
        - updated_at: a string (a timestamp)
        - scopes: a list of strings
        """
        return self._collect_data('admin/tokens')

    @api_call
    def delete_token(self, token_id: int) -> bool:
        """Delete a personal access token.

        # Required parameters

        - token_id: an integer

        # Returned value

        A boolean.  True if the deletion was successful.
        """
        return self._delete(f'admin/tokens/{token_id}').status_code == 204

    ####################################################################
    # GitHub organizations
    #
    # organization name = login key
    #
    # list_organizations
    # get_organization
    # TODO update_organization
    # list_organization_repositories
    # list_organization_members
    # list_organization_outsidecollaborators
    # get_organization_membership
    # add_organization_membership
    # remove_organization_membership
    # add_organization_outsidecollaborator
    # remove_organization_outsidecollaborator
    # list_organization_teams
    # send_organization_invitation
    # cancel_organization_invitation
    # list_organization_failedinvitations
    # list_organization_invitations
    #
    # Part of enterprise administration
    # create_organization
    # TODO rename_organization

    @api_call
    def list_organizations(self) -> List[Dict[str, Any]]:
        """Return list of organizations.

        # Returned value

        A list of _organizations_.  Each organization is a dictionary
        with the following keys:

        - avatar_url: a string
        - description: a string
        - events_url: a string
        - hooks_url: a string
        - id: an integer
        - issues_url: a string
        - login: a string
        - members_url: a string
        - node_id: a string
        - public_members_url: a string
        - repos_url: a string
        - url: a string

        The organization name is the `login` key.
        """
        return self._collect_data('organizations')

    @api_call
    def list_organization_teams(
        self, organization_name: str
    ) -> List[Dict[str, Any]]:
        """Return list of teams.

        # Required parameters

        - organization_name: a non-empty string

        # Returned value

        A list of _teams_.  Each team is a dictionary with the following
        keys:

        - name: a string
        - id: an integer
        - node_id: a string
        - slug: a string
        - description: a string
        - privacy: a string
        - url: a string
        - html_url: a string
        - members_url: a string
        - repositories_url: a string
        - permission: a string
        - parent: ?
        """
        ensure_nonemptystring('organization_name')

        return self._get(f'orgs/{organization_name}/teams')  # type: ignore

    @api_call
    def send_organization_invitation(
        self,
        organization_name: str,
        *,
        invitee_id: Optional[int] = None,
        email: Optional[str] = None,
        role: str = 'direct_member',
        team_ids: Optional[List[int]] = None,
    ) -> Dict[str, Any]:
        """Send an invitation to an user to join an organization.

        # Required parameters

        - organization_name: a non-empty string
        - invitee_id: an integer or None (None by default)
        - email: a string or None (None by default)

        Either `invitee_id` or `email` must be specified.

        # Optional parameters

        - role: a string, one of `direct_member`, `billing_manager`, or
          `admin` (`direct_member` by default)
        - team_ids: a list of integers or None (None by default)

        # Returned value

        An invitation object.  An invitation is a dictionary with the
        following keys:

        - id: an integer
        - login: a string
        - email: a string
        - role: a string
        - created_at: a string
        - inviter: a dictionary
        - team_count: an integer
        - invitation_team_url: a string (url)
        - invitation_teams_url: a string (url)
        """
        ensure_nonemptystring('organization_name')
        ensure_noneorinstance('invitee_id', int)
        ensure_noneornonemptystring('email')
        ensure_onlyone('invitee_id', 'email')
        ensure_in('role', ('direct_member', 'admin', 'billing_manager'))
        ensure_noneorinstance('team_ids', list)

        data = {'role': role}
        add_if_specified(data, 'invitee_id', invitee_id)
        add_if_specified(data, 'email', email)
        add_if_specified(data, 'team_ids', team_ids)

        result = self._post(f'orgs/{organization_name}/invitations', json=data)
        return result  # type: ignore

    @api_call
    def cancel_organization_invitation(
        self, organization_name: str, invitation_id: int
    ) -> bool:
        """Cancel an invitation to an user to join an organization.

        # Required parameters

        - organization_name: a non-empty string
        - invitation_id: an integer

        # Returned value

        A boolean.  True if the invitation was cancelled.
        """
        ensure_nonemptystring('organization_name')
        ensure_instance('invitation_id', int)

        result = self._delete(
            f'orgs/{organization_name}/invitations/{invitation_id}'
        )
        return (result.status_code // 100) == 2

    @api_call
    def list_organization_failedinvitations(
        self, organization_name: str
    ) -> List[Dict[str, Any]]:
        """Return list of failed invitations.

        # Required parameters

        - organization_name: a non-empty string

        # Returned value

        A list of _failed invitations_.  Each failed invitation is a
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
        """
        ensure_nonemptystring('organization_name')

        return self._collect_data(
            f'orgs/{organization_name}/failed_invitations'
        )

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
        """
        ensure_nonemptystring('organization_name')

        return self._collect_data(f'orgs/{organization_name}/invitations')

    @api_call
    def list_organization_installations(
        self, organization_name: str
    ) -> List[Dict[str, Any]]:
        """Return app installations.

        # Required parameters

        - organization_name: a non-empty string

        # Returned value

        A list of _installations_.  Each installation is a dictionary
        with the following keys:

        - access_tokens_url: a string
        - account: a dictionary
        - app_id: an integer
        - app_slug: a string
        - created_at: a string
        - events: a list of strings
        - has_multiple_single_files: a boolean
        - html_url: a string
        - id: an integer
        - permissions: a dictionary
        - repositories_url: a string
        - repository_selection: a string
        - single_file_name: a string
        - single_file_paths
        - suspended_at: a string or None
        - suspended_by: a ? or None
        - target_id: an integer
        - target_type: a string
        - updated_at: a string
        """
        ensure_nonemptystring('organization_name')

        return self._get(f'orgs/{organization_name}/installations').json()['installations']  # type: ignore

    @api_call
    def get_organization(self, organization_name: str) -> Dict[str, Any]:
        """Return extended information on organization.

        # Required parameters

        - organization_name: a non-empty string

        # Returned value

        A dictionary with the following keys:

        - login
        - id
        - url
        - repos_url
        - events_url
        - hooks_url
        - issues_url
        - members_url
        - public_members_url
        - avatar_url
        - description
        - ?name
        - ?company
        - ?blog
        - ?location
        - ?email
        - followers
        - following
        - html_url
        - created_at
        - type
        - ?total_private_repos
        - ?owned_private_repos
        - ?private_gists
        - ?disk_usage
        - ?collaborators
        - ?billing_email
        - ?plan
        - ?default_repository_settings
        - ?members_can_create_repositories

        - has_organization_projects
        - public_gists
        - updated_at
        - has_repository_projects
        - public_repos
        """
        ensure_nonemptystring('organization_name')

        return self._get(f'orgs/{organization_name}')  # type: ignore

    @api_call
    def list_organization_repositories(
        self, organization_name: str, headers: Optional[Dict[str, str]] = None
    ) -> List[Dict[str, Any]]:
        """Return the list of repositories for organization.

        # Required parameters

        - organization_name: a non-empty string

        # Optional parameters

        - headers: a dictionary or None (None by default)

        # Returned value

        A list of _repositories_.  Each repository is a dictionary. See
        #list_repositories() for its format.
        """
        ensure_nonemptystring('organization_name')

        return self._collect_data(
            f'orgs/{organization_name}/repos', headers=headers
        )

    @api_call
    def create_organization(
        self,
        organization_name: str,
        admin: str,
        profile_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create GitHub organization.

        # Required parameters

        - organization_name: a non-empty string
        - admin: a non-empty string

        # Optional parameters

        - profile_name: a string or None (None by default)

        # Returned value

        An _organization_. An organization is a dictionary.
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('admin')
        ensure_noneorinstance('profile_name', str)

        data = {'login': organization_name, 'admin': admin}
        add_if_specified(data, 'profile_name', profile_name)

        result = self._post('admin/organizations', json=data)
        return result  # type: ignore

    @api_call
    def list_organization_members(
        self, organization_name: str, role: str = 'all'
    ) -> List[Dict[str, Any]]:
        """Return the list of organization members.

        # Required parameters

        - organization_name: a non-empty string

        # Optional parameters

        - role: a non-empty string, one of 'all', 'member', or 'admin'
          ('all' by default)

        # Returned value

        A list of _members_.  Each member is a dictionary.
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

        return self._get(f'orgs/{organization_name}/memberships/{user}')  # type: ignore

    @api_call
    def add_organization_membership(
        self, organization_name: str, user: str, role: str = 'member'
    ) -> Dict[str, Any]:
        """Add or update organization membership.

        # Required parameters

        - organization_name: a non-empty string
        - user: a non-empty string

        # Optional parameters

        - role: a non-empty string (`'member'` by default)

        `role` must be either `'member'` or `'admin'`, if provided.

        # Returned value

        A dictionary with the following entries:

        - url: a string
        - state: a string
        - role: a string
        - organization_url: a string
        - organization: a dictionary
        - user: a dictionary

        If `user` already had membership, `state` is `'active'`.  If
        `user` was previously unaffiliated, `state` is `'pending'`.

        Refer to #list_organizations() and #list_users() for more
        details on `organization` and `user` content.
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('user')
        ensure_in('role', ['member', 'admin'])

        result = self._put(
            f'orgs/{organization_name}/memberships/{user}', json={'role': role}
        )
        return result  # type: ignore

    @api_call
    def remove_organization_membership(
        self, organization_name: str, user: str
    ) -> bool:
        """Remove user from organization.

        Removing users will remove them from all teams and they will no
        longer have any access to the organization's repositories.

        # Required parameters

        - organization_name: a non-empty string
        - user: a non-empty string, the login of the user

        # Returned Value

        A boolean.  True if the user has been removed from the
        organization.
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('user')

        result = self._delete(f'orgs/{organization_name}/members/{user}')
        return (result.status_code // 100) == 2

    rm_organization_membership = remove_organization_membership

    @api_call
    def add_organization_outsidecollaborator(
        self, organization_name: str, user: str
    ) -> bool:
        """Add outside collaborator to organization.

        # Required parameters

        - organization_name: a non-empty string
        - user: a non-empty string, the login of the user

        # Returned value

        A boolean.  True if the outside collaborator was added to the
        organization.
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('user')

        result = self._put(
            f'orgs/{organization_name}/outside_collaborators/{user}'
        )
        return (result.status_code // 100) == 2

    add_organization_outside_collaborator = (
        add_organization_outsidecollaborator
    )

    @api_call
    def remove_organization_outsidecollaborator(
        self, organization_name: str, user: str
    ) -> bool:
        """Remove outside collaborator from organization.

        # Required parameters

        - organization_name: a non-empty string
        - user: a non-empty string, the login of the user

        # Returned value

        A boolean.  True if the outside collaborator was removed from
        the organization.
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('user')

        result = self._delete(
            f'orgs/{organization_name}/outside_collaborators/{user}'
        )
        return (result.status_code // 100) == 2

    rm_organization_outside_collaborator = (
        remove_organization_outsidecollaborator
    )
    remove_organization_outside_collaborator = (
        remove_organization_outsidecollaborator
    )

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
    # GitHub apps
    #
    # https://docs.github.com/en/enterprise-server@3.10/rest/orgs/personal-access-tokens?apiVersion=2022-11-28

    @api_call
    def get_app(self, app_slug: str) -> Dict[str, Any]:
        """Return the app details.

        # Required parameters

        - app_slug: a non-empty string

        # Returned value

        An _app_.  An app is a dictionary with the following entries:

        - id: an integer
        - node_id: a string
        - owner: a dictionary
        - name: a string
        - description: a string
        - external_url: a string
        - html_url: a string
        - created_at: a string
        - updated_at: a string
        - permissions: a dictionary
        - events: a list of strings
        - installations_count: an integer
        - slug: a string
        """
        ensure_nonemptystring('app_slug')

        return self._get(f'app/{app_slug}')  # type: ignore

    @api_call
    def list_app_installations(self) -> List[Dict[str, Any]]:
        """Return the list of app installations.

        !!! warning
            Requires a JWT-based authentication.

        # Returned value

        A list of _installations_.  Each installation is a dictionary
        with the following entries:

        - id: an integer
        - account: a dictionary
        - repository_selection: a string
        - access_tokens_url: a string
        - repositories_url: a string
        - html_url: a string
        - app_id: an integer
        - target_id: an integer
        - target_type: a string
        - permissions: a dictionary
        - events: a list of strings
        - created_at: a string
        - updated_at: a string
        - single_file_name: a string
        """
        # ensure_nonemptystring('organization_name')

        return self._collect_data('app/installations')

    @api_call
    def get_app_installation(self, installation_id: int) -> Dict[str, Any]:
        """Return the app installation details.

        !!! warning
            Requires a JWT-based authentication.

        # Required parameters

        - installation_id: an integer

        # Returned value

        An _installation_.  An installation is a dictionary with the
        following entries:

        - id: an integer
        - account: a dictionary
        - repository_selection: a string
        - access_tokens_url: a string
        - repositories_url: a string
        - html_url: a string
        - app_id: an integer
        - target_id: an integer
        - target_type: a string
        - permissions: a dictionary
        - events: a list of strings
        - created_at: a string
        - updated_at: a string
        - single_file_name: a string
        """
        ensure_instance('installation_id', int)

        return self._get(f'app/installations/{installation_id}')  # type: ignore

    @api_call
    def delete_app_installation(self, installation_id: int) -> bool:
        """Delete the app installation.

        !!! warning
            Requires a JWT-based authentication.

        # Required parameters

        - installation_id: an integer

        # Returned value

        A boolean.  True if the installation has been deleted.
        """
        ensure_instance('installation_id', int)

        return (
            self._delete(f'app/installations/{installation_id}').status_code
            == 204
        )

    @api_call
    def create_app_installation_access_token(
        self,
        installation_id: int,
        repositories: Optional[List[str]] = None,
        permissions: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create an access token for the app installation.

        !!! warning
            Requires a JWT-based authentication.

        # Required parameters

        - installation_id: an integer

        # Returned value

        An _access token_.  An access token is a dictionary with the
        following entries:

        - token: a string
        - expires_at: a string
        - permissions: a dictionary
        - repository_selection: a string
        - repository_ids: a list of integers
        """
        ensure_instance('installation_id', int)

        data = {}
        add_if_specified(data, 'repositories', repositories)
        add_if_specified(data, 'permissions', permissions)

        return self._post(
            f'app/installations/{installation_id}/access_tokens', json=data
        )

    ####################################################################
    # GitHub teams
    #
    # list_team_members

    @api_call
    def list_team_members(
        self, organization_name: str, team_name: str
    ) -> List[Dict[str, Any]]:
        """Return a list of members.

        # Required parameters

        - organization_name: a non-empty string
        - team_name: a non-empty string

        # Returned value

        A list of _members_.  Each member is a dictionary with the
        following entries:

        - avatar_url: a string
        - events_url: a string
        - followers_url: a string
        - following_url: a string
        - gists_url: a string
        - gravatar_id: a string
        - html_url: a string
        - id: an integer
        - login: a string
        - node_id: a string
        - organizations_url: a string
        - received_events_url: a string
        - repos_url: a string
        - site_admin: a boolean
        - starred_url: a string
        - subscriptions_url: a string
        - type: a string
        - url: a string
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('team_name')

        return self._get(f'orgs/{organization_name}/teams/{team_name}/members')  # type: ignore

    ####################################################################
    # GitHub repositories
    #
    # repository name = name key
    #
    # list_repositories
    # list_public_repositories
    # get_repository
    # create_repository
    # create_repository_from_template
    # update_repository
    # TODO delete_repository
    # list_repository_commits
    # get_repository_commit
    # list_reporitory_teams
    # list_repository_collaborators
    # add_repository_collaborator
    # remove_repository_collaborator
    # list_repository_permissions_user

    @api_call
    def list_repositories(self) -> List[Dict[str, Any]]:
        """Return the list of repositories.

        # Returned value

        A list of _repositories_.  Each repository is a dictionary with
        the following entries:

        + archive_url: a string
        + assignees_url: a string
        + blobs_url: a string
        + branches_url: a string
        - clone_url: a string
        + collaborators_url: a string
        + comments_url: a string
        + commits_url: a string
        + compare_url: a string
        + contents_url: a string
        + contributors_url: a string
        - created_at: a string (a timestamp)
        - default_branch: a string
        + deployments_url: a string
        + description: a string
        + downloads_url: a string
        + events_url: a string
        + fork: a boolean
        - forks: an integer
        - forks_count: an integer
        + forks_url: a string
        + full_name: a string
        + git_commits_url: a string
        + git_refs_url: a string
        + git_tags_url: a string
        - git_url: a string
        - has_downloads: a boolean
        - has_issues: a boolean
        - has_pages: a boolean
        - has_projects: a boolean
        - has_wiki: a boolean
        - homepage
        + hooks_url: a string
        + html_url: a string
        + id: an integer
        + issue_comment_url
        + issue_events_url
        + issues_url: a string
        + keys_url: a string
        + labels_url: a string
        - language: a string
        + languages_url: a string
        + merges_url: a string
        + milestones_url: a string
        - mirror_url: a string
        + name: a string
        + node_id: a string
        + notifications_url: a string
        - open_issues: an integer
        - open_issues_count: an integer
        + owner: a dictionary
        - permissions: a dictionary
        + private: a boolean
        + pulls_url: a string
        - pushed_at: a string (a timestamp)
        + releases_url
        - size: an integer
        - ssh_url: a string
        - stargazers_count: an integer
        + stargazers_url: a string
        + statuses_url: a string
        + subscribers_url: a string
        + subscription_url: a string
        - svn_url: a string
        + tags_url: a string
        + teams_url: a string
        + trees_url: a string
        - updated_at: a string (a timestamp)
        + url: a string
        - watchers: an integer
        - watchers_count: an integer
        """
        return self._collect_data('repositories', params={'visibility': 'all'})

    @api_call
    def list_public_repositories(self) -> List[Dict[str, Any]]:
        """Return the list of public repositories.

        # Returned value

        A list of _repositories_.  Each repository is a dictionary.  See
        #list_repositories() for its description.
        """
        return self._collect_data('repositories')

    @api_call
    def get_repository(
        self, organization_name: str, repository_name: str
    ) -> Dict[str, Any]:
        """Return the repository details.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string

        # Returned value

        A _repository_. See #list_repositories() for its description.
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')

        return self._get(f'repos/{organization_name}/{repository_name}')  # type: ignore

    @api_call
    def create_repository(
        self,
        organization_name: str,
        repository_name: str,
        *,
        description: Optional[str] = None,
        homepage: Optional[str] = None,
        private: bool = False,
        has_issues: bool = True,
        has_projects: Optional[bool] = None,
        has_wiki: bool = True,
        team_id: Optional[int] = None,
        auto_init: bool = False,
        gitignore_template: Optional[str] = None,
        license_template: Optional[str] = None,
        allow_squash_merge: bool = True,
        allow_merge_commit: bool = True,
        allow_rebase_merge: bool = True,
    ) -> Dict[str, Any]:
        """Create a new repository in organization_name.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string

        # Optional parameters

        - description: a string or None (None by default)
        - homepage: a string or None (None by default)
        - private: a boolean (False by default)
        - has_issues: a boolean (True by default)
        - has_projects: a boolean (True by default except for
            organizations that have disabled repository projects)
        - has_wiki: a boolean (True by default)
        - team_id: an integer or None (None by default)
        - auto_init: a boolean (False by default)
        - gitignore_template: a string or None (None by default)
        - license_template: a string or None (None by default)
        - allow_squash_merge: a boolean (True by default)
        - allow_merge_commit: a boolean (True by default)
        - allow_rebase_merge: a boolean (True by default)

        # Returned value

        A _repository_.  See #list_repositories() for its content.
        """
        ensure_nonemptystring('repository_name')
        ensure_nonemptystring('organization_name')

        ensure_noneorinstance('description', str)
        ensure_instance('private', bool)
        ensure_instance('has_issues', bool)
        ensure_instance('has_wiki', bool)
        ensure_instance('auto_init', bool)
        ensure_instance('allow_squash_merge', bool)
        ensure_instance('allow_merge_commit', bool)
        ensure_instance('allow_rebase_merge', bool)

        data = {
            'name': repository_name,
            'private': private,
            'has_issues': has_issues,
            'has_wiki': has_wiki,
            'auto_init': auto_init,
            'allow_squash_merge': allow_squash_merge,
            'allow_merge_commit': allow_merge_commit,
            'allow_rebase_merge': allow_rebase_merge,
        }
        add_if_specified(data, 'description', description)
        add_if_specified(data, 'homepage', homepage)
        add_if_specified(data, 'has_projects', has_projects)
        add_if_specified(data, 'team_id', team_id)
        add_if_specified(data, 'gitignore_template', gitignore_template)
        add_if_specified(data, 'license_template', license_template)

        result = self._post(f'orgs/{organization_name}/repos', json=data)
        return result  # type: ignore

    @api_call
    def create_repository_from_template(
        self,
        template_owner: str,
        template_repo: str,
        organization_name: str,
        repository_name: str,
        description: Optional[str] = None,
        include_all_branches: bool = False,
        private: bool = False,
    ) -> Dict[str, Any]:
        """Create a new repository in organization_name from a template.

        # Required parameters

        - template_owner: a non-empty string
        - template_repo: a non-empty string
        - organization_name: a non-empty string
        - repository_name: a non-empty string

        # Optional parameters

        - description: a string or None (None by default)
        - include_all_branches: a boolean (False by default)
        - private: a boolean (False by default)

        # Returned value

        A _repository_.  See #list_repositories() for its content.
        """
        ensure_nonemptystring('template_owner')
        ensure_nonemptystring('template_repo')
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')

        ensure_noneorinstance('description', str)
        ensure_instance('include_all_branches', bool)
        ensure_instance('private', bool)

        data = {
            'owner': organization_name,
            'name': repository_name,
            'include_all_branches': include_all_branches,
            'private': private,
        }
        add_if_specified(data, 'description', description)

        result = self._post(
            f'repos/{template_owner}/{template_repo}/generate', json=data
        )
        return result  # type: ignore

    @api_call
    def update_repository(
        self,
        organization_name: str,
        repository_name: str,
        patched_attributes: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Update a repository attributes.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string
        - patched_attributes: a dictionary

        # Returned value

        A _repository_.  See #list_repositories() for its content.
        """
        ensure_nonemptystring('repository_name')
        ensure_nonemptystring('organization_name')
        ensure_instance('patched_attributes', dict)

        response = self._patch(
            f'repos/{organization_name}/{repository_name}',
            json=patched_attributes,
        )
        return response  # type: ignore

    @api_call
    def list_repository_topics(
        self, organization_name: str, repository_name: str
    ) -> List[str]:
        """Return the list of topics.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string

        # Returned value

        A list of strings (the list may be empty).
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')

        response = self._get(
            f'repos/{organization_name}/{repository_name}/topics',
            headers={'Accept': 'application/vnd.github.mercy-preview+json'},
        ).json()
        return response['names']  # type: ignore

    @api_call
    def replace_repository_topics(
        self,
        organization_name: str,
        repository_name: str,
        topics: Iterable[str],
    ) -> List[str]:
        """Replace the list of topics.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string
        - topics: a list of strings

        # Returned value

        A possibly empty list of strings.
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')
        ensure_instance('topics', list)

        response = self._put(
            f'repos/{organization_name}/{repository_name}/topics',
            json={'names': topics},
            headers={'Accept': 'application/vnd.github.mercy-preview+json'},
        ).json()
        return response['names']  # type: ignore

    @api_call
    def list_repository_codefrequency(
        self, organization_name: str, repository_name: str
    ) -> List[List[int]]:
        """Return the list of number of additions&deletions per week.

        The returned value is cached.  A first call for a given
        repository may return a 202 response code.  Retrying a moment
        later will return the computed value.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string

        # Returned value

        A list of lists. Each item in the list is a list with the
        following three values, in order:

        - week: an integer (a unix timestamp)
        - additions: an integer
        - deletions: an integer
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')

        result = self._get(
            f'repos/{organization_name}/{repository_name}/stats/code_frequency'
        )
        return result  # type: ignore

    @api_call
    def list_repository_contributions(
        self, organization_name: str, repository_name: str
    ) -> List[Dict[str, Any]]:
        """Return the list of contributors with their contributions.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string

        # Returned value

        A list of _contributors_.  Each contributor is a dictionary with
        the following entries:

        - author: a dictionary
        - total: the number of commits authored by the contributor
        - weeks: a list of dictionaries describing the contributions
            per week

        `author` contains the following non exhaustive entries:

        - id: a string
        - login: a string
        - type: a string

        Each item in `weeks` has the following entries:

        - w: a string (a unix timestamp)
        - a: an integer (number of additions)
        - d: an integer (number of deletions)
        - c: an integer (number of commits)
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')

        result = self._get(
            f'repos/{organization_name}/{repository_name}/stats/contributors'
        )
        return result  # type: ignore

    @api_call
    def list_repository_commits(
        self,
        organization_name: str,
        repository_name: str,
        sha: Optional[str] = None,
        path: Optional[str] = None,
        author: Optional[str] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return the list of commits.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string

        # Optional parameters

        - sha: a string or None (None by default)
        - path: a string or None (None by default)
        - author: a non-empty string or None (None by default)
        - since: a non-empty string (an ISO 8601 timestamp) or None
          (None by default)
        - until: a non-empty string (an ISO 8601 timestamp) or None
          (None by default)

        # Return value

        A list of _commits_.  Each commit is a dictionary.
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')

        params: Dict[str, Any] = {}
        add_if_specified(params, 'sha', sha)
        add_if_specified(params, 'path', path)
        add_if_specified(params, 'author', author)
        add_if_specified(params, 'since', since)
        add_if_specified(params, 'until', until)
        result = self._get(
            f'repos/{organization_name}/{repository_name}/commits',
            params=params,
        )
        return result  # type: ignore

    @api_call
    def get_repository_commit(
        self, organization_name: str, repository_name: str, ref: str
    ) -> Dict[str, Any]:
        """Return a specific commit.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string
        - ref: a non-empty string

        # Returned value

        A _commit_.  A commit is a dictionary.
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')
        ensure_nonemptystring('ref')

        result = self._get(
            f'repos/{organization_name}/{repository_name}/commits/{ref}'
        )
        return result  # type: ignore

    @api_call
    def list_repository_teams(
        self, organization_name: str, repository_name: str
    ) -> List[Dict[str, Any]]:
        """Return list of teams.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string

        # Returned value

        A list of _teams_.  Each team is a dictionary with the following
        keys:

        - name: a string
        - id: an integer
        - node_id: a string
        - slug: a string
        - description: a string
        - privacy: a string
        - url: a string
        - html_url: a string
        - members_url: a string
        - repositories_url: a string
        - permission: a string
        - parent: ?
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')

        return self._get(f'repos/{organization_name}/{repository_name}/teams')  # type: ignore

    @api_call
    def list_repository_collaborators(
        self, organization_name: str, repository_name: str
    ) -> List[Dict[str, Any]]:
        """Return list of collaborators.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string

        # Returned value

        A list of _members_.  Each member is a dictionary with the
        following entries:

        - avatar_url: a string
        - events_url: a string
        - followers_url: a string
        - following_url: a string
        - gists_url: a string
        - gravatar_id: a string
        - html_url: a string
        - id: an integer
        - login: a string
        - node_id: a string
        - organizations_url: a string
        - received_events_url: a string
        - repos_url: a string
        - site_admin: a boolean
        - starred_url: a string
        - subscriptions_url: a string
        - type: a string
        - url: a string
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')

        return self._collect_data(f'repos/{organization_name}/{repository_name}/collaborators')  # type: ignore

    @api_call
    def add_repository_collaborator(
        self,
        organization_name: str,
        repository_name: str,
        user: str,
        permission: str = 'push',
    ) -> None:
        """Add collaborator to repository.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string
        - user: a non-empty string
        - permission: a non-empty string
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')
        ensure_nonemptystring('user')
        ensure_in(
            'permission', ['pull', 'triage', 'push', 'maintain', 'admin']
        )

        params = {'permission': permission}

        self._put(
            f'repos/{organization_name}/{repository_name}/collaborators/{user}',
            json=params,
        )

    @api_call
    def remove_repository_collaborator(
        self, organization_name: str, repository_name: str, user: str
    ) -> None:
        """Remove collaborator from repository.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string
        - user: a non-empty string
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')
        ensure_nonemptystring('user')

        self._delete(
            f'repos/{organization_name}/{repository_name}/collaborators/{user}'
        )

    rm_repository_collaborator = remove_repository_collaborator

    @api_call
    def list_repository_permissions_user(
        self, organization_name: str, repository_name: str, user: str
    ) -> Dict[str, Any]:
        """List permissions of an user on a repository.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string
        - user: a non-empty string

        # Returned value

        Return a dictionary with following keys:

        - permission: a string
        - user: a dictionary
        - role_name: a string
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')
        ensure_nonemptystring('user')

        result = self._get(
            f'repos/{organization_name}/{repository_name}/collaborators/{user}/permission'
        )
        return result  # type: ignore

    ####################################################################
    # GitHub repository contents
    #
    # get_repository_readme
    # get_repository_content
    # create_repository_file
    # update_repository_file

    @api_call
    def get_repository_readme(
        self,
        organization_name: str,
        repository_name: str,
        ref: Optional[str] = None,
        format_: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return the repository README.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string

        # Optional parameters

        - ref: a non-empty string or None (None by default)
        - format_: a custom media type (a non-empty string) or None
          (None by default)

        # Returned value

        A dictionary by default.  May be something else if `format_` is
        specified.
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')
        ensure_noneornonemptystring('ref')
        ensure_noneornonemptystring('format_')

        params = {'ref': ref} if ref is not None else None
        headers = {'Accept': format_} if format_ is not None else None
        result = self._get(
            f'repos/{organization_name}/{repository_name}/readme',
            params=params,
            headers=headers,
        )
        return result  # type: ignore

    @api_call
    def get_repository_content(
        self,
        organization_name: str,
        repository_name: str,
        path: str,
        ref: Optional[str] = None,
        format_: Optional[str] = None,
    ) -> Any:
        """Return the file or directory content.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string
        - path: a string

        # Optional parameters

        - ref: a non-empty string or None (None by default)
        - format_: the custom media type (a non-empty string) or None
          (None by default)

        # Returned value

        A dictionary or a list of dictionaries by default.  May be
        something else if `format_` is specified
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')
        ensure_instance('path', str)
        ensure_noneornonemptystring('ref')
        ensure_noneornonemptystring('format_')

        params = {'ref': ref} if ref is not None else None
        headers = {'Accept': format_} if format_ is not None else None
        result = self._get(
            f'repos/{organization_name}/{repository_name}/contents/{path}',
            params=params,
            headers=headers,
        )
        if result.status_code // 100 == 2:
            try:
                return result.json()
            except requests.exceptions.JSONDecodeError:
                return result.text
        return result  # type: ignore

    @api_call
    def create_repository_file(
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
        """Create a new repository file.

        The created file must not already exist.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string
        - path: a string
        - message: a string
        - content: a string (Base64-encoded)

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

        data = {'message': message, 'content': content}
        add_if_specified(data, 'branch', branch)
        add_if_specified(data, 'committer', committer)
        add_if_specified(data, 'author', author)

        result = self._put(
            f'repos/{organization_name}/{repository_name}/contents/{path}',
            json=data,
        )
        return result  # type: ignore

    @api_call
    def update_repository_file(
        self,
        organization_name: str,
        repository_name: str,
        path: str,
        message: str,
        content: str,
        sha: str,
        branch: Optional[str] = None,
        committer: Optional[Dict[str, str]] = None,
        author: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Update a repository file.

        The file must already exist on the repository.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string
        - path: a string
        - message: a string
        - content: a string (Base64-encoded)
        - sha: a non-empty string

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
        ensure_nonemptystring('sha')
        ensure_noneornonemptystring('branch')
        ensure_noneorinstance('committer', dict)
        ensure_noneorinstance('author', dict)

        data = {'message': message, 'content': content, 'sha': sha}
        add_if_specified(data, 'branch', branch)
        add_if_specified(data, 'committer', committer)
        add_if_specified(data, 'author', author)

        result = self._put(
            f'repos/{organization_name}/{repository_name}/contents/{path}',
            json=data,
        )
        return result  # type: ignore

    ####################################################################
    # GitHub repository branches
    #
    # list_branches
    # get_branch

    @api_call
    def list_branches(
        self,
        organization_name: str,
        repository_name: str,
        protected: bool = False,
    ) -> List[Dict[str, Any]]:
        """List branches.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string

        # Optional parameters

        - protected: a boolean

        # Returned value

        A list of _short branches_.  Each short branch is a dictionary
        with the following entries:

        - name: a string
        - commit: a dictionary
        - protected: a boolean
        - protection: a dictionary
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')
        ensure_instance('protected', bool)

        return self._collect_data(
            f'repos/{organization_name}/{repository_name}/branches',
            params={'protected': 'true'} if protected else None,
        )

    @api_call
    def get_branch(
        self,
        organization_name: str,
        repository_name: str,
        branch_name: str,
    ) -> Dict[str, Any]:
        """Get branch.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string
        - branch_name: a non-empty string

        # Returned value

        A _branch_.  A branch is a dictionary with the following
        entries:

        - name: a string
        - commit: a dictionary
        - protected: a boolean
        - protection: a dictionary
        - protetion_url: a string
        - pattern: a string
        - required_approving_review_count: an integer
        - _links: a dictionary
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')
        ensure_nonemptystring('branch_name')

        result = self._get(
            f'repos/{organization_name}/{repository_name}/branches/{branch_name}'
        )
        return result  # type: ignore

    ####################################################################
    # GitHub repository pull requests
    #
    # list_pullrequests
    # create_pullrequest
    # TODO get_pullrequest
    # is_pullrequest_merged
    # merge_pullrequest
    # update_pullrequest_branch

    @api_call
    def list_pullrequests(
        self,
        organization_name: str,
        repository_name: str,
        state: str = 'all',
    ) -> List[Dict[str, Any]]:
        """List pull requests.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string

        # Optional parameters

        - state: a string, one of `open`, `closed`, or `all` (`all` by
          default)

        # Returned value

        A list of _pull requests_.  Each pull request is a dictionary
        with the following entries:

        - url: a string
        - id: an integer
        - node_id: a string
        - html_url: a string
        - diff_url: a string
        - patch_url: a string
        - issue_url: a string
        - commits_url: a string
        - review_comments_url: a string
        - review_comment_url: a string
        - comments_url: a string
        - statuses_url: a string
        - number: an integer
        - state: a string
        - locked: a boolean
        - title: a string
        - user: a dictionary
        - body: a string
        - labels: a list of dictionaries
        - milestone: a dictionary,
        - active_lock_reason: a string
        - created_at: a string
        - updated_at: a string
        - closed_at: a string
        - merged_at: a string
        - merge_commit_sha: a string
        - assignee: a dictionary
        - assignees: a list of dictionaries
        - requested_reviewers: a list of dictionaries
        - requested_teams: a list of dictionaries
        - head: a dictionary
        - base: a dictionary
        - _links: a dictionary
        - author_association: a string
        - auto_merge: a dictionary or None
        - draft: a boolean

        `number` is the value you use to interact with the pull request.
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')
        ensure_in('state', ('open', 'closed', 'all'))

        return self._collect_data(
            f'repos/{organization_name}/{repository_name}/pulls',
            params={'state': state},
        )

    @api_call
    def create_pullrequest(
        self,
        organization_name: str,
        repository_name: str,
        head: str,
        base: str,
        title: Optional[str] = None,
        body: Optional[str] = None,
        maintainer_can_modify: bool = True,
        draft: bool = False,
        issue: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """List branches.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string
        - head: a non-empty string
        - base: a non-empty string
        - title: a non-empty string or None (None by default)
        - issue: an integer or None

        Either `title` or `issue` must be specified.

        # Optional parameters

        - body: a non-empty string or None (None by default)
        - maintainer_can_modify: a boolean (True by default)
        - draft: a boolean (False by default)

        # Returned value

        A _pull request_.  See #list_pullrequests for its description.
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')
        ensure_nonemptystring('head')
        ensure_nonemptystring('base')
        ensure_noneornonemptystring('title')
        ensure_noneornonemptystring('body')
        ensure_instance('maintainer_can_modify', bool)
        ensure_instance('draft', bool)
        ensure_noneorinstance('issue', int)
        ensure_onlyone('title', 'issue')

        data = {
            'head': head,
            'base': base,
            'maintainer_can_modify': maintainer_can_modify,
            'draft': draft,
        }
        add_if_specified(data, 'body', body)
        add_if_specified(data, 'title', title)
        add_if_specified(data, 'issue', issue)

        result = self._post(
            f'repos/{organization_name}/{repository_name}/pulls', json=data
        )
        return result  # type: ignore

    @api_call
    def is_pullrequest_merged(
        self, organization_name: str, repository_name: str, pull_number: int
    ) -> bool:
        """Check if pull request has been merged.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string
        - pull_number: an integer

        # Returned value

        A boolean.  True if the pull request has been merged, False
        otherwise.
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')
        ensure_instance('pull_number', int)
        return (
            self._get(
                f'repos/{organization_name}/{repository_name}/pulls/{pull_number}/merge'
            ).status_code
            == 204
        )

    @api_call
    def merge_pullrequest(
        self,
        organization_name: str,
        repository_name: str,
        pull_number: int,
        commit_title: Optional[str] = None,
        commit_message: Optional[str] = None,
        sha: Optional[str] = None,
        merge_method: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Merge pull request.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string
        - pull_number: an integer

        # Optional parameters

        - commit_title: a non-empty string or None (None by default)
        - commit_message: a non-empty string or None (None by default)
        - sha: a non-empty string or None (None by default)
        - merge_method: a string, one of `merge`, `squash`, `rebase`,
          or None (None by default)

        # Returned value

        A _pull request merge result_.  A pull request merge result is a
        dictionary with the following entries:

        - sha: a string
        - merged: a boolean
        - message: a string
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')
        ensure_instance('pull_number', int)
        ensure_noneornonemptystring('commit_title')
        ensure_noneornonemptystring('commit_message')
        ensure_noneornonemptystring('sha')
        ensure_noneornonemptystring('merge_method')

        if merge_method is not None:
            ensure_in('merge_method', ('merge', 'squash', 'rebase'))

        data = {}
        add_if_specified(data, 'commit_title', commit_title)
        add_if_specified(data, 'commit_message', commit_message)
        add_if_specified(data, 'sha', sha)
        add_if_specified(data, 'merge_method', merge_method)

        result = self._put(
            f'repos/{organization_name}/{repository_name}/pulls/{pull_number}/merge',
            json=data,
        )
        return result  # type: ignore

    @api_call
    def update_pullrequest_branch(
        self,
        organization_name: str,
        repository_name: str,
        pull_number: int,
        expected_head_sha: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update pull request branch with latest upstream changes.

        Update the pull request branch with the latest upstream changes
        by merging HEAD from the base branch into the pull request
        branch.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string
        - pull_number: an integer

        # Optional parameters

        - expected_head_sha: a non-empty string or None (None by
          default)

        # Returned value

        A dictionary with the following entries:

        - message: a string
        - url: a string
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')
        ensure_instance('pull_number', int)
        ensure_noneornonemptystring('expected_head_sha')

        data = (
            {'expected_head_sha': expected_head_sha}
            if expected_head_sha
            else None
        )
        result = self._put(
            f'repos/{organization_name}/{repository_name}/pulls/{pull_number}/update-branch',
            json=data,
        )
        return result  # type: ignore

    ####################################################################
    # GitHub repository git database
    #
    # create_repository_reference
    # delete_repository_reference
    # create_repository_tag
    # get_repository_reference
    # get_repository_references
    # get_repository_tree

    @api_call
    def create_repository_reference(
        self,
        organization_name: str,
        repository_name: str,
        ref: str,
        sha: str,
        key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a reference.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string
        - ref: a non-empty string (a fully-qualified reference, starting
          with `refs` and having at least two slashed)
        - sha: a non-empty string

        # Optional parameters

        - key: a string

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
        ensure_nonemptystring('ref')
        if not ref.startswith('refs/') or ref.count('/') < 2:
            raise ValueError(
                'ref must start with "refs" and contains at least two slashes.'
            )
        ensure_nonemptystring('sha')
        ensure_noneornonemptystring('key')

        data = {'ref': ref, 'sha': sha}
        add_if_specified(data, 'key', key)
        result = self._post(
            f'repos/{organization_name}/{repository_name}/git/refs', json=data
        )
        return result  # type: ignore

    @api_call
    def delete_repository_reference(
        self,
        organization_name: str,
        repository_name: str,
        ref: str,
    ) -> None:
        """Delete a reference.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string
        - ref: a non-empty string (a fully-qualified reference, starting
          with `refs` and having at least two slashed)

        # Returned value

        No content.
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')
        ensure_nonemptystring('ref')
        if not ref.startswith('refs/') or ref.count('/') < 2:
            raise ValueError(
                'ref must start with "refs" and contains at least two slashes.'
            )
        result = self._delete(
            f'repos/{organization_name}/{repository_name}/git/{ref}'
        )
        return result  # type: ignore

    @api_call
    def create_repository_tag(
        self,
        organization_name: str,
        repository_name: str,
        tag: str,
        message: str,
        object_: str,
        type_: str,
        tagger: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Create a tag.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string
        - tag: a non-empty string
        - message: a string
        - object_: a non-empty string
        - type_: a string

        # Optional parameters

        - tagger: a dictionary or None (None by default)

        # Returned value

        A _tag_.  A tag is a dictionary with the following entries:

        - node_id: a string
        - tag: a string
        - sha: a string
        - url: a string
        - message: a string
        - tagger: a dictionary
        - object: a dictionary
        - verification: a dictionary
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')
        ensure_nonemptystring('tag')
        ensure_instance('message', str)
        ensure_nonemptystring('object_')
        ensure_nonemptystring('type_')

        data = {
            'tag': tag,
            'message': message,
            'object': object_,
            'type': type_,
        }
        add_if_specified(data, 'tagger', tagger)
        result = self._post(
            f'repos/{organization_name}/{repository_name}/git/tags', json=data
        )
        return result  # type: ignore

    @api_call
    def get_repository_reference(
        self,
        organization_name: str,
        repository_name: str,
        ref: str,
    ) -> Dict[str, Any]:
        """Get a repository reference.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string
        - ref: a non-empty string (of form `heads/{branch}` or
          `tags/{tag}`)

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
        ensure_nonemptystring('ref')
        if not (ref.startswith('heads/') or ref.startswith('tags/')):
            raise ValueError('ref must start with "heads/" or "tags/".')

        result = self._get(
            f'repos/{organization_name}/{repository_name}/git/ref/{ref}',
        )
        return result  # type: ignore

    @api_call
    def get_repository_references(
        self,
        organization_name: str,
        repository_name: str,
        ref: str,
    ) -> Dict[str, Any]:
        """Get a repository references.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string
        - ref: a non-empty string (`heads` or `tags`)

        # Returned value

        A list of _references_.  A reference is a dictionary with the
        following entries:

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
        ensure_in('ref', ('heads', 'tags'))

        result = self._get(
            f'repos/{organization_name}/{repository_name}/git/refs/{ref}',
        )
        return result  # type: ignore

    @api_call
    def get_repository_tree(
        self,
        organization_name: str,
        repository_name: str,
        tree_sha: str,
        recursive: bool = False,
    ) -> Dict[str, Any]:
        """Get a tree.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string
        - tree_sha: a non-empty string (a SHA1)

        # Optional parameters

        - recursive: a boolean (False by default)

        # Returned value

        A _tree_.  A tree is a dictionary with the following keys:

        - sha: a string
        - url: a string
        - tree: a list of dictionaries
        - truncated: a boolean

        The `tree` elements have the following keys:

        - path: a string
        - mode: a string
        - type: a string
        - size: an integer
        - sha: a string
        - url: a string

        If `truncated` is `True`, the number of items in the `tree` list
        exceeds githubs' internal limits (100k entries with a maximum
        size of 7 MB).  If you need to fetch more items, use the
        non-recursive method of fetching trees, and fetch one sub-tree
        at a time.
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')
        ensure_nonemptystring('tree_sha')
        ensure_instance('recursive', bool)

        params = {'recursive': 'true'} if recursive else None
        headers = {'Accept': 'application/vnd.github+json'}
        result = self._get(
            f'repos/{organization_name}/{repository_name}/git/tree/{tree_sha}',
            params=params,
            headers=headers,
        )
        return result  # type: ignore

    ####################################################################
    # GitHub hook operations
    #
    # list_hooks
    # list_global_hooks
    # list_organization_hooks
    # get_organization_hook
    # create_hook
    # create_global_hook
    # create_organization_hook
    # delete_hook
    # delete_global_hook
    # delete_organization_hook
    # ping_hook
    # ping_global_hook
    # ping_organization_hook

    @api_call
    def list_hooks(
        self, organization_name: str, repository_name: str
    ) -> List[Dict[str, Any]]:
        """List webhooks for repository.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string

        # Returned value

        A list of _hooks_.  A hook is a dictionary with the following
        entries:

        - type: a string (`Repository`)
        - id: an integer
        - name: a string (always `web`)
        - active: a boolean
        - events: a list of strings
        - config: a dictionary
        - updated_at: a string (a timestamp)
        - created_at: a string (a timestamp)
        - url: a string
        - ping_url: a string
        - test_url: a a string
        - last_response: a dictionary

        `config` has the following entries:

        - insecure_ssl: a string
        - content_type: a string
        - url: a string

        `last_response` has the following entries:

        - message: a string or None
        - code: an integer
        - status: a string or None
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')

        result = self._collect_data(
            f'repos/{organization_name}/{repository_name}/hooks'
        )
        return result  # type: ignore

    @api_call
    def list_global_hooks(self) -> List[Dict[str, Any]]:
        """List global webhooks.

        # Returned value

        A list of _hooks_.  A hook is a dictionary with the following
        entries:

        - type: a string (`Global`)
        - id: an integer
        - name: a string (always `web`)
        - active: a boolean
        - events: a list of strings
        - config: a dictionary
        - updated_at: a string (a timestamp)
        - created_at: a string (a timestamp)
        - url: a string
        - test_url: a string

        `config` has the following entries:

        - url: a string
        - content_type: a string
        - insecure_ssl: a string
        - secret: a string
        """
        return self._collect_data('admin/hooks')

    @api_call
    def list_organization_hooks(
        self, organization_name: str
    ) -> List[Dict[str, Any]]:
        """List organization webhooks.

        # Required parameters

        - organization_name: a non-empty string

        # Returned value

        A list of _hooks_.  A hook is a dictionary with the following
        entries:

        - type: a string (`Organization`)
        - id: an integer
        - name: a string (always `web`)
        - active: a boolean
        - events: a list of strings
        - config: a dictionary
        - updated_at: a string (a timestamp)
        - created_at: a string (a timestamp)
        - url: a string
        - ping_url: a string
        - delivery_url: a string

        `config` has the following entries:

        - insecure_ssl: a string
        - content_type: a string
        - url: a string
        - secret: a string
        """
        ensure_nonemptystring('organization_name')

        return self._collect_data(f'orgs/{organization_name}/hooks')

    @api_call
    def get_organization_hook(
        self, organization_name: str, hook_id: int
    ) -> Dict[str, Any]:
        """Return an organization webhook.

        # Required parameters

        - organization_name: a non-empty string
        - hook_id: an integer

        # Returned value

        A _hook_.  See #list_organization_hooks() for its format.
        """
        ensure_nonemptystring('organization_name')
        ensure_instance('hook_id', int)

        result = self._get(f'orgs/{organization_name}/hooks/{hook_id}')
        return result  # type: ignore

    @api_call
    def create_hook(
        self,
        organization_name: str,
        repository_name: str,
        name: str,
        config: Dict[str, str],
        events: Optional[List[str]] = None,
        active: bool = True,
    ) -> Dict[str, Any]:
        """Create a webhook.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string
        - name: a string (must be `web`)
        - config: a dictionary

        The `config` dictionary must contain the following entry:

        - url: a string

        It may contain the following entries:

        - content_type: a string
        - secret: a string
        - insecure_ssl: a string

        # Optional parameters

        - events: a list of strings (`['push']` by default)
        - active: a boolean (True by default)

        # Returned value

        A _hook_.  See #list_hooks() for its format.
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')
        if name != 'web':
            raise ValueError('name must be "web".')
        ensure_instance('config', dict)
        ensure_noneorinstance('events', list)
        ensure_instance('active', bool)
        if 'url' not in config:
            raise ValueError('config must contain an "url" entry.')
        if events is None:
            events = ['push']

        data = {
            'name': name,
            'active': active,
            'config': config,
            'events': events,
        }

        result = self._post(
            f'repos/{organization_name}/{repository_name}/hooks', json=data
        )
        return result  # type: ignore

    @api_call
    def create_global_hook(
        self,
        name: str,
        config: Dict[str, str],
        events: Optional[List[str]] = None,
        active: bool = True,
    ) -> Dict[str, Any]:
        """Create a global webhook.

        # Required parameters

        - name: a string (must be `web`)
        - config: a dictionary

        The `config` dictionary must contain the following entry:

        - url: a string

        It may contain the following entries:

        - content_type: a string
        - secret: a string
        - insecure_ssl: a string

        # Optional parameters

        - events: a list of strings (`['user', 'organization']` by
          default)
        - active: a boolean (True by default)

        # Returned value

        A _hook_.  See #list_global_hooks() for its format.
        """
        if name != 'web':
            raise ValueError('name must be "web".')
        ensure_instance('config', dict)
        ensure_noneorinstance('events', list)
        ensure_instance('active', bool)
        if 'url' not in config:
            raise ValueError('config must contain an "url" entry.')
        if events is None:
            events = ['user', 'organization']

        data = {
            'name': name,
            'active': active,
            'config': config,
            'events': events,
        }

        result = self._post('admin/hooks', json=data)
        return result  # type: ignore

    @api_call
    def create_organization_hook(
        self,
        organization_name: str,
        name: str,
        config: Dict[str, str],
        events: Optional[List[str]] = None,
        active: bool = True,
    ) -> Dict[str, Any]:
        """Create an organization webhook.

        # Required parameters

        - organization_name: a non-empty string
        - name: a string (must be `web`)
        - config: a dictionary

        The `config` dictionary must contain the following entry:

        - url: a string

        It may contain the following entries:

        - content_type: a string
        - secret: a string
        - insecure_ssl: a string

        # Optional parameters

        - events: a list of strings (`['push']` by default)
        - active: a boolean (True by default)

        # Returned value

        A _hook_.  See #list_organization_hooks() for its format.
        """
        ensure_nonemptystring('organization_name')
        if name != 'web':
            raise ValueError('name must be "web".')
        ensure_instance('config', dict)
        ensure_noneorinstance('events', list)
        ensure_instance('active', bool)
        if 'url' not in config:
            raise ValueError('config must contain an "url" entry.')
        if events is None:
            events = ['push']

        data = {
            'name': name,
            'active': active,
            'config': config,
            'events': events,
        }

        result = self._post(f'orgs/{organization_name}/hooks', json=data)
        return result  # type: ignore

    @api_call
    def delete_hook(
        self, organization_name: str, repository_name: str, hook_id: int
    ) -> bool:
        """Delete a webhook.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string
        - hook_id: an integer

        # Returned value

        A boolean.  True when successful.
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')
        ensure_instance('hook_id', int)

        result = self._delete(
            f'repos/{organization_name}/{repository_name}/hooks/{hook_id}'
        )
        return result.status_code == 204

    @api_call
    def delete_global_hook(self, hook_id: int) -> bool:
        """Delete a global webhook.

        # Required parameters

        - hook_id: an integer

        # Returned value

        A boolean.  True when successful.
        """
        ensure_instance('hook_id', int)

        result = self._delete(f'admin/hooks/{hook_id}')
        return result.status_code == 204

    @api_call
    def delete_organization_hook(
        self, organization_name: str, hook_id: int
    ) -> bool:
        """Delete an organization webhook.

        # Required parameters

        - organization_name: a non-empty string
        - hook_id: an integer

        # Returned value

        A boolean.  True when successful.
        """
        ensure_nonemptystring('organization_name')
        ensure_instance('hook_id', int)

        result = self._delete(f'orgs/{organization_name}/hooks/{hook_id}')
        return result.status_code == 204

    @api_call
    def ping_hook(
        self, organization_name: str, repository_name: str, hook_id: int
    ) -> bool:
        """Ping a webhook.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string
        - hook_id: an integer

        # Returned value

        A boolean.  True when successful.
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')
        ensure_instance('hook_id', int)

        result = self._post(
            f'repos/{organization_name}/{repository_name}/hooks/{hook_id}/pings'
        )
        return result.status_code == 204

    @api_call
    def ping_global_hook(self, hook_id: int) -> bool:
        """Ping a global webhook.

        # Required parameters

        - hook_id: an integer

        # Returned value

        A boolean.  True when successful.
        """
        ensure_instance('hook_id', int)

        result = self._post(f'admin/hooks/{hook_id}/pings')
        return result.status_code == 204

    @api_call
    def ping_organization_hook(
        self, organization_name: str, hook_id: int
    ) -> bool:
        """Ping an organization webhook.

        # Required parameters

        - organization_name: a non-empty string
        - hook_id: an integer

        # Returned value

        A boolean.  True when successful.
        """
        ensure_nonemptystring('organization_name')
        ensure_instance('hook_id', int)

        result = self._post(f'orgs/{organization_name}/hooks/{hook_id}/pings')
        return result.status_code == 204

    ####################################################################
    # GitHub license (Enterprise cloud)
    #
    # get_consumed_licenses

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
        response = self.session().get(
            join_url(
                self.url,
                f'enterprises/{enterprise_name}/consumed-licenses',
            )
        )

        data = response.json()
        return {
            'total_seats_consumed': data['total_seats_consumed'],
            'total_seats_purchased': data['total_seats_purchased'],
        }

    ####################################################################
    # GitHub copilot (Enterprise cloud)
    #
    # get_copilot_billing
    # get_copilot_billing_seats
    # add_copilot_users
    # remove_copilot_users

    @api_call
    def get_copilot_billing(self, organization_name: str) -> Dict[str, Any]:
        """Get billing information for organization.

        Can only be used on a GitHub Enterprise Cloud instance.

        # Required parameters

        - organization_name: a non-empty string

        # Returned value

        A _billing information_ dictionary with the following entries:

        - seat_breakdown: a dictionary
        - seat_management_settings: a string
        - public_code_suggestions: a string

        The `seat_breakdown` dictionary has the following entries:

        - total: an integer
        - added_this_cycle: an integer
        - pending_invitation: an integer
        - pending_cancellation: an integer
        - active_this_cycle: an integer
        - inactive_this_cycle: an integer
        """
        ensure_nonemptystring('organization_name')

        result = self._get(f'orgs/{organization_name}/copilot/billing')
        return result  # type: ignore

    @api_call
    def get_copilot_billing_seats(
        self, organization_name: str
    ) -> List[Dict[str, Any]]:
        """Get billing seats for organization.

        Can only be used on a GitHub Enterprise Cloud instance.

        # Required parameters

        - organization_name: a non-empty string

        # Returned value

        A list of _seats_.  A seat is a dictionary with the following
        entries:

        - created_at: a string (a timestamp)
        - assignee: a dictionary
        - updated_at: a string (a timestamp)
        - pending_cancellation_date: a string (a timestamp)
        - last_activity_at: a string (a timestamp)
        - last_activity_editor: a string
        """
        ensure_nonemptystring('organization_name')

        result = self._get(
            f'orgs/{organization_name}/copilot/billing/seats'
        ).json()
        return result.get('seats', [])  # type: ignore

    @api_call
    def add_copilot_users(
        self, organization_name: str, users: List[str]
    ) -> List[Dict[str, Any]]:
        """Add users to copilot.

        Can only be used on a GitHub Enterprise Cloud instance.

        # Required parameters

        - organization_name: a non-empty string
        - users: a list of non-empty strings

        # Returned value

        A dictionary with a `seats_created` entry.
        """
        ensure_nonemptystring('organization_name')
        ensure_instance('users', list)
        for user in users:
            ensure_nonemptystring(user)

        data = {'selected_usernames': users}
        result = self._post(
            f'orgs/{organization_name}/copilot/billing/selected_users',
            json=data,
        )
        return result  # type: ignore

    @api_call
    def remove_copilot_users(
        self, organization_name: str, users: List[str]
    ) -> List[Dict[str, Any]]:
        """Remove users from copilot.

        Can only be used on a GitHub Enterprise Cloud instance.

        # Required parameters

        - organization_name: a non-empty string
        - users: a list of non-empty strings

        # Returned value

        A dictionary with a `seats_cancelled` entry.
        """
        ensure_nonemptystring('organization_name')
        ensure_instance('users', list)
        for user in users:
            ensure_nonemptystring(user)

        data = {'selected_usernames': users}
        result = self._delete(
            f'orgs/{organization_name}/copilot/billing/selected_users',
            json=data,
        )
        return result  # type: ignore

    ####################################################################
    # GitHub misc. operations
    #
    # get_server_version
    # get_admin_stats

    @api_call
    def get_server_version(self) -> None:
        """Return current GitHub version.

        !!! warning
            Not implemented yet.
        """

    @api_call
    def get_admin_stats(self, what: str = 'all') -> Dict[str, Any]:
        """Return admin stats.

        # Optional parameters

        - what: a string (`all` by default)

        `what` can be `all`, `comments`, `gists`, `hooks`, `issues`,
        `milestones`, `orgs`, `pages`, `pulls`, `repos`,
        `security-products`, or `users`.

        Requires sysadmin rights.

        # Returned value

        A dictionary with either one entry (if `what` is not `all`)
        or one entry per item.

        Values are dictionaries.
        """
        ensure_nonemptystring('what')

        return self._get(f'enterprise/stats/{what}')  # type: ignore

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

    def _patch(
        self,
        api: str,
        json: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> requests.Response:
        api_url = join_url(self.url, api)
        return self.session().patch(api_url, json=json, headers=headers)
