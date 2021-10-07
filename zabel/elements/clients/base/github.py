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

from typing import Any, Dict, Iterable, List, Mapping, Optional, Union

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
    join_url,
)


########################################################################
########################################################################

# GitHub low-level api


class GitHub:
    """GitHub Low-Level Wrapper.

    # Reference URL

    - <https://developer.github.com/v3/>
    - <https://developer.github.com/enterprise/2.20/v3>
    - <https://stackoverflow.com/questions/10625190>

    # Implemented features

    - users
    - organizations
    - repositories
    - hooks
    - misc. operations (version, staff reports & stats)

    # Sample use

    ```python
    # standard use
    from zabel.elements.clients import GitHub

    url = 'https://github.example.com/api/v3/'
    gh = GitHub(url, user, token)
    gh.list_users()

    # enabling management features
    from zabel.elements import clients

    mngt = 'https://github.example.com/'
    gh = clients.GitHub(url, user, token, mngt)
    gh.create_organization('my_organization', 'admin')
    ```
    """

    def __init__(
        self,
        url: str,
        user: str,
        token: str,
        management_url: Optional[str] = None,
        verify: bool = True,
    ) -> None:
        """Create a GitHub instance object.

        The optional `management_url` is only required if
        'enterprise' features are used (staff reports, ...).

        # Required parameters

        - url: a non-empty string
        - user: a string
        - token: a string

        # Optional parameters

        - management_url: a non-empty string or None (None by
          default)
        - verify: a boolean (True by default)

        `verify` can be set to False if disabling certificate checks for
        GitHub communication is required.  Tons of warnings will occur
        if this is set to False.
        """
        ensure_nonemptystring('url')
        ensure_instance('user', str)
        ensure_instance('token', str)
        ensure_noneornonemptystring('management_url')

        self.url = url
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
    # TODO update_user
    # TODO get_user_organizations
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
        - created_at: a string representing a datetime
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
    # list_organization_teams
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
        self, login: str, admin: str, profile_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create GitHub organization.

        # Required parameters

        - login: a non-empty string
        - admin: a non-empty string

        # Optional parameters

        - profile_name: a string or None (None by default)

        # Returned value

        A dictionary.
        """
        ensure_nonemptystring('login')
        ensure_nonemptystring('admin')
        ensure_noneorinstance('profile_name', str)

        data = {'login': login, 'admin': admin}
        add_if_specified(data, 'profile_name', profile_name)

        result = self._post('admin/organizations', json=data)
        return result  # type: ignore

    @api_call
    def list_organization_members(
        self, login: str, role: str = 'all'
    ) -> List[Dict[str, Any]]:
        """Return the list of organization members.

        # Required parameters

        - login: a non-empty string

        # Optional parameters

        - role: a non-empty string, one of 'all', 'member', or 'admin'
          ('all' by default)

        # Returned value

        A list of _members_.  Each member is a dictionary.
        """
        ensure_nonemptystring('login')
        ensure_in('role', ('all', 'member', 'admin'))

        return self._collect_data(
            f'orgs/{login}/members', params={'role': role}
        )

    @api_call
    def list_organization_outsidecollaborators(
        self, login: str
    ) -> List[Dict[str, Any]]:
        """Return the list of organization outside collaborators.

        # Required parameters

        - login: a non-empty string

        # Returned value

        A list of _members_ (outside collaborators).  Each member is a
        dictionary.
        """
        ensure_nonemptystring('login')

        return self._collect_data(f'orgs/{login}/outside_collaborators')

    @api_call
    def get_organization_membership(
        self, login: str, user: str
    ) -> Dict[str, Any]:
        """Get organization membership.

        # Required parameters

        - login: a non-empty string
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
        ensure_nonemptystring('login')
        ensure_nonemptystring('user')

        return self._get(f'orgs/{login}/memberships/{user}')  # type: ignore

    @api_call
    def add_organization_membership(
        self, login: str, user: str, role: str = 'member'
    ) -> Dict[str, Any]:
        """Add or update organization membership.

        # Required parameters

        - login: a non-empty string
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

        Refer to #list_organizations() and #list_users() for more details
        on `organization` and `user` content.
        """
        ensure_nonemptystring('login')
        ensure_nonemptystring('user')
        ensure_in('role', ['member', 'admin'])

        result = self._put(
            f'orgs/{login}/memberships/{user}', json={'role': role}
        )
        return result  # type: ignore

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

        return self._get(f'orgs/{organization_name}/teams/{team_name}/members')

    ####################################################################
    # GitHub repositories
    #
    # repository name = name key
    #
    # list_repositories
    # list_public_repositories
    # get_repository
    # create_repository
    # TODO update_repository
    # TODO delete_repository
    # list_repository_commits
    # get_repository_commit
    # list_reporitory_teams
    # list_repository_collaborators

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

        A dictionary. See #list_repositories() for its description.
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')

        return self._get(f'repos/{organization_name}/{repository_name}')  # type: ignore

    @api_call
    def create_repository(
        self,
        organization_name: str,
        repository_name: str,
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
        """Create a new repository in organization organization_name.

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

        A dictionary.  See #list_repositories() for its content.
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
        sha: Optional['str'] = None,
        path: Optional['str'] = None,
        author: Optional['str'] = None,
        since: Optional['str'] = None,
        until: Optional['str'] = None,
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

        A list of dictionaries.
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
        """Return a specific commit."""
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
            except:
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
        - commiter: a dictionary or None (None by default)
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
        - commiter: a dictionary or None (None by default)
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
    # GitHub git database API
    #
    # create_repository_tag
    # create_repository_ref

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
    def create_repository_ref(
        self, organization_name: str, repository_name: str, ref: str, sha: str
    ) -> Dict[str, Any]:
        """Create a reference.

        # Required parameters

        - ref: a non-empty string
        - sha: a non-empty string

        # Returned value

        A _reference_.  A reference is a dictionary with the following
        entries:

        - node_id: a string
        - ref: a string
        - url: a string
        - object: a dictionary
        """
        ensure_nonemptystring('ref')
        ensure_nonemptystring('sha')

        result = self._post(
            f'repos/{organization_name}/{repository_name}/git/refs',
            json={'ref': ref, 'sha': sha},
        )
        return result  # type: ignore

    ####################################################################
    # GitHub hook operations
    #
    # list_hooks
    # create_hook
    # delete_hook

    @api_call
    def list_hooks(
        self, organization_name: str, repository_name: str
    ) -> Dict[str, Any]:
        """Return the list of hooks for repository.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string

        # Returned value

        A list of _hooks_.  A hook is a dictionary with the following
        entries:

        - active: a boolean
        - config: a dictionary
        - created_at: a string (a timestamp)
        - events: a list of strings
        - id: an integer
        - last_response: a dictionary
        - name: a string (always `'web'`)
        - ping_url: a string
        - test_url: a a string
        - type: a string
        - updated_at: a string (a timestamp)
        - url: a string

        `config` has the following entries:

        - insecure_ssl: a string
        - content_type: a string
        - url: a string

        `last_response` has the following entries:

        - message: a string
        - code: an integer
        - status: a string
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')

        result = self._get(
            f'repos/{organization_name}/{repository_name}/hooks'
        )
        return result  # type: ignore

    @api_call
    def create_hook(
        self,
        organization_name: str,
        repository_name: str,
        name: str,
        config: Dict[str, str],
        events: List[str] = ['push'],
        active: bool = True,
    ) -> Dict[str, Any]:
        """Create a webhook.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string
        - name: a string (must be `'web'`)
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

        A dictionary.  See #list_hooks() for its format.
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')
        if name != 'web':
            raise ValueError('name must be "web".')
        ensure_instance('config', dict)
        ensure_instance('events', list)
        ensure_instance('active', bool)
        if 'url' not in config:
            raise ValueError('config must contain an "url" entry.')

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

        - what: a string (`'all'` by default)

        `what` can be `'issues'`, `'hooks'`, `'milestones'`, `'orgs'`,
        `'comments'`, `'pages'`, `'users'`, `'gists'`, `'pulls'`,
        `'repos'` or `'all'`.

        Requires sysadmin rights.

        # Returned value

        A dictionary with either one entry (if `what` is not `'all'`)
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
        more = True
        while more:
            response = self.session().get(
                api_url, params=params, headers=headers
            )
            if response.status_code // 100 != 2:
                raise ApiError(response.text)
            try:
                collected += response.json()
            except Exception as exception:
                raise ApiError(exception)
            more = 'next' in response.links
            if more:
                api_url = response.links['next']['url']

        return collected

    def _post(
        self, api: str, json: Optional[Mapping[str, Any]] = None
    ) -> requests.Response:
        api_url = join_url(self.url, api)
        return self.session().post(api_url, json=json)

    def _put(
        self,
        api: str,
        json: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> requests.Response:
        api_url = join_url(self.url, api)
        return self.session().put(api_url, json=json, headers=headers)

    def _delete(self, api: str) -> requests.Response:
        api_url = join_url(self.url, api)
        return self.session().delete(api_url)
