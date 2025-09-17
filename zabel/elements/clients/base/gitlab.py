# Copyright (c) 2025 Martin Lafaix (mlafaix@henix.com)
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

"""GitLab.

A class wrapping GitLab APIs.

There can be as many GitLab instances as needed.

This module depends on the **python-gitlab** public library.  It also
depends on three **zabel-commons** modules, #::zabel.commons.exceptions,
#::zabel.commons.sessions, and #::zabel.commons.utils.
"""

from typing import Any, Dict, List, Optional, Union

from zabel.commons.utils import (
    api_call,
    ensure_in,
    ensure_instance,
    ensure_nonemptystring,
    ensure_noneorinstance,
    ensure_onlyone,
)


########################################################################
########################################################################

# GitLab low-level API

ISSUES_STATE = ('all', 'opened', 'closed')
MR_STATE = ('all', 'opened', 'closed', 'merged', 'locked')
MILESTONES_STATE = ('all', 'active', 'closed')
ITERATIONS_STATE = ('opened', 'upcoming', 'current', 'closed', 'all')
PIPELINES_STATUSES = (
    'created',
    'waiting_for_resource',
    'preparing',
    'pending',
    'running',
    'success',
    'failed',
    'canceled',
    'skipped',
    'manual',
    'scheduled',
)


def _expand(items: Any) -> List[Dict[str, Any]]:
    """Expand a list of items into a list of dictionaries."""
    return [item.asdict() for item in items]


class GitLab:
    """GitLab Low-Level Wrapper.

    !!! note
        Reuse the **python-gitlab** library whenever possible, but
        always returns 'raw' values (dictionaries, ..., not classes).

    ## Reference URLs

    - <https://docs.gitlab.com/api/rest/>
    - <https://docs.gitlab.com/api/api_resources/>
    - <https://python-gitlab.readthedocs.io/en/stable/>

    ## Implemented features

    - namespaces
    - groups
    - projects
    - members

    ## Examples

    ```python
    # standard use
    from zabel.elements.clients import GitLab

    url = 'https://gitlab.com/'
    token = '...'
    gl = GitLab(url, private_token=token)
    gl.list_project_protectedbranches()
    ```
    """

    def __init__(
        self,
        url: str,
        *,
        private_token: Optional[str] = None,
        oauth_token: Optional[str] = None,
        job_token: Optional[str] = None,
        verify: Union[bool, str] = True,
    ) -> None:
        """Create a GitLab instance object.

        You can only specify either `private_token`, `oauth_token`, or
        `job_token`.

        # Required parameters

        - url: a non-empty string

        and one of

        - private_token: a non-empty string or None (None by default)
        - oauth_token: a non-empty string or None (None by default)
        - job_token: a non-empty string or None (None by default)

        # Optional parameters

        - verify: a boolean or string

        # Usage

        `url ` is the GitLab instance URL.  For example, if you are
        using the public `gitlab.com` instance:

            'https://gitlab.com/'

        `verify` can be set to False if disabling certificate checks for
        GitLab communication is required.  Tons of warnings will occur
        if this is set to False.
        """
        ensure_nonemptystring('url')
        ensure_noneorinstance('private_token', str)
        ensure_noneorinstance('oauth_token', str)
        ensure_noneorinstance('job_token', str)
        ensure_onlyone('private_token', 'oauth_token', 'job_token')
        ensure_instance('verify', (bool, str))

        self.url = url
        self.private_token = private_token
        self.oauth_token = oauth_token
        self.job_token = job_token

        self.client = None
        self.verify = verify

    def __str__(self) -> str:
        return f'{self.__class__.__name__}: {self.url}'

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__}: {self.url!r}>'

    def _client(self) -> 'gitlab.Gitlab':
        """Return a GitLab client."""
        if self.client is None:
            from gitlab import Gitlab

            self.client = Gitlab(
                url=self.url,
                private_token=self.private_token,
                oauth_token=self.oauth_token,
                job_token=self.job_token,
                ssl_verify=self.verify,
            )
        return self.client

    ####################################################################
    # GitLab member roles (self hosted only)
    #
    # list_memberroles

    @api_call
    def list_memberroles(self) -> List[Dict[str, Any]]:
        """List all available member roles.

        # Returned value

        A list of _memberroles_.
        """
        roles = self._client().member_roles.list(iterator=True)
        return [role.asdict() for role in roles]

    ####################################################################
    # GitLab namespaces (users or groups)
    #
    # list_namespaces
    # get_namespace
    # is_namespace_available

    @api_call
    def list_namespaces(self):
        """List all available namespaces."""
        return _expand(self._client().namespaces.list(iterator=True))

    @api_call
    def get_namespace(self, name: str) -> Dict[str, Any]:
        """Return the namespace details.

        # Required parameters

        - name: a non-empty string

        # Returned value

        A _namespace_ dictionary.  The namespace's `kind` entry may be
        either `'user'` or `'group'`.
        """
        ensure_nonemptystring('name')

        return self._client().namespaces.get(name).asdict()

    @api_call
    def is_namespace_available(self, name: str) -> bool:
        """Check if a namespace is available.

        # Required parameters

        - name: a non-empty string

        # Returned value

        A boolean indicating whether the namespace is available.
        """
        ensure_nonemptystring('name')

        return self._client().namespaces.exists(name).exists

    ####################################################################
    # GitLab groups
    #
    # list_group_boards
    # list_group_directmembers
    # list_group_epics
    # list_group_issues
    # list_group_iterations
    # list_group_memberroles
    # list_group_members
    # list_group_mergerequests
    # list_group_milestones
    # list_group_projects
    # list_group_releases
    # list_group_subgroups

    @api_call
    def list_group_projects(
        self, group_name_or_id: Union[str, int]
    ) -> List[Dict[str, Any]]:
        """List all projects in a group.

        # Required parameters

        - group_name_or_id: a non-empty string or an integer

        # Returned value

        A list of _projects_.
        """
        if isinstance(group_name_or_id, str):
            ensure_nonemptystring('group_name_or_id')
        else:
            ensure_instance('group_name_or_id', int)

        group = self._group(group_name_or_id)

        return _expand(group.projects.list(iterator=True))

    @api_call
    def list_group_subgroups(
        self, group_name_or_id: Union[str, int]
    ) -> List[Dict[str, Any]]:
        """List all direct subgroups in a group.

        # Required parameters

        - group_name_or_id: a non-empty string or an integer

        # Returned value

        A list of _groups_.
        """
        if isinstance(group_name_or_id, str):
            ensure_nonemptystring('group_name_or_id')
        else:
            ensure_instance('group_name_or_id', int)

        group = self._group(group_name_or_id)

        return _expand(group.subgroups.list(iterator=True))

    @api_call
    def list_group_milestones(
        self,
        group_name_or_id: Union[str, int],
        *,
        state: str = 'all',
        **filter,
    ) -> List[Dict[str, Any]]:
        """List group milestones.

        # Required parameters

        - group_name_or_id: a non-empty string or an integer

        # Optional parameters

        - state: a string (default: `'all'`)
        - filter: additional filters

        # Returned value

        A list of _milestones_.
        """
        if isinstance(group_name_or_id, str):
            ensure_nonemptystring('group_name_or_id')
        else:
            ensure_instance('group_name_or_id', int)
        ensure_in('state', MILESTONES_STATE)

        group = self._group(group_name_or_id)
        extra = filter or {}

        return _expand(
            group.milestones.list(iterator=True, state=state, **extra)
        )

    @api_call
    def list_group_boards(
        self,
        group_name_or_id: Union[str, int],
        *,
        state: str = 'all',
        **filter,
    ) -> List[Dict[str, Any]]:
        """List group boards.

        # Required parameters

        - group_name_or_id: a non-empty string or an integer

        # Optional parameters

        - state: a string (default: `'all'`)
        - filter: additional filters

        # Returned value

        A list of _boards_.
        """
        if isinstance(group_name_or_id, str):
            ensure_nonemptystring('group_name_or_id')
        else:
            ensure_instance('group_name_or_id', int)
        ensure_in('state', MILESTONES_STATE)

        group = self._group(group_name_or_id)
        extra = filter or {}

        return _expand(group.boards.list(iterator=True, state=state, **extra))

    @api_call
    def list_group_iterations(
        self,
        group_name_or_id: Union[str, int],
        *,
        state: str = 'all',
        **filter,
    ) -> List[Dict[str, Any]]:
        """List group iterations.

        # Required parameters

        - group_name_or_id: a non-empty string or an integer

        # Optional parameters

        - state: a string (default: `'all'`)
        - filter: additional filters

        # Returned value

        A list of _iterations_.
        """
        if isinstance(group_name_or_id, str):
            ensure_nonemptystring('group_name_or_id')
        else:
            ensure_instance('group_name_or_id', int)
        ensure_in('state', ITERATIONS_STATE)

        group = self._group(group_name_or_id)
        extra = filter or {}

        return _expand(
            group.iterations.list(iterator=True, state=state, **extra)
        )

    @api_call
    def list_group_issues(
        self,
        group_name_or_id: Union[str, int],
        *,
        state: str = 'all',
        **filter,
    ) -> List[Dict[str, Any]]:
        """List all issues in a group.

        # Required parameters

        - group_name_or_id: a non-empty string or an integer

        # Optional parameters

        - state: a string (default: `'all'`)
        - filter: additional filters

        # Returned value

        A list of _issues_.
        """
        if isinstance(group_name_or_id, str):
            ensure_nonemptystring('group_name_or_id')
        else:
            ensure_instance('group_name_or_id', int)
        ensure_in('state', ISSUES_STATE)

        group = self._group(group_name_or_id)
        extra = filter or {}

        return _expand(group.issues.list(iterator=True, state=state, **extra))

    @api_call
    def list_group_epics(
        self,
        group_name_or_id: Union[str, int],
        *,
        state: str = 'opened',
        **filter,
    ) -> List[Dict[str, Any]]:
        """List all epics in a group.

        # Required parameters

        - group_name_or_id: a non-empty string or an integer

        # Optional parameters

        - state: a string (default: `'opened'`)
        - filter: additional filters

        # Returned value

        A list of _epics_.
        """
        if isinstance(group_name_or_id, str):
            ensure_nonemptystring('group_name_or_id')
        else:
            ensure_instance('group_name_or_id', int)
        ensure_in('state', ISSUES_STATE)

        group = self._group(group_name_or_id)
        extra = filter or {}

        return _expand(group.epics.list(iterator=True, state=state, **extra))

    @api_call
    def list_group_mergerequests(
        self,
        group_name_or_id: Union[str, int],
        *,
        state: str = 'opened',
        **filter,
    ) -> List[Dict[str, Any]]:
        """List all merge requests in a group.

        # Required parameters

        - group_name_or_id: a non-empty string or an integer

        # Optional parameters

        - state: a string (default: `'opened'`)
        - filter: additional filters

        # Returned value

        A list of _merge requests_.
        """
        if isinstance(group_name_or_id, str):
            ensure_nonemptystring('group_name_or_id')
        else:
            ensure_instance('group_name_or_id', int)
        ensure_in('state', MR_STATE)

        group = self._group(group_name_or_id)
        extra = filter or {}

        return _expand(
            group.mergerequests.list(iterator=True, state=state, **extra)
        )

    @api_call
    def list_group_directmembers(
        self,
        group_name_or_id: Union[str, int],
        **filter: Any,
    ) -> List[Dict[str, Any]]:
        """List all direct members in a group.

        # Required parameters

        - group_name_or_id: a non-empty string or an integer

        # Optional parameters

        - filter: additional filters

        # Returned value

        A list of _members_.
        """
        if isinstance(group_name_or_id, str):
            ensure_nonemptystring('group_name_or_id')
        else:
            ensure_instance('group_name_or_id', int)

        group = self._group(group_name_or_id)
        extra = filter or {}

        return _expand(group.members.list(iterator=True, **extra))

    @api_call
    def list_group_members(
        self,
        group_name_or_id: Union[str, int],
        **filter: Any,
    ) -> List[Dict[str, Any]]:
        """List all members in a group.

        # Required parameters

        - group_name_or_id: a non-empty string or an integer

        # Optional parameters

        - filter: additional filters

        # Returned value

        A list of _members_.
        """
        if isinstance(group_name_or_id, str):
            ensure_nonemptystring('group_name_or_id')
        else:
            ensure_instance('group_name_or_id', int)

        group = self._group(group_name_or_id)
        extra = filter or {}

        return _expand(group.members_all.list(iterator=True, **extra))

    @api_call
    def list_group_memberroles(
        self,
        group_name_or_id: Union[str, int],
        **filter,
    ) -> List[Dict[str, Any]]:
        """List all member roles in a group.

        # Required parameters

        - group_name_or_id: a non-empty string or an integer

        # Optional parameters

        - filter: additional filters

        # Returned value

        A list of _member roles_.
        """
        if isinstance(group_name_or_id, str):
            ensure_nonemptystring('group_name_or_id')
        else:
            ensure_instance('group_name_or_id', int)

        group = self._group(group_name_or_id)
        extra = filter or {}

        return _expand(group.member_roles.list(iterator=True, **extra))

    @api_call
    def list_group_releases(
        self,
        group_name_or_id: Union[str, int],
        **filter,
    ) -> List[Dict[str, Any]]:
        """List all releases in a group.

        # Required parameters

        - group_name_or_id: a non-empty string or an integer

        # Optional parameters

        - filter: additional filters

        # Returned value

        A list of _releases_.
        """
        if isinstance(group_name_or_id, str):
            ensure_nonemptystring('group_name_or_id')
        else:
            ensure_instance('group_name_or_id', int)

        group = self._group(group_name_or_id)
        extra = filter or {}

        return _expand(group.releases.list(iterator=True, **extra))

    ####################################################################
    # GitLab projects
    #
    # get_project
    # get_project_pages
    # list_project_boards
    # list_project_branches
    # list_project_commits
    # list_project_directmembers
    # list_project_issues
    # list_project_iterations
    # list_project_members
    # list_project_mergerequests
    # list_project_milestones
    # list_project_packages
    # list_project_pipelines
    # list_project_protectedbranches
    # list_project_releases
    # list_project_tags

    @api_call
    def get_project(
        self, project_name_or_id: Union[str, int]
    ) -> Dict[str, Any]:
        """Return a project's details.

        # Required parameters

        - project_name_or_id: a non-empty string or an integer

        # Returned value

        A _project_ dictionary.
        """
        if isinstance(project_name_or_id, str):
            ensure_nonemptystring('project_name_or_id')
        else:
            ensure_instance('project_name_or_id', int)

        project = self._project(project_name_or_id)

        return project.asdict()

    @api_call
    def get_project_pages(
        self, project_name_or_id: Union[str, int]
    ) -> Dict[str, Any]:
        """Return a project's pages details.

        # Required parameters

        - project_name_or_id: a non-empty string or an integer

        # Returned value

        A _pages_ dictionary.
        """
        if isinstance(project_name_or_id, str):
            ensure_nonemptystring('project_name_or_id')
        else:
            ensure_instance('project_name_or_id', int)

        project = self._project(project_name_or_id)

        return project.pages.get().asdict()

    @api_call
    def list_project_pipelines(
        self,
        project_name_or_id: Union[str, int],
        *,
        status: Optional[str] = None,
        **filter,
    ) -> List[Dict[str, Any]]:
        """List all pipelines in a project.

        # Required parameters

        - project_name_or_id: a non-empty string or an integer

        # Optional parameters

        - status: a string or None (None by default)
        - filter: additional filters

        # Returned value

        A list of _pipelines_.
        """
        if isinstance(project_name_or_id, str):
            ensure_nonemptystring('project_name_or_id')
        else:
            ensure_instance('project_name_or_id', int)
        ensure_noneorinstance('status', str)
        if status:
            ensure_in('status', PIPELINES_STATUSES)

        project = self._project(project_name_or_id)
        extra = filter or {}

        return _expand(
            project.pipelines.list(iterator=True, status=status, **extra)
        )

    @api_call
    def list_project_tags(
        self,
        project_name_or_id: Union[str, int],
        **filter,
    ) -> List[Dict[str, Any]]:
        """List repository tags in a project.

        # Required parameters

        - project_name_or_id: a non-empty string or an integer

        # Optional parameters

        - filter: additional filters

        # Returned value

        A list of _tags_.
        """
        if isinstance(project_name_or_id, str):
            ensure_nonemptystring('project_name_or_id')
        else:
            ensure_instance('project_name_or_id', int)

        project = self._project(project_name_or_id)
        extra = filter or {}

        return _expand(project.tags.list(iterator=True, **extra))

    @api_call
    def list_project_commits(
        self,
        project_name_or_id: Union[str, int],
        **filter,
    ) -> List[Dict[str, Any]]:
        """List repository commits in a project.

        !!! note
            It is recommended to specify a filter (for example `since`
            and/or `until`), to limit the number of returned commits.

        # Required parameters

        - project_name_or_id: a non-empty string or an integer

        # Optional parameters

        - filter: additional filters

        # Returned value

        A list of _commits_.
        """
        if isinstance(project_name_or_id, str):
            ensure_nonemptystring('project_name_or_id')
        else:
            ensure_instance('project_name_or_id', int)

        project = self._project(project_name_or_id)
        extra = filter or {}

        return _expand(project.commits.list(iterator=True, **extra))

    @api_call
    def list_project_packages(
        self, project_name_or_id: Union[str, int], **filter
    ) -> List[Dict[str, Any]]:
        """List all packages in a project.

        # Required parameters

        - project_name_or_id: a non-empty string or an integer

        # Optional parameters

        - filter: additional filters

        # Returned value

        A list of _packages_.
        """
        if isinstance(project_name_or_id, str):
            ensure_nonemptystring('project_name_or_id')
        else:
            ensure_instance('project_name_or_id', int)

        project = self._project(project_name_or_id)
        extra = filter or {}

        return _expand(project.packages.list(iterator=True, **extra))

    @api_call
    def list_project_issues(
        self,
        project_name_or_id: Union[str, int],
        *,
        state: str = 'opened',
        **filter,
    ) -> List[Dict[str, Any]]:
        """List all issues in a project.

        # Required parameters

        - project_name_or_id: a non-empty string or an integer

        # Optional parameters

        - state: a string (default: `'opened'`)
        - filter: additional filters

        # Returned value

        A list of _issues_.
        """
        if isinstance(project_name_or_id, str):
            ensure_nonemptystring('project_name_or_id')
        else:
            ensure_instance('project_name_or_id', int)
        ensure_in('state', ISSUES_STATE)

        project = self._project(project_name_or_id)
        extra = filter or {}

        return _expand(
            project.issues.list(iterator=True, state=state, **extra)
        )

    @api_call
    def list_project_milestones(
        self,
        project_name_or_id: Union[str, int],
        *,
        state: str = 'active',
        **filter,
    ) -> List[Dict[str, Any]]:
        """List project milestones.

        # Required parameters

        - project_name_or_id: a non-empty string or an integer

        # Optional parameters

        - state: a string (default: `'all'`)
        - filter: additional filters

        # Returned value

        A list of _milestones_.
        """
        if isinstance(project_name_or_id, str):
            ensure_nonemptystring('project_name_or_id')
        else:
            ensure_instance('project_name_or_id', int)
        ensure_in('state', MILESTONES_STATE)

        project = self._project(project_name_or_id)
        extra = filter or {}

        return _expand(
            project.milestones.list(iterator=True, state=state, **extra)
        )

    @api_call
    def list_project_iterations(
        self,
        project_name_or_id: Union[str, int],
        *,
        state: str = 'all',
        **filter,
    ) -> List[Dict[str, Any]]:
        """List project iterations.

        # Required parameters

        - project_name_or_id: a non-empty string or an integer

        # Optional parameters

        - state: a string (default: `'all'`)
        - filter: additional filters

        # Returned value

        A list of _iterations_.
        """
        if isinstance(project_name_or_id, str):
            ensure_nonemptystring('project_name_or_id')
        else:
            ensure_instance('project_name_or_id', int)
        ensure_in('state', ITERATIONS_STATE)

        project = self._project(project_name_or_id)
        extra = filter or {}

        return _expand(
            project.iterations.list(iterator=True, state=state, **extra)
        )

    @api_call
    def list_project_boards(
        self, project_name_or_id: Union[str, int], **filter
    ) -> List[Dict[str, Any]]:
        """List project boards.

        # Required parameters

        - project_name_or_id: a non-empty string or an integer

        # Optional parameters

        - filter: additional filters

        # Returned value

        A list of _boards_.
        """
        if isinstance(project_name_or_id, str):
            ensure_nonemptystring('project_name_or_id')
        else:
            ensure_instance('project_name_or_id', int)

        project = self._project(project_name_or_id)
        extra = filter or {}

        return _expand(project.boards.list(iterator=True, **extra))

    @api_call
    def list_project_mergerequests(
        self,
        project_name_or_id: Union[str, int],
        *,
        state: str = 'opened',
        **filter,
    ) -> List[Dict[str, Any]]:
        """List all merge requests in a project.

        # Required parameters

        - project_name_or_id: a non-empty string or an integer

        # Optional parameters

        - state: a string (default: `'opened'`)
        - filter: additional filters

        # Returned value

        A list of _merge requests_.
        """
        if isinstance(project_name_or_id, str):
            ensure_nonemptystring('project_name_or_id')
        else:
            ensure_instance('project_name_or_id', int)
        ensure_in('state', MR_STATE)

        project = self._project(project_name_or_id)
        extra = filter or {}

        return _expand(
            project.mergerequests.list(iterator=True, state=state, **extra)
        )

    @api_call
    def list_project_directmembers(
        self, project_name_or_id: Union[str, int], **filter
    ) -> List[Dict[str, Any]]:
        """List all direct members in a project.

        # Required parameters

        - project_name_or_id: a non-empty string or an integer

        # Optional parameters

        - filter: additional filters

        # Returned value

        A list of _members_.
        """
        if isinstance(project_name_or_id, str):
            ensure_nonemptystring('project_name_or_id')
        else:
            ensure_instance('project_name_or_id', int)

        project = self._project(project_name_or_id)
        extra = filter or {}

        return _expand(project.members.list(iterator=True, **extra))

    @api_call
    def list_project_members(
        self, project_name_or_id: Union[str, int], **filter: Any
    ) -> List[Dict[str, Any]]:
        """List all members in a project.

        # Required parameters

        - project_name_or_id: a non-empty string or an integer

        # Optional parameters

        - filter: additional filters

        # Returned value

        A list of _members_.
        """
        if isinstance(project_name_or_id, str):
            ensure_nonemptystring('project_name_or_id')
        else:
            ensure_instance('project_name_or_id', int)

        project = self._project(project_name_or_id)
        extra = filter or {}

        return _expand(project.members_all.list(iterator=True, **extra))

    @api_call
    def list_project_releases(
        self, project_name_or_id: Union[str, int], **filter
    ) -> List[Dict[str, Any]]:
        """List all releases in a project.

        # Required parameters

        - project_name_or_id: a non-empty string or an integer

        # Optional parameters

        - filter: additional filters

        # Returned value

        A list of _releases_.
        """
        if isinstance(project_name_or_id, str):
            ensure_nonemptystring('project_name_or_id')
        else:
            ensure_instance('project_name_or_id', int)

        project = self._project(project_name_or_id)
        extra = filter or {}

        return _expand(project.releases.list(iterator=True, **extra))

    @api_call
    def list_project_branches(
        self, project_name_or_id: Union[str, int], **filter
    ) -> List[Dict[str, Any]]:
        """List all branches in a project.

        This include both protected and non-protected branches.

        # Required parameters

        - project_name_or_id: a non-empty string or an integer

        # Optional parameters

        - filter: additional filters

        # Returned value

        A list of _branches_.
        """
        if isinstance(project_name_or_id, str):
            ensure_nonemptystring('project_name_or_id')
        else:
            ensure_instance('project_name_or_id', int)

        project = self._project(project_name_or_id)
        extra = filter or {}

        return _expand(project.branches.list(iterator=True, **extra))

    @api_call
    def list_project_protectedbranches(
        self, project_name_or_id: Union[str, int], **filter
    ) -> List[Dict[str, Any]]:
        """List protected branches in a project.

        # Required parameters

        - project_name_or_id: a non-empty string or an integer

        # Optional parameters

        - filter: additional filters

        # Returned value

        A list of _protected branches_.  (Note that a protected branch
        may be a pattern, not a real branch.)
        """
        if isinstance(project_name_or_id, str):
            ensure_nonemptystring('project_name_or_id')
        else:
            ensure_instance('project_name_or_id', int)

        project = self._project(project_name_or_id)
        extra = filter or {}

        return _expand(project.protectedbranches.list(iterator=True, **extra))

    ####################################################################
    # GitLab helpers

    def _project(
        self, project: Union[str, int]
    ) -> 'gitlab.v4.objects.Project':
        return self._client().projects.get(project)

    def _group(self, group: Union[str, int]) -> 'gitlab.v4.objects.Group':
        return self._client().groups.get(group)
