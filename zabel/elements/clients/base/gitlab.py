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

This module depends on the **requests** public library.  It also depends
on three **zabel-commons** modules, #::zabel.commons.exceptions,
#::zabel.commons.sessions, and #::zabel.commons.utils.
"""

from typing import Any, Dict, List, Optional, Union

import gitlab

from zabel.commons.exceptions import ApiError
from zabel.commons.utils import (
    add_if_specified,
    api_call,
    ensure_in,
    ensure_instance,
    ensure_nonemptystring,
    ensure_noneorinstance,
    ensure_noneornonemptystring,
    ensure_onlyone,
)


########################################################################
########################################################################

# GitLab low-level api

ISSUES_STATE = ('all', 'opened', 'closed')
MR_STATE = ('all', 'opened', 'closed', 'merged', 'locked')


class GitLab:
    """GitLab Low-Level Wrapper.

    # Reference URL

    - <https://docs.gitlab.com/api/rest/>
    - <https://docs.gitlab.com/api/api_resources/>
    - <https://python-gitlab.readthedocs.io/en/stable/>

    # Implemented features

    - namespaces
    - groups
    - projects
    - members

    # Sample use

    ```python
    # standard use
    from zabel.elements.clients import GitLab

    url = 'https://gitlab.com/'
    gl = GitLab(url, private_token)
    gl.list_project_protectedbranches()
    ```

    !!! note
        Reuse the **python-gitlab** library whenever possible, but
        always returns 'raw' values (dictionaries, ..., not classes).
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
    # GitLab member roles
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
        return [
            ns.asdict() for ns in self._client().namespaces.list(iterator=True)
        ]

    @api_call
    def get_namespace(self, name: str) -> Dict[str, Any]:
        """Return the namespace details.

        # Required parameters

        - name: a non-empty string

        # Returned value

        A _namespace_ dictionary.  The namespace's `kind` entry may be
        either `user` or `group`.
        """
        ensure_nonemptystring('name')

        ns = self._client().namespaces.get(name)
        return ns.asdict()

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
    # list_group_projects
    # list_group_subgroups
    # list_group_issues
    # list_group_epics
    # list_group_mergerequests
    # list_group_memberroles
    # list_group_directmembers
    # list_group_members

    @api_call
    def list_group_projects(
        self,
        *,
        group_name: Optional[str] = None,
        group_id: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """List all projects in a group.

        # Required parameters

        Either `group_name` or `group_id` must be specified.

        - group_name: a non-empty string or None (None by default)
        - group_id: an integer or None (None by default)

        # Returned value

        A list of _projects_.
        """
        ensure_noneornonemptystring('group_name')
        ensure_noneorinstance('group_id', int)
        ensure_onlyone('group_name', 'group_id')

        client = self._client()
        if group_name:
            group = client.groups.get(group_name)
        else:
            group = client.groups.get(group_id)

        return [
            project.asdict() for project in group.projects.list(iterator=True)
        ]

    @api_call
    def list_group_subgroups(
        self,
        *,
        group_name: Optional[str] = None,
        group_id: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """List all direct subgroups in a group.

        # Required parameters

        Either `group_name` or `group_id` must be specified.

        - group_name: a non-empty string or None (None by default)
        - group_id: an integer or None (None by default)

        # Returned value

        A list of _groups_.
        """
        ensure_noneornonemptystring('group_name')
        ensure_noneorinstance('group_id', int)
        ensure_onlyone('group_name', 'group_id')

        client = self._client()
        if group_name:
            group = client.groups.get(group_name)
        else:
            group = client.groups.get(group_id)

        return [
            subgroup.asdict()
            for subgroup in group.subgroups.list(iterator=True)
        ]

    @api_call
    def list_group_issues(
        self,
        *,
        group_name: Optional[str] = None,
        group_id: Optional[int] = None,
        state: str = 'all',
        **filter,
    ) -> List[Dict[str, Any]]:
        """List all issues in a group.

        # Required parameters

        Either `group_name` or `group_id` must be specified.

        - group_name: a non-empty string or None (None by default)
        - group_id: an integer or None (None by default)

        # Optional parameters

        - state: a string (default: 'all')
        - filter: additional filters

        # Returned value

        A list of _issues_.
        """
        ensure_noneornonemptystring('group_name')
        ensure_noneorinstance('group_id', int)
        ensure_onlyone('group_name', 'group_id')
        ensure_in('state', ISSUES_STATE)

        client = self._client()
        if group_name:
            group = client.groups.get(group_name)
        else:
            group = client.groups.get(group_id)

        extra = filter or {}
        return [
            issue.asdict()
            for issue in group.issues.list(iterator=True, state=state, **extra)
        ]

    @api_call
    def list_group_epics(
        self,
        *,
        group_name: Optional[str] = None,
        group_id: Optional[int] = None,
        state: str = 'opened',
        **filter,
    ) -> List[Dict[str, Any]]:
        """List all epics in a group.

        # Required parameters

        Either `group_name` or `group_id` must be specified.

        - group_name: a non-empty string or None (None by default)
        - group_id: an integer or None (None by default)

        # Optional parameters

        - state: a string (default: 'opened')
        - filter: additional filters

        # Returned value

        A list of _epics_.
        """
        ensure_noneornonemptystring('group_name')
        ensure_noneorinstance('group_id', int)
        ensure_onlyone('group_name', 'group_id')
        ensure_in('state', ISSUES_STATE)

        client = self._client()
        if group_name:
            group = client.groups.get(group_name)
        else:
            group = client.groups.get(group_id)

        extra = filter or {}
        return [
            epic.asdict()
            for epic in group.epics.list(iterator=True, state=state, **extra)
        ]

    @api_call
    def list_group_mergerequests(
        self,
        *,
        group_name: Optional[str] = None,
        group_id: Optional[int] = None,
        state: str = 'opened',
        **filter,
    ) -> List[Dict[str, Any]]:
        """List all merge requests in a group.

        # Required parameters

        Either `group_name` or `group_id` must be specified.

        - group_name: a non-empty string or None (None by default)
        - group_id: an integer or None (None by default)

        # Optional parameters

        - state: a string (default: 'opened')
        - filter: additional filters

        # Returned value

        A list of _merge requests_.
        """
        ensure_noneornonemptystring('group_name')
        ensure_noneorinstance('group_id', int)
        ensure_onlyone('group_name', 'group_id')
        ensure_in('state', MR_STATE)

        client = self._client()
        if group_name:
            group = client.groups.get(group_name)
        else:
            group = client.groups.get(group_id)

        extra = filter or {}
        return [
            mr.asdict()
            for mr in group.mergerequests.list(
                iterator=True, state=state, **extra
            )
        ]

    @api_call
    def list_group_directmembers(
        self,
        *,
        group_name: Optional[str] = None,
        group_id: Optional[int] = None,
        **filter,
    ) -> List[Dict[str, Any]]:
        """List all direct members in a group.

        # Required parameters

        Either `group_name` or `group_id` must be specified.

        - group_name: a non-empty string or None (None by default)
        - group_id: an integer or None (None by default)

        # Optional parameters

        - filter: additional filters

        # Returned value

        A list of _members_.
        """
        ensure_noneornonemptystring('group_name')
        ensure_noneorinstance('group_id', int)
        ensure_onlyone('group_name', 'group_id')

        client = self._client()
        if group_name:
            group = client.groups.get(group_name)
        else:
            group = client.groups.get(group_id)

        extra = filter or {}
        return [
            member.asdict()
            for member in group.members.list(iterator=True, **extra)
        ]

    @api_call
    def list_group_members(
        self,
        *,
        group_name: Optional[str] = None,
        group_id: Optional[int] = None,
        **filter: Any,
    ) -> List[Dict[str, Any]]:
        """List all members in a group.

        # Required parameters

        Either `group_name` or `group_id` must be specified.

        - group_name: a non-empty string or None (None by default)
        - group_id: an integer or None (None by default)

        # Optional parameters

        - filter: additional filters

        # Returned value

        A list of _members_.
        """
        ensure_noneornonemptystring('group_name')
        ensure_noneorinstance('group_id', int)
        ensure_onlyone('group_name', 'group_id')

        client = self._client()
        if group_name:
            group = client.groups.get(group_name)
        else:
            group = client.groups.get(group_id)

        extra = filter or {}
        return [
            member.asdict()
            for member in group.members_all.list(iterator=True, **extra)
        ]

    @api_call
    def list_group_memberroles(
        self,
        *,
        group_name: Optional[str] = None,
        group_id: Optional[int] = None,
        **filter,
    ) -> List[Dict[str, Any]]:
        """List all member roles in a group.

        # Required parameters

        Either `group_name` or `group_id` must be specified.

        - group_name: a non-empty string or None (None by default)
        - group_id: an integer or None (None by default)

        # Optional parameters

        - filter: additional filters

        # Returned value

        A list of _member roles_.
        """
        ensure_noneornonemptystring('group_name')
        ensure_noneorinstance('group_id', int)
        ensure_onlyone('group_name', 'group_id')

        client = self._client()
        if group_name:
            group = client.groups.get(group_name)
        else:
            group = client.groups.get(group_id)

        extra = filter or {}
        return [
            role.asdict()
            for role in group.member_roles.list(iterator=True, **extra)
        ]

    ####################################################################
    # GitLab projects
    #
    # get_project
    # list_project_pipelines
    # list_project_packages
    # list_project_issues
    # list_project_mergerequests
    # list_project_directmembers
    # list_project_members
    # list_project_releases

    @api_call
    def get_project(
        self,
        project_name: Optional[str] = None,
        project_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Return a project's details.

        # Required parameters

        Either `project_name` or `project_id` must be specified.

        - project_name: a non-empty string or None (None by default)
        - project_id: an integer or None (None by default)

        # Returned value

        A _project_ dictionary.
        """
        ensure_noneornonemptystring('project_name')
        ensure_noneorinstance('project_id', int)
        ensure_onlyone('project_name', 'project_id')

        client = self._client()
        if project_name:
            project = client.projects.get(project_name)
        else:
            project = client.projects.get(project_id)

        return project.asdict()

    @api_call
    def list_project_pipelines(
        self,
        project_name: Optional[str] = None,
        project_id: Optional[int] = None,
        status: Optional[str] = None,
        **filter,
    ) -> List[Dict[str, Any]]:
        """List all pipelines in a project.

        # Required parameters

        Either `project_name` or `project_id` must be specified.

        - project_name: a non-empty string or None (None by default)
        - project_id: an integer or None (None by default)

        # Optional parameters

        - status: a string or None (None by default)
        - filter: additional filters

        # Returned value

        A list of _pipelines_.
        """
        ensure_noneornonemptystring('project_name')
        ensure_noneorinstance('project_id', int)
        ensure_onlyone('project_name', 'project_id')

        client = self._client()
        if project_name:
            project = client.projects.get(project_name)
        else:
            project = client.projects.get(project_id)

        extra = filter or {}
        return [
            pipeline.asdict()
            for pipeline in project.pipelines.list(
                iterator=True, status=status, **extra
            )
        ]

    @api_call
    def list_project_packages(
        self,
        project_name: Optional[str] = None,
        project_id: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """List all packages in a project.

        # Required parameters

        Either `project_name` or `project_id` must be specified.

        - project_name: a non-empty string or None (None by default)
        - project_id: an integer or None (None by default)

        # Returned value

        A list of _packages_.
        """
        ensure_noneornonemptystring('project_name')
        ensure_noneorinstance('project_id', int)
        ensure_onlyone('project_name', 'project_id')

        client = self._client()
        if project_name:
            project = client.projects.get(project_name)
        else:
            project = client.projects.get(project_id)

        return [
            package.asdict()
            for package in project.packages.list(iterator=True)
        ]

    @api_call
    def list_project_issues(
        self,
        project_name: Optional[str] = None,
        project_id: Optional[int] = None,
        state: str = 'opened',
        **filter,
    ) -> List[Dict[str, Any]]:
        """List all issues in a project.

        # Required parameters

        Either `project_name` or `project_id` must be specified.

        - project_name: a non-empty string or None (None by default)
        - project_id: an integer or None (None by default)

        # Optional parameters

        - state: a string (default: 'opened')
        - filter: additional filters

        # Returned value

        A list of _issues_.
        """
        ensure_noneornonemptystring('project_name')
        ensure_noneorinstance('project_id', int)
        ensure_onlyone('project_name', 'project_id')
        ensure_in('state', ISSUES_STATE)

        client = self._client()
        if project_name:
            project = client.projects.get(project_name)
        else:
            project = client.projects.get(project_id)

        extra = filter or {}
        return [
            issue.asdict()
            for issue in project.issues.list(
                iterator=True, state=state, **extra
            )
        ]

    @api_call
    def list_project_mergerequests(
        self,
        project_name: Optional[str] = None,
        project_id: Optional[int] = None,
        state: str = 'opened',
        **filter,
    ) -> List[Dict[str, Any]]:
        """List all merge requests in a project.

        # Required parameters

        Either `project_name` or `project_id` must be specified.

        - project_name: a non-empty string or None (None by default)
        - project_id: an integer or None (None by default)

        # Optional parameters

        - state: a string (default: 'opened')
        - filter: additional filters

        # Returned value

        A list of _merge requests_.
        """
        ensure_noneornonemptystring('project_name')
        ensure_noneorinstance('project_id', int)
        ensure_onlyone('project_name', 'project_id')
        ensure_in('state', MR_STATE)

        client = self._client()
        if project_name:
            project = client.projects.get(project_name)
        else:
            project = client.projects.get(project_id)

        extra = filter or {}
        return [
            mr.asdict()
            for mr in project.mergerequests.list(
                iterator=True, state=state, **extra
            )
        ]

    @api_call
    def list_project_directmembers(
        self,
        project_name: Optional[str] = None,
        project_id: Optional[int] = None,
        **filter,
    ) -> List[Dict[str, Any]]:
        """List all direct members in a project.

        # Required parameters

        Either `project_name` or `project_id` must be specified.

        - project_name: a non-empty string or None (None by default)
        - project_id: an integer or None (None by default)

        # Optional parameters

        - filter: additional filters

        # Returned value

        A list of _members_.
        """
        ensure_noneornonemptystring('project_name')
        ensure_noneorinstance('project_id', int)
        ensure_onlyone('project_name', 'project_id')

        client = self._client()
        if project_name:
            project = client.projects.get(project_name)
        else:
            project = client.projects.get(project_id)

        extra = filter or {}
        return [
            member.asdict()
            for member in project.members.list(iterator=True, **extra)
        ]

    @api_call
    def list_project_members(
        self,
        project_name: Optional[str] = None,
        project_id: Optional[int] = None,
        **filter: Any,
    ) -> List[Dict[str, Any]]:
        """List all members in a project.

        # Required parameters

        Either `project_name` or `project_id` must be specified.

        - project_name: a non-empty string or None (None by default)
        - project_id: an integer or None (None by default)

        # Optional parameters

        - filter: additional filters

        # Returned value

        A list of _members_.
        """
        ensure_noneornonemptystring('project_name')
        ensure_noneorinstance('project_id', int)
        ensure_onlyone('project_name', 'project_id')

        client = self._client()
        if project_name:
            project = client.projects.get(project_name)
        else:
            project = client.projects.get(project_id)

        extra = filter or {}
        return [
            member.asdict()
            for member in project.members_all.list(iterator=True, **extra)
        ]

    @api_call
    def list_project_releases(
        self,
        project_name: Optional[str] = None,
        project_id: Optional[int] = None,
        **filter,
    ) -> List[Dict[str, Any]]:
        """List all releases in a project.

        # Required parameters

        Either `project_name` or `project_id` must be specified.

        - project_name: a non-empty string or None (None by default)
        - project_id: an integer or None (None by default)

        # Optional parameters

        - filter: additional filters

        # Returned value

        A list of _releases_.
        """
        ensure_noneornonemptystring('project_name')
        ensure_noneorinstance('project_id', int)
        ensure_onlyone('project_name', 'project_id')

        client = self._client()
        if project_name:
            project = client.projects.get(project_name)
        else:
            project = client.projects.get(project_id)

        extra = filter or {}
        return [
            release.asdict()
            for release in project.releases.list(iterator=True, **extra)
        ]
