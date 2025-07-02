# Copyright (c) 2019 Martin Lafaix (martin.lafaix@external.engie.com)
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

"""Jira Cloud.

A class wrapping Jira Cloud APIs.

There can be as many Jira instances as needed.

This module depends on the public **requests** and **jira.JIRA**
libraries.  It also depends on two **zabel-commons** modules,
#::zabel.commons.exceptions and #::zabel.commons.utils.
"""
from typing import Optional, Tuple, Union, Mapping, Iterable, List, Any, Dict
import requests

from zabel.commons.exceptions import ApiError
from zabel.commons.utils import (
    api_call,
    ensure_nonemptystring,
    ensure_noneorinstance,
    ensure_instance,
    join_url,
    add_if_specified,
)


########################################################################
########################################################################
TIMEOUT = 60
PROJECTS_EXPAND = 'description,lead,url,projectKeys,issueTypes'
PROJECT_EXPAND = 'description,lead,projectKeys,issueTypes,issueTypeHierarchy'


class JiraCloud:
    def __init__(
        self, url: str, basic_auth: Optional[Tuple[str, str]] = None
    ) -> None:
        """Create a JiraCloud instance object.

        You can only specify either `basic_auth`.

        # Required parameters

        - url: a string
        - basic_auth: a strings tuple (user, token)
        # Usage

        `url` must be the URL of the JiraCloud instance, e.g.,
        `https://jira.atlassian.net`.


        """
        ensure_nonemptystring('url')
        ensure_noneorinstance('basic_auth', tuple)

        self.url = url
        self.basic_auth = basic_auth

        self.client = None

        if basic_auth is not None:
            self.auth = basic_auth

    def __str__(self) -> str:
        return f'{self.__class__.__name__}: {self.url}'

    def __repr__(self) -> str:
        if self.basic_auth:
            rep = self.basic_auth[0]

        return f'<{self.__class__.__name__}: {self.url!r}, {rep!r}>'

    @api_call
    def list_projects(
        self,
        expand: str = PROJECTS_EXPAND,
        query: Optional[str] = None,
        order_by: Optional[str] = None,
        start_at: Optional[int] = None,
        max_results: Optional[int] = None,
        id: Optional[List[int]] = None,
        keys: Optional[List[str]] = None,
        type_key: Optional[str] = None,
        category_id: Optional[int] = None,
        action: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List all projects.
        
        # Optional parameters
        
        - expand: a string (see `PROJECT_EXPAND` constant)
        - query: a string
        - order_by: a string
        - start_at: an integer
        - max_results: an integer (default: 50, maximum: 100)
        - id: a list of integers
        - keys: a list of strings
        - type_key: a string
        - category_id: an integer
        - action: a string
        
        # Return value
        
        A list of dictionaries, each representing a project.
        """
        ensure_noneorinstance('expand', str)
        ensure_noneorinstance('query', str)
        ensure_noneorinstance('order_by', str)
        ensure_noneorinstance('start_at', int)
        ensure_noneorinstance('max_results', int)
        ensure_noneorinstance('id', list)
        ensure_noneorinstance('keys', list)
        ensure_noneorinstance('type_key', str)
        ensure_noneorinstance('category_id', int)
        ensure_noneorinstance('action', str)

        params = {}
        add_if_specified(params, 'expand', expand)
        add_if_specified(params, 'query', query)
        add_if_specified(params, 'order_by', order_by)
        add_if_specified(params, 'start_at', start_at)
        add_if_specified(params, 'max_results', max_results)
        add_if_specified(params, 'id', id)
        add_if_specified(params, 'keys', keys)
        add_if_specified(params, 'type_key', type_key)
        add_if_specified(params, 'category_id', category_id)
        add_if_specified(params, 'action', action)

        return self._collect_data('project/search', params=params)

    @api_call
    def get_project(
        self, project_key: str, expand: str = PROJECT_EXPAND
    ) -> Dict[str, Any]:
        """Get a project by its key.
        
        # Required parameters
        
        - project_key: a non-empty string
        
        # Optional parameters

        - expand: a string (`PROJECT_EXPAND` by default)

        # Returned value

        A dictionary.  See #list_projects() for details on its
        structure.
        """
        ensure_nonemptystring('project_key')
        ensure_nonemptystring('expand')

        params = {'expand': expand}
        response = self._get(f'project/{project_key}', params=params)
        response.raise_for_status()

        return response.json()

    @api_call
    def create_project(
        self,
        key: str,
        project_type_key: str,
        name: str,
        lead_account_id: str = None,
        url: Optional[str] = None,
        assignee_type: Optional[str] = None,
        avatar_id: Optional[int] = None,
        category_id: Optional[int] = None,
        description: Optional[str] = None,
        field_configuration_scheme: Optional[int] = None,
        issue_security_scheme: Optional[int] = None,
        issue_type_scheme: Optional[int] = None,
        issue_type_screen_scheme: Optional[int] = None,
        notification_scheme: Optional[int] = None,
        permission_scheme: Optional[int] = None,
        project_template_key: Optional[str] = None,
        workflow_scheme: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Create a new project.
        
        # Required parameters
        
        - key: a non-empty string (the project key)
        - project_type_key: a string (project type key, e.g., 'business', 'software', 'service_desk')
        - name: a non-empty string (the project name)
        - lead_account_id: a string (the project lead account ID, if different from username)

        # Optional parameters
        
        - url: a string (the project URL)
        - assignee_type: a string (e.g., 'PROJECT_LEAD')
        - avatar_id: an integer (the avatar ID)
        - category_id: an integer (the category ID)
        - description: a string (the project description)
        - field_configuration_scheme: an integer (field configuration scheme ID)
        - issue_security_scheme: an integer (issue security scheme ID)
        - issue_type_scheme: an integer (issue type scheme ID)
        - issue_type_screen_scheme: an integer (issue type screen scheme ID)
        - notification_scheme: an integer (notification scheme ID)
        - permission_scheme: an integer (permission scheme ID)
        - project_template_key: a string (project template key, e.g., 'com.atlassian.jira-core-project-templates:jira-core-simplified')
        - workflow_scheme: an integer (workflow scheme ID)

        # Return Value

            A dictionary representing the created project.
        
        """
        ensure_nonemptystring('key')
        ensure_nonemptystring('name')
        ensure_nonemptystring('project_type_key')
        ensure_noneorinstance('lead_account_id', str)
        ensure_noneorinstance('url', str)
        ensure_noneorinstance('assignee_type', str)
        ensure_noneorinstance('avatar_id', int)
        ensure_noneorinstance('category_id', int)
        ensure_noneorinstance('description', str)
        ensure_noneorinstance('field_configuration_scheme', int)
        ensure_noneorinstance('issue_security_scheme', int)
        ensure_noneorinstance('issue_type_scheme', int)
        ensure_noneorinstance('issue_type_screen_scheme', int)
        ensure_noneorinstance('notification_scheme', int)
        ensure_noneorinstance('permission_scheme', int)
        ensure_noneorinstance('project_template_key', str)
        ensure_noneorinstance('workflow_scheme', int)

        params = {
            'key': key,
            'name': name,
            'leadAccountId': lead_account_id,
            'projectTypeKey': project_type_key,
        }
        add_if_specified(params, 'url', url)
        add_if_specified(params, 'assigneeType', assignee_type)
        add_if_specified(params, 'avatarId', avatar_id)
        add_if_specified(params, 'categoryId', category_id)
        add_if_specified(params, 'description', description)
        add_if_specified(
            params, 'fieldConfigurationScheme', field_configuration_scheme
        )
        add_if_specified(params, 'issueSecurityScheme', issue_security_scheme)
        add_if_specified(params, 'issueTypeScheme', issue_type_scheme)
        add_if_specified(
            params, 'issueTypeScreenScheme', issue_type_screen_scheme
        )
        add_if_specified(params, 'notificationScheme', notification_scheme)
        add_if_specified(params, 'permissionScheme', permission_scheme)
        add_if_specified(params, 'projectTemplateKey', project_template_key)
        add_if_specified(params, 'workflowScheme', workflow_scheme)

        response = self._post('project', json=params)
        return response.json()

    ### Groups

    @api_call
    def list_groups(
        self, max_results: int = 9999, query: Optional[str] = None
    ) -> Dict[str, Dict[str, Any]]:
        """
        List groups.
        
        # Required parameters
        
        - max_results: an integer (default: 9999)
        
        # Optional parameters
        
        - query: a string (optional, used for filtering group names)
        
        # Return Value
            A dictionary where keys are group names and values are dictionaries
        
        """
        ensure_noneorinstance('query', str)
        ensure_instance('max_results', int)

        params = {'maxResults': max_results}
        add_if_specified(params, 'query', query)

        response = self._get('groups/picker', params=params)
        groups = response.json().get('groups', [])

        if not groups:
            return {}

        return {group['name']: group for group in groups}

    @api_call
    def create_group(self, group_name: str) -> bool:

        """ Create new group.
        
        # Required parameters

        - group_name: a non-empty string

        # Returned value

        A boolean.  True if successful, False otherwise.
        
        """
        ensure_instance('group_name', str)
        response = self._post('group', json={'name': group_name})

        return response.status_code == 201

    ### Schemes ###

    @api_call
    def list_issuetypescreenschemes(
        self,
        start_at: int = 0,
        max_results: int = 50,
        id: Optional[List[int]] = None,
        query: Optional[str] = None,
        order_by: Optional[str] = None,
        expand: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        List issue type screen schemes.
        
        # Optional parameters   
        - start_at: an integer (default: 0)
        - max_results: an integer (default: 50, maximum: 100)
        - id: a list of integers (optional, used for filtering by scheme IDs)
        - query: a string (optional, used for filtering by scheme name)
        - order_by: a string (optional, used for ordering results)
        - expand: a string (optional, used for expanding additional fields)
        
        # Return Value
        A list of dictionaries, each representing an issue type screen scheme.
        
        """
        ensure_instance('start_at', int)
        ensure_instance('max_results', int)
        ensure_noneorinstance('id', list)
        ensure_noneorinstance('query', str)
        ensure_noneorinstance('order_by', str)
        ensure_noneorinstance('expand', str)

        params = {'startAt': start_at, 'maxResults': max_results}
        add_if_specified(params, 'id', id)
        add_if_specified(params, 'query', query)
        add_if_specified(params, 'order_by', order_by)
        add_if_specified(params, 'expand', expand)

        return self._collect_data('issuetypescreenscheme', params=params)

    ### Roles ###

    def list_roles(self) -> List[Dict[str, Any]]:
        """Return the list of all roles.

        # Returned value

        A list of _roles_.  Each role is a dictionary  with the
        following entries:

        - self: a string (an URL)
        - name: a string
        - id: an integer
        - scope : a list of dictionaries
        - description: a string (optional)
        - actors: a list of dictionaries

        `actors` entries have the following entries:
        
        - id: an integer
        - displayName: a string
        - type: a string
        - name: a string
        - avatarUrl: a string

        The `actors` entry may be missing.
        """
        response = self._get('role')

        return response.json()

    def _get(
        self,
        uri: str,
        params: Optional[
            Mapping[str, Union[str, Iterable[str], int, bool]]
        ] = None,
    ) -> requests.Response:
        return requests.get(
            join_url(self.url, uri),
            params=params,
            auth=self.auth,
            timeout=TIMEOUT,
        )

    def _post(
        self, api: str, json: Optional[Mapping[str, Any]] = None
    ) -> requests.Response:
        return requests.post(
            join_url(self.url, api), json=json, auth=self.auth, timeout=TIMEOUT
        )

    def _collect_data(
        self,
        api: str,
        params: Optional[Mapping[str, Union[str, List[str], None]]] = None,
        headers: Optional[Mapping[str, str]] = None,
        start_at: str = 'startAt',
        is_last: str = 'isLast',
        key: str = 'values',
    ) -> List[Any]:
        api_url = join_url(self.url, api)
        collected: List[Any] = []
        _params = dict(params or {})
        more = True
        with requests.Session() as session:
            session.auth = self.auth
            session.headers = headers  # type: ignore
            while more:
                response = session.get(api_url, params=_params)
                if response.status_code // 100 != 2:
                    raise ApiError(response.text)
                try:
                    workload = response.json()
                    values = workload[key]
                    collected += values
                except Exception as exception:
                    raise ApiError(exception)
                # Some APIs do not provide an 'isLast' field :(
                if is_last in workload:
                    more = not workload[is_last]
                else:
                    more = workload[start_at] + len(values) < workload['total']
                if more:
                    _params[start_at] = workload[start_at] + len(values)

        return collected
