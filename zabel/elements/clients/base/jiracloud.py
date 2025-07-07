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

This module depends on the public **requests**library.
It also depends on two **zabel-commons** modules,
#::zabel.commons.exceptions and #::zabel.commons.utils.
"""
from typing import Optional, Tuple, Union, Mapping, Iterable, List, Any, Dict
import requests

from zabel.commons.exceptions import ApiError
from zabel.commons.sessions import prepare_session
from zabel.commons.utils import (
    api_call,
    ensure_nonemptystring,
    ensure_noneorinstance,
    ensure_instance,
    join_url,
    add_if_specified,
    ensure_onlyone,
)


########################################################################
########################################################################
TIMEOUT = 60
PROJECTS_EXPAND = 'description,lead,url,projectKeys,issueTypes'
PROJECT_EXPAND = 'description,lead,projectKeys,issueTypes,issueTypeHierarchy'


class JiraCloud:
    """JIRA Cloud Low-Level Wrapper.

    There can be as many Jira instances as needed.

    This class depends on the public **requests** library.
    It also depends on two **zabel-commons** modules,
    #::zabel.commons.exceptions and #::zabel.commons.utils.

    # Reference URLs

    - <https://developer.atlassian.com/cloud/jira/platform/rest/v3>
    
    # Agile references

    - <https://developer.atlassian.com/cloud/jira/software/rest/intro/>
    - <https://support.atlassian.com/jira/kb/how-to-update-board-administrators-through-rest-api/>

    # Implemented features

    - boards
    - filters
    - groups
    - projects
    - users

    Works with basic authentication.

    It is the responsibility of the user to be sure the provided
    authentication has enough rights to perform the requested operation.

    # Sample usage

    ```python
    from zabel.elements.clients.jiracloud import JiraCloud

    url = 'https://your-domain.atlassian.net'
    jc = JiraCloud(
        url,
        basic_auth=(user, token),
    )
    jc.list_projects()
    ```
    """
    def __init__(
        self,
        url: str,
        basic_auth: Optional[Tuple[str, str]] = None,
        verify: bool = True,
    ) -> None:
        """Create a JiraCloud instance object.

        https://developer.atlassian.com/cloud/jira/software/rest/intro/#introduction

        You can only specify either `basic_auth`.

        # Required parameters

        - url: a string
        - basic_auth: a strings tuple (user, token)

        # Optional parameters

        - verify: a boolean (True by default)

        # Usage

        `url` must be the URL of the JiraCloud instance, e.g.,
        `https://jira.atlassian.net`.

        `verify` can be set to False if disabling certificate checks for
        Jira communication is required.  Tons of warnings will occur if
        this is set to False.
        """
        ensure_nonemptystring('url')
        ensure_noneorinstance('basic_auth', tuple)
        ensure_instance('verify', bool)


        self.url = url
        self.basic_auth = basic_auth

        self.client = None
        self.verify = verify
        self.REST_BASE_URL = join_url(url, 'rest/api/3/')
        self.AGILE_BASE_URL = join_url(url, 'rest/agile/1.0/')
        self.GREENHOPPER_BASE_URL = join_url(url, 'rest/greenhopper/1.0/')

        self.auth = basic_auth
        self.session = prepare_session(self.auth, verify=verify)

    def __str__(self) -> str:
        return f'{self.__class__.__name__}: {self.url}'

    def __repr__(self) -> str:
        if self.basic_auth:
            rep = self.basic_auth[0]

        return f'<{self.__class__.__name__}: {self.url!r}, {rep!r}>'
    
    ####################################################################
    # JIRA CLOUD groups
    #
    # list_groups
    # create_group
    # list_group_users
    # add_group_user
    # remove_group_user

    @api_call
    def list_groups(
        self, max_results: int = 9999, query: Optional[str] = None
    ) -> Dict[str, Dict[str, Any]]:
        """
        List groups.

        # Optional parameters

        - query: a string (optional, used for filtering group names)
        - max_results: an integer (default: 9999)

        # Returned value

        A dictionary where keys are group names and values are dictionaries
          with following entries:
          
        - name: a string
        - html: a string
        - labels: a list of strings
        - groupId: a string
        """
        ensure_noneorinstance('query', str)
        ensure_instance('max_results', int)

        params = {'maxResults': max_results}
        add_if_specified(params, 'query', query)

        response = self._get('groups/picker', params=params).json()
        groups = response.get('groups', [])
        return {group['name']: group for group in groups}

    @api_call
    def create_group(self, group_name: str) -> bool:
        """Create new group.

        # Required parameters

        - group_name: a non-empty string

        # Returned value

        A boolean.  True if successful, False otherwise.
        """
        ensure_instance('group_name', str)
        response = self._post('group', json={'name': group_name})

        return response.status_code == 201

    @api_call
    def list_group_users(self, group_name: str, include_inactive_users: bool = False) -> Dict[str, Any]:
        """List users in a group.

        # Required parameters

        - group_name: a non-empty string

        # Optional parameters

        - include_inactive_users: a boolean (default: False)

        # Returned value
        A list of dictionaries.  Each dictionary has the following keys:

        - accountId: a string
        - accountType: a string
        - active: a boolean
        - avatarUrls: a dictionary
        - displayName: a string
        - emailAddress: a string
        - self: a string
        - timeZone: a string
        """
        ensure_nonemptystring('group_name')
        ensure_instance('include_inactive_users', bool)

        params = {
            'groupname': group_name,
        }
        add_if_specified(
            params, 'includeInactiveUsers', include_inactive_users
        )
        return self._collect_data(
            'group/member', params={'groupname': group_name}
        )

    @api_call
    def add_group_user(self, group_name: str, account_id: str) -> bool:
        """Add a user to a group.

        # Required parameters

        - group_name: a non-empty string
        - account_id: a non-empty string

        # Returned value
        
        A boolean.  True if successful, False otherwise.
        """
        ensure_nonemptystring('group_name')
        ensure_nonemptystring('account_id')

        response = self._post(
            f'group/user',
            params={'groupname': group_name},
            json={'accountId': account_id},
        )
        return response.status_code == 204

    @api_call
    def remove_group_user(self, group_name: str, account_id: str) -> bool:
        """Remove a user from a group.

        # Required parameters

        - group_name: a non-empty string (the group name)
        - account_id: a non-empty string (the user's account ID)

        # Returned value
        
        A boolean.  True if successful, False otherwise.
        """
        ensure_nonemptystring('group_name')
        ensure_nonemptystring('account_id')

        response = self._delete(
            f'group/user={group_name}',
            params={'accountId': account_id, 'groupname': group_name},
        )
        return response.status_code == 204

    ####################################################################
    # JIRA Cloud projects
    #
    # list_projects
    # get_project
    # create_project
    # get_project_role
    # list_project_boards
    # create_project_board
    # add_project_role_actors
    # remove_project_role_actor
    
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

    @api_call
    def get_project_role(
        self, project_id_or_key: Union[int, str], role_id: Union[int, str]
    ) -> Dict[str, Any]:
        """Return the project role details.

        # Required parameters

        - project_id_or_key: an integer or a string
        - role_id: an integer or a string

        # Return Value

        A project _role_.  Project roles are dictionaries with the
        following entries:

        - self: a string (an URL)
        - name: a string
        - id: an integer
        - description: a string (optional)
        - actors: a list of dictionaries
        - scope: a dictionary with the following entries:
            - type: a string (e.g., 'PROJECT')
            - project: a dictionary

        `actors` entries have the following entries:

        - id: an integer
        - displayName: a string
        - type: a string
        - name: a string (for actorGroup)
        - avatarUrl: a string

        """
        ensure_nonemptystring('project_key')
        ensure_instance('role_id', int)

        response = self._get(f'project/{project_id_or_key}/role/{role_id}')
        return response.json()

    def list_project_boards(
        self, project_id_or_key: Union[int, str]
    ) -> List[Dict[str, Any]]:
        """Returns the list of boards attached to project.

        # Required parameters

        - project_id_or_key: an integer or a string

        # Returned value

        A list of _boards_.  Each board is a dictionary with the
        following entries:

        - type: a string
        - id: an integer
        - name: a string
        - self: a string

        # Raised exceptions

        Browse project permission required (will raise an _ApiError_
        otherwise).
        """
        ensure_nonemptystring('project_id_or_key')

        return self._collect_agile_data(
            'board', params={'projectKeyOrId': project_id_or_key}
        )

    @api_call
    def create_project_board(
        self,
        project_id_or_key: Union[int, str],
        name: str,
        type: str,
        filter_id: Optional[Union[int, str]] = None,
    ) -> Dict[str, Any]:
        """Create a new board for a project.

        # Required parameters

        - project_id_or_key: an integer or a string
        - name: a non-empty string (the board name)
        - type: a string (the board type, e.g., 'scrum', 'kanban', 'simple')

        # Optional parameters

        - filter_id: an integer (the filter ID)

        # Returned value

        A dictionary representing the created board.
        """
        ensure_nonemptystring('project_id_or_key')
        ensure_nonemptystring('name')
        ensure_nonemptystring('type')

        return self.create_board(
            name=name,
            type=type,
            filter_id=filter_id,
            location={
                'projectKeyOrId': project_id_or_key,
                'type': 'project',
            },
        )

    @api_call
    def add_project_role_actors(
        self,
        project_id_or_key: Union[int, str],
        role_id: Union[int, str],
        groups: Optional[List[str]] = None,
        users: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Add an actor (group or user) to a project role.

        You can only specify either `groups` or `users`.

        # Required parameters

        - project_id_or_key: an integer or a string
        - role_id: an integer or a string
        - groups: a list of strings
        - users: a list of strings (account IDs)

        # Returned value

        A project _role_.  Refer to #get_project_role() for details.
        """
        ensure_instance('project_id_or_key', (str, int))
        ensure_instance('role_id', (str, int))
        ensure_onlyone('groups', 'users')
        ensure_noneorinstance('groups', list)
        ensure_noneorinstance('users', list)

        if groups is not None:
            data = {'group': groups}
        else:
            data = {'user': users}
        result = self._post(
            f'project/{project_id_or_key}/role/{role_id}',
            json=data,
        )
        return result

    @api_call
    def remove_project_role_actor(
        self,
        project_id_or_key: Union[int, str],
        role_id: Union[int, str],
        group: Optional[str] = None,
        user: Optional[str] = None,
    ) -> None:
        """Remove an actor from project role.

        You can only specify either `group` or `user`.

        # Required parameters

        - project_id_or_key: an integer or a string
        - role_id: an integer or a string
        - group: a string
        - user: a string
        """
        ensure_instance('project_id_or_key', (str, int))
        ensure_instance('role_id', (str, int))
        ensure_onlyone('group', 'user')
        ensure_noneorinstance('group', str)
        ensure_noneorinstance('user', str)

        if group is not None:
            params = {'group': group}
        else:
            params = {'user': user}  # type: ignore
        self._delete(
            f'project/{project_id_or_key}/role/{role_id}',
            params=params,
        )

    ### Groups

    

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

    @api_call
    def create_filter(
        self,
        name: str,
        jql: str,
        share_permissions: Optional[List[Dict[str, Any]]] = None,
        edit_permissions: Optional[List[Dict[str, Any]]] = None,
        description: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new filter.

        # Required parameters

        - name: a non-empty string (the filter name)
        - jql: a non-empty string (the JQL query)

        # Optional parameters

        - description: a string (the filter description, optional)
        - share_permissions: a list of dictionaries (optional, used for sharing the filter)
        - edit_permissions: a list of dictionaries (optional, used for editing permissions)

        # Returned value

        A dictionary representing the created filter.
        """
        ensure_nonemptystring('name')
        ensure_nonemptystring('jql')
        ensure_noneorinstance('description', str)
        ensure_noneorinstance('share_permissions', list)
        ensure_noneorinstance('edit_permissions', list)

        params = {
            'name': name,
            'jql': jql,
        }
        add_if_specified(params, 'description', description)
        add_if_specified(params, 'sharePermissions', share_permissions)
        add_if_specified(params, 'editPermissions', edit_permissions)
        response = self._post('filter', json=params)
        return response.json()

    @api_call
    def list_boards(
        self, params: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Return the list of boards.

        # Optional parameters

        - params: a dictionary or None (None by default)

        # Usage

        `params`, if provided, is a dictionary with at least one of the
        following entries:

        - accountIdLocation: a string
        - expand: a string
        - filterId: an integer
        - includePrivate: a boolean
        - maxResults: an integer
        - name: a string
        - negateLocationFiltering: a boolean
        - orderBy: a string
        - projectKeyOrId: a string
        - projectLocation: a string
        - startAt: an integer
        - type: a string

        # Returned value

        A list of _boards_.  Each board is a dictionary with the
        following entries:

        - name: a string
        - type: a string (`'scrum'` or `'kanban'` or `'simple'`)
        - id: an integer
        - self: a string (URL)
        """
        ensure_noneorinstance('params', dict)

        return self._collect_agile_data('board', params=params)

    @api_call
    def create_board(
        self,
        name: str,
        type: str,
        filter_id: Optional[int] = None,
        location: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a new board.

        # Required parameters

        - name: a non-empty string (the board name)
        - type: a string (the board type, e.g., 'scrum', 'kanban', 'simple')

        # Optional parameters

        - filter_id: an integer (the filter ID)
        - location: a dictionary (optional, used for specifying the board location)

        # Returned value

        A dictionary representing the created board.
        """
        ensure_nonemptystring('name')
        ensure_nonemptystring('type')
        ensure_noneorinstance('location', dict)

        data = {'name': name, 'type': type}
        if filter_id is not None:
            data['filterId'] = filter_id
        if location is not None:
            data['location'] = location

        response = self.session().post(
            join_url(self.AGILE_BASE_URL, 'board'), json=data
        )
        return response.json()

    @api_call
    def set_board_admins(
        self, board_id: int, board_admins: Dict[str, List[str]]
    ) -> Dict[str, List[Dict[str, str]]]:
        """Set the board administrators.

        # Required parameters

        - board_id: an integer
        - board_admins: a dictionary

        # Usage

        The `board_admins` dictionary has the following two entries:

        - groupKeys: a list of strings
        - userKeys: a list of strings

        The lists can be empty.  Their items must be valid group keys
        or user keys, respectively.

        # Returned value

        A dictionary with the following entries:

        - groupKeys: a list of dictionaries
        - userKeys: a list of dictionaries

        The list items are dictionaries with the following two entries:

        - key: a string
        - displayName: a string

        This returned value has the same format as the `boardAdmins`
        entry in #get_board_editmodel().

        # Raised exceptions

        Raises an _ApiError_ if a provided key is invalid.
        """
        ensure_instance('board_id', int)
        ensure_instance('board_admins', dict)

        result = requests.put(
            join_url(self.GREENHOPPER_BASE_URL, 'rapidviewconfig/boardadmins'),
            json={'id': board_id, 'boardAdmins': board_admins},
            auth=self.auth,
            verify=self.verify,
            timeout=TIMEOUT,
        )
        return result  # type: ignore

    @api_call
    def set_board_columns(
        self,
        board_id: int,
        columns_template: List[Dict[str, Any]],
        statistics_field: str = 'none_',
    ) -> Dict[str, Any]:
        """Set the board columns.

        # Required parameters

        - board_id: an integer
        - columns_template: a list of dictionaries

        # Optional parameters

        - statistics_field: a non-empty string (`'_none'` by default)

        If specified, it must be the ID of a valid statistic field.

        # Usage

        Each item in the `columns_template` list has the following
        entries:

        - name: a non-empty string
        - mappedStatuses: a list of string (possibly empty)
        - isKanPlanColumn: a boolean
        - min: a string,
        - max: a string,
        - id: an integer or None

        `mappedStatuses` entries must be names of existing statuses in
        the associated project(s) workflow(s).  A given status cannot
        be mapped to more than one column (but it's fine to have a
        status not mapped to a column).

        If `id` is None, a new column is created.  If it is not None,
        the column must already exist, and will be updated if needed.

        # Returned value

        A dictionary.

        # Raised exceptions

        Raises an _ApiError_ if the provided columns definition is
        invalid.
        """
        ensure_instance('board_id', int)
        ensure_instance('columns_template', list)
        ensure_nonemptystring('statistics_field')

        model = self.get_board_editmodel(board_id)
        if statistics_field not in [
            sf['id'] for sf in model['rapidListConfig']['statisticsFields']
        ]:
            raise ApiError(f'Unknown statistics_field {statistics_field}.')

        # collecting known statuses
        statuses = list(model['rapidListConfig']['unmappedStatuses'])
        for col in model['rapidListConfig']['mappedColumns']:
            statuses += col['mappedStatuses']
        statuses_names = {status['name']: status['id'] for status in statuses}

        mapped_names: List[str] = []
        columns_definitions = []
        for col in columns_template:
            col_statuses = []
            for name in col['mappedStatuses']:
                if name in mapped_names:
                    raise ApiError(f'Status {name} mapped more than once.')
                if name not in statuses_names:
                    raise ApiError(f'Unknown status {name}.')
                mapped_names.append(name)
                col_statuses.append(name)
            column_definition = col.copy()
            column_definition['mappedStatuses'] = [
                {'id': statuses_names[n]} for n in col_statuses
            ]
            columns_definitions.append(column_definition)

        result = requests.put(
            join_url(self.GREENHOPPER_BASE_URL, 'rapidviewconfig/columns'),
            json={
                'currentStatisticsField': {'id': statistics_field},
                'rapidViewId': board_id,
                'mappedColumns': columns_definitions,
            },
            auth=self.auth,
            verify=self.verify,
            timeout=TIMEOUT,
        )
        return result  # type: ignore

    @api_call
    def set_board_daysincolumn(
        self, board_id: int, days_in_column: bool
    ) -> None:
        """Enable or disable the time spent indicator on cards.

        # Required parameters

        - board_id: an integer
        - days_in_column: a boolean

        # Raised exceptions

        An _ApiError_ is raised if something went wrong while setting
        the time spent indicator.
        """
        ensure_instance('board_id', int)
        ensure_instance('days_in_column', bool)

        result = requests.put(
            join_url(
                self.GREENHOPPER_BASE_URL, 'rapidviewconfig/showDaysInColumn'
            ),
            json={'rapidViewId': board_id, 'showDaysInColumn': days_in_column},
            auth=self.auth,
            verify=self.verify,
            timeout=TIMEOUT,
        )
        return result

    def _get_url(self, uri: str) -> str:
        """Return the full URL for a given URI."""
        ensure_nonemptystring('uri')
        return join_url(self.REST_BASE_URL, uri)

    def _get(
        self,
        uri: str,
        params: Optional[
            Mapping[str, Union[str, Iterable[str], int, bool]]
        ] = None,
    ) -> requests.Response:
        return self.session().get(
            self._get_url(uri),
            params=params,
            auth=self.auth,
            timeout=TIMEOUT,
        )

    def _post(
        self,
        uri: str,
        params: Optional[Mapping[str, Any]] = None,
        json: Optional[Mapping[str, Any]] = None,
    ) -> requests.Response:
        return self.session().post(
            self._get_url(uri),
            params=params,
            json=json,
            auth=self.auth,
            timeout=TIMEOUT,
        )

    def _delete(
        self,
        uri: str,
        json_data: Optional[Mapping[str, Any]] = None,
        params: Optional[
            Mapping[str, Union[str, Iterable[str], int, bool]]
        ] = None,
    ) -> requests.Response:
        return self.session().delete(
            self._get_url(uri),
            json=json_data,
            params=params,
            auth=self.auth,
            timeout=TIMEOUT,
        )

    def _collect_data(
        self,
        uri: str,
        params: Optional[Mapping[str, Union[str, List[str], None]]] = None,
        base: Optional[str] = None,
        start_at: str = 'startAt',
        is_last: str = 'isLast',
        key: str = 'values',
    ) -> List[Any]:
        api_url = self._get_url(uri) if base is None else join_url(base, uri)
        collected: List[Any] = []
        _params = dict(params or {})
        more = True

        while more:
            response = self.session().get(api_url, params=_params)
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

    def _collect_agile_data(
        self,
        api: str,
        params: Optional[Mapping[str, Union[str, List[str], None]]] = None,
        key: str = 'values',
    ) -> List[Any]:
        return self._collect_data(
            api, params=params, base=self.AGILE_BASE_URL, key=key
        )
