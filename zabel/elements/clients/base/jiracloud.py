# Copyright (c) 2019 Martin Lafaix (martin.lafaix@external.engie.com)
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

"""Jira Cloud.

A class wrapping Jira Cloud APIs.

There can be as many Jira Cloud instances as needed.

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
    ensure_noneornonemptystring,
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
    """Jira Cloud Low-Level Wrapper.

    There can be as many Jira Cloud instances as needed.

    This class depends on the public **requests** library.
    It also depends on two **zabel-commons** modules,
    #::zabel.commons.exceptions and #::zabel.commons.utils.

    ## Reference URLs

    - <https://developer.atlassian.com/cloud/jira/platform/rest/v3>

    ### Agile references

    - <https://developer.atlassian.com/cloud/jira/software/rest/intro/>
    - <https://support.atlassian.com/jira/kb/how-to-update-board-administrators-through-rest-api/>

    ## Implemented features

    - boards
    - filters
    - groups
    - projects
    - users

    Works with basic authentication.

    It is the responsibility of the user to be sure the provided
    authentication has enough rights to perform the requested operation.

    ## Expansion

    The Jira REST API uses resource expansion.  This means the API will
    only return parts of the resource when explicitly requested.

    Many query methods have an `expand` parameter, a comma-separated
    list of entities that are to be expanded, identifying each of them
    by name.

    Here are the default values for the main Jira entities:

    | Entity            | Default value
    | ----------------- | -------------
    | `PROJECTS_EXPAND` | description, lead, url, projectKeys,
                          issueTypes
    | `PROJECT_EXPAND`  | description, lead, projectKeys, issueTypes,
                          issueTypeHierarchy

    To discover the identifiers for each entity, look at the `expand`
    properties in the parent object.  In the example below, the
    resource declares _widgets_ as being expandable:

    ```json
    {
      "expand": "widgets",
      "self": "http://www.example.com/jira/rest/api/resource/KEY-1",
      "widgets": {
        "widgets": [],
        "size": 5
      }
    }
    ```

    The dot notation allows to specify expansion of entities within
    another entity.  For example, `expand='widgets.fringels'` would
    expand the widgets collection and also the _fringel_ property of
    each widget.

    ## Examples

    ```python
    from zabel.elements.clients.jiracloud import JiraCloud

    url = 'https://your-domain.atlassian.net'
    user = '...'
    token = '...'
    jc = JiraCloud(url, basic_auth=(user, token))
    jc.list_projects()
    ```
    """

    def __init__(
        self,
        url: str,
        *,
        basic_auth: Tuple[str, str],
        verify: bool = True,
    ) -> None:
        """Create a Jira Cloud instance object.

        <https://developer.atlassian.com/cloud/jira/software/rest/intro/#introduction>

        # Required parameters

        - url: a string
        - basic_auth: a strings tuple (user, token)

        # Optional parameters

        - verify: a boolean (True by default)

        # Usage

        `url` must be the URL of the Jira Cloud instance.  For example:

            `https://your-domain.atlassian.net`

        `verify` can be set to False if disabling certificate checks for
        Jira communication is required.  Tons of warnings will occur if
        this is set to False.
        """
        ensure_nonemptystring('url')
        ensure_instance('basic_auth', tuple)
        ensure_instance('verify', bool)

        self.url = url
        self.basic_auth = basic_auth

        self.client = None
        self.verify = verify
        self.REST_BASE_URL = join_url(url, 'rest/api/3/')
        self.AGILE_BASE_URL = join_url(url, 'rest/agile/1.0/')
        self.SERVICEDESK_BASE_URL = join_url(url, 'rest/servicedeskapi/')

        self.auth = basic_auth
        self.session = prepare_session(self.auth, verify=verify)

    def __str__(self) -> str:
        return f'{self.__class__.__name__}: {self.url}'

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__}: {self.url!r}, {self.basic_auth[0]!r}>'

    ####################################################################
    # Jira Cloud groups
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
        - max_results: an integer (default: `9999`)

        # Returned value

        A dictionary where keys are group names and values are
        dictionaries with following entries:

        - groupId: a string
        - html: a string
        - labels: a list of strings
        - name: a string
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
    def list_group_users(
        self, group_name: str, include_inactive_users: bool = False
    ) -> List[Dict[str, Any]]:
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
            'group/user',
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
            'group/user',
            params={'accountId': account_id, 'groupname': group_name},
        )
        return response.status_code == 204

    ####################################################################
    # Jira Cloud groups
    #
    # list_users
    # get_user
    # search_users

    @api_call
    def list_users(
        self,
    ) -> List[Dict[str, Any]]:
        """List all users.

        # Returned value

        A list of _users_.  Each user is a dictionary with the following
        entries:

        - accountId: a string
        - accountType: a string
        - active: a boolean
        - avatarUrls: a dictionary
        - displayName: a string
        - emailAddress: a string
        - self: a string
        - timeZone: a string
        """
        return self._get('users/search')

    @api_call
    def get_user(self, account_id: str) -> Dict[str, Any]:
        """Get a user by their account ID.

        # Required parameters

        - account_id: a non-empty string (the user's account ID)

        # Returned value

        A _user_.  See #list_users() for details on its structure.
        """
        ensure_nonemptystring('account_id')

        response = self._get('user', params={'accountId': account_id})
        return response.json()

    @api_call
    def get_currentuser(self, expand: Optional[str] = None) -> Dict[str, Any]:
        """Return currently logged user details.

        # Optional parameters

        - expand: a string

        # Returned value

        A _user_.  Refer to #list_users() for details on its structure.
        """
        ensure_noneorinstance('expand', str)

        if expand:
            params = {'expand': expand}
        else:
            params = {}

        return self._get('myself', params=params)  # type: ignore

    @api_call
    def search_users(
        self,
        query: Optional[str] = None,
        start_at: Optional[int] = None,
        max_results: Optional[int] = None,
        account_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Search for users.

        # Optional parameters

        - query: a non-empty string or None (None by default)
        - start_at: an integer or None (None by default)
        - max_results: an integer or None (None by default)
        - account_id: a non-empty string or None (None by default)

        # Returned value

        A list of _users_.  Refer to #list_user() for details on its
        structure.
        """
        ensure_noneornonemptystring('query')
        ensure_noneorinstance('start_at', int)
        ensure_noneorinstance('max_results', int)
        ensure_noneornonemptystring('account_id')

        params = {}
        add_if_specified(params, 'query', query)
        add_if_specified(params, 'startAt', start_at)
        add_if_specified(params, 'maxResults', max_results)
        add_if_specified(params, 'accountId', account_id)

        return self._get('user/search', params=params)  # type: ignore

    ####################################################################
    # Jira Cloud projects
    #
    # list_projects
    # get_project
    # create_project
    # get_project_issuetypescheme
    # get_project_issuetypescreenscheme
    # get_project_notificationscheme
    # get_project_permissionscheme
    # get_project_workflowscheme
    # update_project
    # set_project_workflowscheme
    # set_project_issuetypescheme
    # set_project_issuetypescreenscheme
    # set_project_permissionscheme
    # get_project_role
    # add_project_role_actors
    # remove_project_role_actor

    @api_call
    def list_projects(
        self,
        *,
        expand: str = PROJECTS_EXPAND,
        query: Optional[str] = None,
        order_by: Optional[str] = None,
        start_at: Optional[int] = None,
        max_results: Optional[int] = None,
        ids: Optional[List[int]] = None,
        keys: Optional[List[str]] = None,
        type_key: Optional[str] = None,
        category_id: Optional[int] = None,
        action: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List all projects.

        # Optional parameters

        - action: a string
        - category_id: an integer
        - expand: a string (`PROJECTS_EXPAND` by default)
        - ids: a list of integers
        - keys: a list of strings
        - max_results: an integer (default: `50`, maximum: `100`)
        - order_by: a string
        - query: a string
        - start_at: an integer
        - type_key: a string

        # Returned value

        A list of dictionaries, each representing a project.
        """
        ensure_noneorinstance('expand', str)
        ensure_noneorinstance('query', str)
        ensure_noneorinstance('order_by', str)
        ensure_noneorinstance('start_at', int)
        ensure_noneorinstance('max_results', int)
        ensure_noneorinstance('ids', list)
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
        add_if_specified(params, 'id', ids)
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

        return response.json()

    @api_call
    def create_project(
        self,
        key: str,
        project_type_key: str,
        name: str,
        lead_account_id: Optional[str] = None,
        *,
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
        - project_type_key: a string (project type key, e.g.,
          `'business'`, `'software'`, `'service_desk'`)
        - name: a non-empty string (the project name)

        # Optional parameters

        - lead_account_id: a string (the project lead account ID, if
          different from username)
        - assignee_type: a string (e.g., `'PROJECT_LEAD'`)
        - avatar_id: an integer (the avatar ID)
        - category_id: an integer (the category ID)
        - description: a string (the project description)
        - field_configuration_scheme: an integer (field configuration
          scheme ID)
        - issue_security_scheme: an integer (issue security scheme ID)
        - issue_type_scheme: an integer (issue type scheme ID)
        - issue_type_screen_scheme: an integer (issue type screen scheme
          ID)
        - notification_scheme: an integer (notification scheme ID)
        - permission_scheme: an integer (permission scheme ID)
        - project_template_key: a string (project template key, e.g.,
          `'com.atlassian.jira-core-project-templates:jira-core-simplified'`)
        - url: a string (the project URL)
        - workflow_scheme: an integer (workflow scheme ID)

        # Returned value

        A dictionary representing the created project.
        """
        ensure_nonemptystring('key')
        ensure_nonemptystring('project_type_key')
        ensure_nonemptystring('name')
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
            'projectTypeKey': project_type_key,
        }
        add_if_specified(params, 'leadAccountId', lead_account_id)
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

    def _get_project_id(self, project_id_or_key: Union[int, str]) -> str:
        """Get numerical project ID."""
        if isinstance(project_id_or_key, int) or project_id_or_key.isdigit():
            return str(project_id_or_key)

        p = self.get_project(str(project_id_or_key))
        return str(p['id'])

    @api_call
    def get_project_issuetypescheme(
        self, project_id_or_key: Union[int, str]
    ) -> Dict[str, Any]:
        """Get the issue type scheme assigned to project.

        # Required parameters

        - project_id_or_key: an integer or a non-empty string

        # Returned value

        A dictionary with the following entries:

        - id: a string
        - name: a string
        - description: a string
        """
        ensure_instance('project_id_or_key', (int, str))

        pid = self._get_project_id(project_id_or_key)
        resp = self._get(
            'issuetypescheme/project', params={'projectId': pid}
        ).json()
        return resp.get('values', [])[0]

    @api_call
    def get_project_issuetypescreenscheme(
        self, project_id_or_key: Union[int, str]
    ) -> Dict[str, Any]:
        """Get the issue type screen scheme assigned to project.

        # Required parameters

        - project_id_or_key: an integer or a non-empty string

        # Returned value

        A dictionary with the following entries:

        - id: a string
        - name: a string
        - description: a string
        """
        ensure_instance('project_id_or_key', (int, str))

        pid = self._get_project_id(project_id_or_key)
        resp = self._get(
            'issuetypescreenscheme/project', params={'projectId': pid}
        ).json()
        return resp.get('values', [])[0]

    @api_call
    def get_project_notificationscheme(
        self, project_id_or_key: Union[int, str]
    ) -> Dict[str, Any]:
        """Get the notification scheme assigned to project.

        # Required parameters

        - project_id_or_key: an integer or a non-empty string

        # Returned value

        A dictionary with the following entries:

        - id: a string
        - name: a string
        - description: a string
        """
        ensure_instance('project_id_or_key', (int, str))

        pid = self._get_project_id(project_id_or_key)
        resp = self._get(
            'notificationscheme/project', params={'projectId': pid}
        ).json()
        return resp.get('values', [])[0]

    @api_call
    def get_project_permissionscheme(
        self, project_id_or_key: Union[int, str]
    ) -> Dict[str, Any]:
        """Get the permission scheme assigned to project.

        # Required parameters

        - project_id_or_key: an integer or a non-empty string

        # Returned value

        A dictionary with the following entries:

        - id: a string
        - name: a string
        - description: a string
        """
        ensure_instance('project_id_or_key', (int, str))

        return self._get(f'project/{project_id_or_key}/permissionscheme')

    @api_call
    def get_project_workflowscheme(
        self, project_id_or_key: Union[int, str]
    ) -> Dict[str, Any]:
        """Get the workflow scheme assigned to project.

        # Required parameters

        - project_id_or_key: an integer or a non-empty string

        # Returned value

        A dictionary with the following entries:

        - id: a string
        - name: a string
        - description: a string
        """
        ensure_instance('project_id_or_key', (int, str))

        pid = self._get_project_id(project_id_or_key)
        resp = self._get(
            'workflowscheme/project', params={'projectId': pid}
        ).json()
        return resp.get('values', [])[0]

    @api_call
    def update_project(
        self, project_id_or_key: Union[int, str], project: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update project.

        # Required parameters

        - project_id_or_key: an integer or a non-empty string
        - project: a dictionary

        `project` is dictionary with the following optional entries:

        - assigneeType
        - avatarId
        - categoryId
        - description
        - issueSecurityScheme
        - key
        - lead
        - leadAccountId
        - name
        - notificationScheme
        - permissionScheme
        - releasedProjectKeys
        - url

        This dictionary respects the format returned by
        #list_projects().

        If an entry is not specified or is None, its corresponding
        value in the project will remain unchanged.

        # Returned value

        A dictionary.  See #list_projects() for details on its
        structure.
        """
        ensure_instance('project_id_or_key', (str, int))

        result = self._put(f'project/{project_id_or_key}', json=project)
        return result  # type: ignore

    @api_call
    def set_project_workflowscheme(
        self,
        project_id_or_key: Union[int, str],
        workflowscheme_id: Union[int, str],
    ) -> bool:
        """Set the workflow scheme associated to project.

        # Required parameters

        - project_id_or_key: an integer or a non-empty string
        - workflowscheme_id: an integer or a non-empty string

        # Returned value

        A boolean.  True if successful, False otherwise.
        """
        ensure_instance('project_id_or_key', (int, str))
        ensure_instance('workflowscheme_id', (int, str))

        pid = self._get_project_id(project_id_or_key)
        response = self._put(
            'workflowscheme/project',
            json={
                'projectId': pid,
                'workflowSchemeId': workflowscheme_id,
            },
        )
        return response.status_code == 204

    @api_call
    def set_project_issuetypescheme(
        self,
        project_id_or_key: Union[int, str],
        issuetypescheme_id: Union[int, str],
    ) -> bool:
        """Set issue type scheme associated to project.

        # Required parameters

        - project_id_or_key: an integer or a non-empty string
        - issuetypescheme_id: an integer or a non-empty string

        # Returned value

        A boolean.  True if successful, False otherwise.
        """
        ensure_instance('project_id_or_key', (int, str))
        ensure_instance('issuetypescheme_id', (int, str))

        pid = self._get_project_id(project_id_or_key)
        response = self._put(
            'issuetypescheme/project',
            json={
                'projectId': pid,
                'issueTypeSchemeId': issuetypescheme_id,
            },
        )
        return response.status_code == 204

    @api_call
    def set_project_issuetypescreenscheme(
        self,
        project_id_or_key: Union[int, str],
        issuetypescreenscheme_id: Union[int, str],
    ) -> bool:
        """Set the issue type screen scheme associated to project.

        # Required parameters

        - project_id_or_key: an integer or a  non-empty string
        - issuetypescreenscheme_id: an integer or a non-empty string

        # Returned value

        A boolean.  True if successful, False otherwise.
        """
        ensure_instance('project_id_or_key', (int, str))
        ensure_instance('issuetypescreenscheme_id', (int, str))

        pid = self._get_project_id(project_id_or_key)
        response = self._put(
            'issuetypescreenscheme/project',
            json={
                'projectId': pid,
                'issueTypeScreenSchemeId': issuetypescreenscheme_id,
            },
        )
        return response.status_code == 204

    def set_project_permissionscheme(
        self,
        project_id_or_key: Union[int, str],
        permissionscheme_id: Union[int, str],
    ) -> bool:
        """Set the permission scheme associated to project.

        # Required parameters

        - project_id_or_key: an integer or a non-empty string
        - permissionscheme_id: an integer or a non-empty string

        # Returned value

        A boolean.  True if successful, False otherwise.
        """
        ensure_instance('project_id_or_key', (int, str))
        ensure_instance('permissionscheme_id', (int, str))

        response = self._put(
            f'project/{project_id_or_key}/permissionscheme',
            json={'id': permissionscheme_id},
        )
        return response.status_code == 200

    @api_call
    def get_project_role(
        self, project_id_or_key: Union[int, str], role_id: Union[int, str]
    ) -> Dict[str, Any]:
        """Return the project role details.

        # Required parameters

        - project_id_or_key: an integer or a non-empty string
        - role_id: an integer or a string

        # Returned value

        A project _role_.  Project roles are dictionaries with the
        following entries:

        - actors: a list of dictionaries
        - description: a string (optional)
        - id: an integer
        - name: a string
        - scope: a dictionary with the following entries:
            - type: a string (e.g., `'PROJECT'`)
            - project: a dictionary
        - self: a string (an URL)

        `actors` entries have the following entries:

        - avatarUrl: a string
        - id: an integer
        - displayName: a string
        - name: a string (for actorGroup)
        - type: a string
        """
        ensure_instance('project_id_or_key', (int, str))
        ensure_instance('role_id', (int, str))

        response = self._get(f'project/{project_id_or_key}/role/{role_id}')
        return response.json()

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

        - project_id_or_key: an integer or a non-empty string
        - role_id: an integer or a string

        # Optional parameters

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

        - project_id_or_key: an integer or a non-empty string
        - role_id: an integer or a string

        # Optional parameters

        - group: a string
        - user: a string (account ID)
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

    ####################################################################
    # Jira agile
    #
    # list_project_boards
    # create_project_board
    # create_filter
    # list_boards
    # create_board

    @api_call
    def list_project_boards(
        self, project_id_or_key: Union[int, str]
    ) -> List[Dict[str, Any]]:
        """Returns the list of boards attached to project.

        # Required parameters

        - project_id_or_key: an integer or a non-empty string

        # Returned value

        A list of _boards_.  Each board is a dictionary with the
        following entries:

        - id: an integer
        - name: a string
        - self: a string
        - type: a string

        # Raised exceptions

        Browse project permission required (will raise an _ApiError_
        otherwise).
        """
        ensure_instance('project_id_or_key', (int, str))

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

        - project_id_or_key: an integer or a non-empty string
        - name: a non-empty string (the board name)
        - type: a string (the board type, e.g., `'scrum'`, `'kanban'`,
          `'simple'`)

        # Optional parameters

        - filter_id: an integer or a string (the filter ID)

        # Returned value

        A dictionary representing the created board.
        """
        ensure_instance('project_id_or_key', (int, str))
        ensure_nonemptystring('name')
        ensure_nonemptystring('type')
        ensure_noneorinstance('filter_id', (int, str))

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
    def create_filter(
        self,
        name: str,
        jql: str,
        *,
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
        - share_permissions: a list of dictionaries (optional, used for
          sharing the filter)
        - edit_permissions: a list of dictionaries (optional, used for
          editing permissions)

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

        # Returned value

        A list of _boards_.  Each board is a dictionary with the
        following entries:

        - name: a string
        - type: a string (`'scrum'` or `'kanban'` or `'simple'`)
        - id: an integer
        - self: a string (URL)

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
        """
        ensure_noneorinstance('params', dict)

        return self._collect_agile_data('board', params=params)

    @api_call
    def create_board(
        self,
        name: str,
        type: str,
        *,
        filter_id: Optional[int] = None,
        location: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a new board.

        # Required parameters

        - name: a non-empty string (the board name)
        - type: a string (the board type, e.g., `'scrum'`, `'kanban'`,
          `'simple'`)

        # Optional parameters

        - filter_id: an integer (the filter ID)
        - location: a dictionary (optional, used for specifying the
          board location)

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

    ####################################################################
    # Jira Cloud misc. schemes
    #
    # list_issuetypeschemes
    # list_issuetypescreenschemes
    # list_notificationschemes
    # list_permissionschemes
    # list_workflowschemes

    @api_call
    def list_issuetypescreenschemes(
        self,
        *,
        start_at: int = 0,
        max_results: int = 50,
        ids: Optional[List[int]] = None,
        query: Optional[str] = None,
        order_by: Optional[str] = None,
        expand: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        List issue type screen schemes.

        # Optional parameters

        - start_at: an integer (default: `0`)
        - max_results: an integer (default: `50`, maximum: `100`)
        - ids: a list of integers (optional, used for filtering by
          scheme IDs)
        - query: a string (optional, used for filtering by scheme name)
        - order_by: a string (optional, used for ordering results)
        - expand: a string (optional, used for expanding additional
          fields)

        # Returned value

        A list of dictionaries, each representing an issue type screen
        scheme.
        """
        ensure_instance('start_at', int)
        ensure_instance('max_results', int)
        ensure_noneorinstance('ids', list)
        ensure_noneorinstance('query', str)
        ensure_noneorinstance('order_by', str)
        ensure_noneorinstance('expand', str)

        params = {'startAt': start_at, 'maxResults': max_results}
        add_if_specified(params, 'id', ids)
        add_if_specified(params, 'queryString', query)
        add_if_specified(params, 'orderBy', order_by)
        add_if_specified(params, 'expand', expand)

        return self._collect_data('issuetypescreenscheme', params=params)

    @api_call
    def list_permissionschemes(self) -> List[Dict[str, Any]]:
        """Return the list of all permission schemes.

        # Returned value

        A list of _permission schemes_.  Each permission scheme is a
        dictionary with the following entries:

        - id: an integer
        - name: a string
        - description: a string (optional)
        - self: a string (an URL)
        """
        return self._get('permissionscheme')  # type: ignore

    @api_call
    def list_workflowschemes(
        self, *, start_at: int = 0, max_results: int = 50
    ) -> List[Dict[str, Any]]:
        """Return the list of all workflow schemes.

        # Optional parameters

        - start_at: an integer (default: `0`)
        - max_results: an integer (default: `50`, maximum: `100`)

        # Returned value

        A list of _workflow schemes_.  Each workflow scheme is a
        dictionary with the following entries:

        - id: an integer
        - name: a string
        - description: a string
        """
        params = {'startAt': start_at, 'maxResults': max_results}
        return self._collect_data('workflowscheme', params=params)

    @api_call
    def list_issuetypeschemes(
        self, *, start_at: int = 0, max_results: int = 50
    ) -> List[Dict[str, Any]]:
        """List issue type schemes.

        # Optional parameters

        - start_at: an integer (default: `0`)
        - max_results: an integer (default: `50`, maximum: `100`)

        # Returned value

        A list of _issue type schemes_.  Each issue type scheme is a
        dictionary with the following entries:

        - id: an integer
        - name: a string
        - description: a string
        """
        params = {'startAt': start_at, 'maxResults': max_results}
        return self._collect_data('issuetypescheme', params=params)

    @api_call
    def list_notificationschemes(
        self, *, start_at: int = 0, max_results: int = 50
    ) -> List[Dict[str, Any]]:
        """List notification schemes.

        # Optional parameters

        - start_at: an integer (default: `0`)
        - max_results: an integer (default: `50`, maximum: `100`)

        # Returned value

        A list of _notification schemes_.  Each notification scheme is a
        dictionary with the following entries:

        - id: an integer
        - name: a string
        - description: a string
        """
        params = {'startAt': start_at, 'maxResults': max_results}
        return self._collect_data('notificationscheme', params=params)

    ####################################################################
    # Jira Cloud roles
    #
    # list_roles

    def list_roles(self) -> List[Dict[str, Any]]:
        """Return the list of all roles.

        # Returned value

        A list of _roles_.  Each role is a dictionary  with the
        following entries:

        - actors: a list of dictionaries
        - id: an integer
        - description: a string (optional)
        - name: a string
        - scope : a list of dictionaries
        - self: a string

        `actors` entries have the following entries:

        - avatarUrl: a string
        - displayName: a string
        - id: an integer
        - name: a string
        - type: a string

        The `actors` entry may be missing.
        """
        response = self._get('role')

        return response.json()

    ####################################################################
    # Jira Service Desk
    #
    # list_servicedesks
    # create_request
    # get_request
    # list_request_comments
    # add_request_comment
    # add_request_participants
    # list_queues
    # list_queue_issues
    # list_requesttypes
    # list_requesttypes_fields
    # list_servicedesk_organizations
    # get_organization
    # create_organization
    # delete_organization
    # add_servicedesk_organization

    @api_call
    def list_servicedesks(self) -> List[Dict[str, Any]]:
        """Return the available service desks.

        # Returned value

        A list of _service desks_.  Each service desk is a dictionary
        with the following entries:

        - id: a string
        - projectId: a string
        - projectName: a string
        - projectKey: a string
        - _links: a dictionary
        """
        return self._collect_sd_data('servicedesk')

    @api_call
    def create_request(
        self,
        servicedesk_id: str,
        request_type_id: str,
        fields: Dict[str, Any],
        request_participants: Optional[List[str]] = None,
        raise_on_behalf_of: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new request in a service desk.

        # Required parameters

        - servicedesk_id: a non-empty string
        - request_type_id: a non-empty string
        - fields: a dictionary

        # Optional parameters

        - request_participants: a list of strings (account IDs) or None
        - raise_on_behalf_of: a string or None (optional, account ID)

        # Usage

        The `fields` dictionary content depends on the request type (as
        specified by `requesttype_id`).  It typically has at least the
        following two entries:

        - summary: a string
        - description: a string

        Refer to #list_requesttypes() for more information.

        # Returned value

        A dictionary representing the created request.

        """
        ensure_nonemptystring('servicedesk_id')
        ensure_nonemptystring('request_type_id')
        ensure_instance('fields', dict)
        ensure_noneorinstance('raise_on_behalf_of', str)
        ensure_noneorinstance('request_participants', list)

        params = {
            'serviceDeskId': servicedesk_id,
            'requestTypeId': request_type_id,
            'requestFieldValues': fields,
        }
        add_if_specified(params, 'requestParticipants', request_participants)
        add_if_specified(params, 'raiseOnBehalfOf', raise_on_behalf_of)

        response = self.session().post(
            join_url(self.SERVICEDESK_BASE_URL, 'request'), json=params
        )
        return response.json()

    @api_call
    def get_request(
        self, request_id_or_key: str, expand: Optional[str] = None
    ) -> Dict[str, Any]:
        """Return service desk request details.

        # Required parameters

        - request_id_or_key: a non-empty string

        # Optional parameters

        - expand: a string or None (None by default)

        # Returned value

        The _request_ details, a dictionary with the following entries:

        - active: a boolean
        - createDate: a dictionary
        - currentStatus: a dictionary
        - issueId: a string
        - issueKey: a string
        - reporter: a dictionary
        - requestFieldValues: a dictionary
        - requestTypeId: a string
        - serviceDeskId: a string
        - timeZone: a string

        There may be additional fields depending on the specified
        `expand` parameter.
        """
        ensure_nonemptystring('request_id_or_key')
        ensure_noneorinstance('expand', str)

        params = {}
        add_if_specified(params, 'expand', expand)

        response = self.session().get(
            join_url(
                self.SERVICEDESK_BASE_URL, f'request/{request_id_or_key}'
            ),
            params=params,
        )

        return response.json()

    @api_call
    def list_request_comments(
        self,
        request_id_or_key: str,
        public: bool = True,
        internal: bool = True,
        expand: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return the available comments for request.

        # Required parameters

        - request_id_or_key: a non-empty string

        # Optional parameters

        - public: a boolean (default: True, whether to include public
          comments)
        - internal: a boolean (default: True, whether to include
          internal comments)
        - expand: a string (optional, used for expanding additional
          fields)

        # Returned value

        A list of _request comments_.  Each request comment is a
        dictionary with the following entries:

        - author: a dictionary
        - body: a string
        - created: a string (a timestamp)
        - id: a string
        - public: a boolean
        - _links: a dictionary
        """
        ensure_nonemptystring('request_id_or_key')
        ensure_instance('public', bool)
        ensure_instance('internal', bool)
        ensure_noneorinstance('expand', str)

        params = {'public': public, 'internal': internal}
        add_if_specified(params, 'expand', expand)

        response = self._collect_sd_data(
            f'request/{request_id_or_key}/comment',
            params=params,
        )

        return response

    @api_call
    def add_request_participants(
        self, request_id_or_key: str, participants: List[str]
    ) -> bool:
        """Add participants to a request.

        # Required parameters

        - request_id_or_key: a non-empty string (the request ID or key)
        - participants: a list of strings (the account IDs of the
          participants)

        # Returned value

        A boolean.  True if successful, False otherwise.
        """
        ensure_nonemptystring('request_id_or_key')
        ensure_instance('participants', list)

        params = {'accountIds': participants}

        response = self.session().post(
            join_url(
                self.SERVICEDESK_BASE_URL,
                f'request/{request_id_or_key}/participant',
            ),
            json=params,
        )

        return response.status_code == 200

    @api_call
    def list_queues(
        self, servicedesk_id: str, include_count: bool = False
    ) -> List[Dict[str, Any]]:
        """List queues for a service desk.

        # Required parameters

        - servicedesk_id: a non-empty string

        # Optional parameters

        - include_count: a boolean (False by default)

        # Returned value

        A list of dictionaries, each representing a queue.
        Each queue has the following entries:

        - fields: a list of dictionaries
        - id: a string
        - issueCount: an integer (if `include_count` is True)
        - jql: a string
        - name: a string
        - _links: a dictionary
        """
        ensure_nonemptystring('servicedesk_id')
        ensure_instance('include_count', bool)

        params = {'includeCount': include_count}

        return self._collect_sd_data(
            f'servicedesk/{servicedesk_id}/queue', params=params
        )

    @api_call
    def list_queue_issues(
        self, servicedesk_id: str, queue_id: str
    ) -> List[Dict[str, Any]]:
        """Return the list of all issues in a given queue.

        # Required parameters

        - servicedesk_id: a non-empty string
        - queue_id: a non-empty string

        # Returned value

        A list of dictionaries.
        """
        ensure_nonemptystring('servicedesk_id')
        ensure_nonemptystring('queue_id')

        return self._collect_sd_data(
            f'servicedesk/{servicedesk_id}/queue/{queue_id}/issue',
        )

    @api_call
    def list_requesttypes(
        self, servicedesk_id: str, search_query: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List request types for a service desk.

        # Required parameters

        - servicedesk_id: a non-empty string (the service desk ID)

        # Optional parameters

        - search_query: a string

        # Returned value

        A list of _request types_.  Each request type is a dictionary
        with the following entries:

        - description: a string
        - groupIds: a list of strings
        - helpText: a string
        - icon: a dictionary
        - id: a string
        - name: a string
        - portalId: a string
        - serviceDeskId: a string
        - _links: a dictionary
        """
        ensure_nonemptystring('servicedesk_id')
        ensure_noneorinstance('search_query', str)

        params = {}
        add_if_specified(params, 'searchQuery', search_query)

        return self._collect_sd_data(
            f'servicedesk/{servicedesk_id}/requesttype',
            params=params,
        )

    @api_call
    def get_requesttype_fields(
        self,
        servicedesk_id: str,
        request_type_id: str,
        expand: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List fields for request type.

        # Required parameters

        - servicedesk_id: a non-empty string
        - request_type_id: a non-empty string

        # Optional parameters

        - expand: a string (optional, used for expanding additional
          fields)

        # Returned value

        A dictionary representing the fields for a specific request
        type.  The structure of the returned value is as follows:

        - canRaiseOnBehalfOf: a boolean
        - canRequestParticipants: a boolean
        - requestTypeFields: a list of dictionary with the following
          entries:

            - defaultValues: a list
            - description: a string
            - fieldId: a string
            - jiraSchema: a dictionary
            - name: a string
            - required: a boolean
            - validValues: a list
        """
        ensure_nonemptystring('servicedesk_id')
        ensure_nonemptystring('request_type_id')
        ensure_noneorinstance('expand', str)

        params = {}
        add_if_specified(params, 'expand', expand)

        response = self.session().get(
            join_url(
                self.SERVICEDESK_BASE_URL,
                f'servicedesk/{servicedesk_id}/requesttype/{request_type_id}/field',
            ),
            params=params,
        )
        return response.json()

    list_requesttypes_fields = get_requesttype_fields

    @api_call
    def list_servicedesk_organizations(
        self, servicedesk_id: str
    ) -> List[Dict[str, Any]]:
        """Return the list of all service desk organizations.

        # Required parameters

        - servicedesk_id: a non-empty string

        # Returned value

        A list of _organizations_.  An organization is a dictionary.

        Refer to #get_organization() for details on its structure.
        """
        ensure_nonemptystring('servicedesk_id')

        return self._collect_sd_data(
            f'servicedesk/{servicedesk_id}/organization',
        )

    @api_call
    def get_organization(
        self, organization_id: Union[int, str]
    ) -> Dict[str, Any]:
        """Get a specific organization by its ID.

        # Required parameters

        - organization_id: an integer or a string

        # Returned value

        The _organization_ details, a dictionary, with the following
        entries:

        - created : a dictionary
        - id: a string
        - name: a string
        - scimManaged: a boolean
        - uuid: a string
        - _links: a dictionary
        """
        ensure_instance('organization_id', (int, str))

        response = self.session().get(
            join_url(
                self.SERVICEDESK_BASE_URL, f'organization/{organization_id}'
            )
        )
        return response.json()

    @api_call
    def create_organization(self, name: str) -> Dict[str, Any]:
        """Create a new organization.

        # Required parameters

        - name: a non-empty string

        # Returned value

        The created _organization_ details, a dictionary, with the
        following entries:

        - id: an integer
        - name: a string
        - scimManaged: a boolean (indicating if the organization is
          managed by SCIM)
        - _links: a dictionary

        """
        ensure_nonemptystring('name')
        params = {'name': name}

        response = self.session().post(
            join_url(self.SERVICEDESK_BASE_URL, 'organization'), json=params
        )

        return response.json()

    @api_call
    def delete_organization(self, organization_id: Union[int, str]) -> bool:
        """Delete service desk organization.

        # Required parameters

        - organization_id: an integer or a string

        # Returned value

        A boolean.  True if successful, False otherwise.
        """
        ensure_instance('organization_id', (int, str))

        response = self.session().delete(
            join_url(
                self.SERVICEDESK_BASE_URL, f'organization/{organization_id}'
            ),
            headers={'Content-Type': 'application/json'},
        )
        return response.status_code == 204

    @api_call
    def add_servicedesk_organization(
        self, servicedesk_id: str, organization_id: Union[int, str]
    ) -> bool:
        """Add organization to service desk.

        # Required parameters

        - servicedesk_id: a non-empty string
        - organization_id: an integer or a string

        # Returned value

        A boolean.  True if successful, False otherwise.
        """
        ensure_nonemptystring('servicedesk_id')
        ensure_instance('organization_id', (int, str))

        params = {
            'organizationId': organization_id,
        }

        response = self.session().post(
            join_url(
                self.SERVICEDESK_BASE_URL,
                f'/servicedesk/{servicedesk_id}/organization',
            ),
            json=params,
        )
        return response.status_code == 204

    @api_call
    def add_request_comment(
        self, request_id_or_key: str, body: str, public: bool = False
    ) -> Dict[str, Any]:
        """Create public or private comment on request.

        # Required parameters

        - request_id_or_key: a non-empty string
        - body: a string

        # Optional parameters

        - public: a boolean (False by default)

        # Returned value

        A _request comment_.  A request comment is a dictionary with the
        following entries:

        - author: a dictionary
        - body: a string
        - created: a dictionary
        - id: a string
        - public: a boolean
        - _links: a dictionary

        The `author` dictionary has the following entries:

        - accountId: a string
        - active: a boolean
        - displayName: a string
        - emailAddress: a string
        - key: a string
        - name: a string
        - timeZone: a string
        - _links: a dictionary

        The `created` dictionary has the following entries:

        - epochMillis: an integer
        - friendly: a string
        - iso8601: a string (an ISO8601 timestamp)
        - jira: a string (an ISO8601 timestamp)
        """
        ensure_nonemptystring('request_id_or_key')
        ensure_nonemptystring('body')
        ensure_instance('public', bool)

        params = {'body': body, 'public': public}

        response = self.session().post(
            join_url(
                self.SERVICEDESK_BASE_URL,
                f'request/{request_id_or_key}/comment',
            ),
            json=params,
        )

        return response.json()

    ####################################################################
    # Jira Cloud helpers

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
        headers: Optional[Mapping[str, str]] = None,
    ) -> requests.Response:
        return self.session().get(
            self._get_url(uri),
            params=params,
            headers=headers,
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

    def _put(
        self,
        uri: str,
        params: Optional[Mapping[str, Any]] = None,
        json: Optional[Mapping[str, Any]] = None,
    ) -> requests.Response:
        return self.session().put(
            self._get_url(uri),
            params=params,
            json=json,
            auth=self.auth,
            timeout=TIMEOUT,
        )

    def _collect_data(
        self,
        uri: str,
        params: Optional[Mapping[str, Union[str, List[str], None]]] = None,
        base: Optional[str] = None,
        headers: Optional[Mapping[str, str]] = None,
        start_at: str = 'startAt',
        is_last: str = 'isLast',
        key: str = 'values',
    ) -> List[Any]:
        api_url = self._get_url(uri) if base is None else join_url(base, uri)
        collected: List[Any] = []
        _params = dict(params or {})
        more = True
        while more:
            response = self.session().get(
                api_url, params=_params, headers=headers
            )
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

    def _delete(
        self,
        uri: str,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> requests.Response:
        return self.session().delete(
            self._get_url(uri),
            params=params,
            headers=headers,
            auth=self.auth,
            timeout=TIMEOUT,
        )

    def _collect_sd_data(
        self,
        api: str,
        params: Optional[Mapping[str, Union[str, List[str], None]]] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> List[Any]:
        return self._collect_data(
            api,
            params=params,
            base=self.SERVICEDESK_BASE_URL,
            headers=headers,
            start_at='start',
            is_last='isLastPage',
        )

    def _collect_agile_data(
        self,
        api: str,
        params: Optional[Mapping[str, Union[str, List[str], None]]] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> List[Any]:
        return self._collect_data(
            api,
            params=params,
            base=self.AGILE_BASE_URL,
            headers=headers,
            start_at='startAt',
            is_last='isLast',
        )
