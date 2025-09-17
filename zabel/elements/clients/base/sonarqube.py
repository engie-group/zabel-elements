# Copyright (c) 2019 Martin Lafaix (martin.lafaix@external.engie.com)
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

"""SonarQube.

A base class wrapping SonarQube APIs.

There can be as many SonarQube instances as needed.

This module depends on the public **requests** library.  It also depends
on three **zabel-commons** modules, #::zabel.commons.exceptions,
#::zabel.commons.sessions, and #::zabel.commons.utils.

A base class wrapper only implements 'simple' API requests.  It handles
pagination if appropriate, but does not process the results or compose
API requests.
"""

from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Union

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
)


########################################################################
########################################################################

PROJECT_PERMISSIONS = [
    'admin',
    'codeviewer',
    'issueadmin',
    'scan',
    'user',
    'securityhotspotadmin',
]

GLOBAL_PERMISSIONS = [
    'admin',
    'gateadmin',
    'profileadmin',
    'provisioning',
    'scan',
    'applicationcreator',
    'portfoliocreator',
]

QUALIFIERS = {
    'APP': 'Applications',
    'BRC': 'Sub-projects',
    'DIR': 'Directories',
    'FIL': 'Files',
    'SVW': 'Portfolios',
    'TRK': 'Projects',
    'UTS': 'Test Files',
    'VW': 'Portfolios',
}

EVENT_CATEGORIES = [
    'VERSION',
    'OTHER',
    'QUALITY_PROFILE',
    'QUALITY_GATE',
    'DEFINITION_CHANGE',
]

# SonarQube low-level api


class SonarQube:
    """SonarQube Base-Level API Wrapper.

    There can be as many SonarQube instances as needed.

    This class depends on the public **requests** library.  It also
    depends on three **zabel-commons** modules,
    #::zabel.commons.exceptions, #::zabel.commons.sessions,
    and #::zabel.commons.utils.

    ## Reference URLs

    - <https://docs.sonarqube.org/display/DEV/Web+API>
    - <https://next.sonarqube.com/sonarqube/web_api_v2>

    ### Web API URLs

    - <https://sonar.example.com/sonar/web_api>

    ## Implemented features

    - applications (incomplete)
    - components (incomplete)
    - languages
    - permissions
    - permissionstemplates
    - projectanalyses (incomplete)
    - projects (incomplete)
    - qualitygates (incomplete)
    - qualityprofiles (incomplete)
    - tokens
    - usergroups
    - users
    - misc. operations

    Some features may be specific to the Enterprise Edition, but as long
    as they are not used directly, the library can be used with the
    Community edition too.

    When using SonarCloud, the `organization_key` parameter must be
    specified for methods that declare it.

    Tested on SonarQube v9.9 and v10.4.

    ## Conventions

    `'_'` are removed from SonarQube entrypoints names, to prevent
    confusion.

    Getters exhaust results (they return all items matching the query,
    there is no need for paging).

    `list_xxx` methods take a possibly optional filter argument and
    return a list of matching items.

    ## Permissions, qualifiers and event categories

    | Item                  | Possible values
    | ---                   | -----
    | `PROJECT_PERMISSIONS` | `'admin'`, `'codeviewer'`, `'issueadmin'`,
                              `'scan'`, `'user'`, `'securityhotspotadmin'`
    | `GLOBAL_PERMISSIONS`  | `'admin'`, `'gateadmin'`, `'profileadmin'`,
                              `'provisioning'`, `'scan'`,
                              `'applicationcreator'`, `'portfoliocreator'`
    | `QUALIFIERS`          | `'BRC'`, `'DIR'`,` 'FIL'`, `'TRK'`, `'UTS'`
    | `EVENT_CATEGORIES`    | `'VERSION'`, `'OTHER'`, `'QUALITY_PROFILE'`,
                              `'QUALITY_GATE'`, `'DEFINITION_CHANGE'`

    ## Examples

    Using a private SonarQube instance:

    ```python
    from zabel.elements.clients import SonarQube

    url = 'https://sonar.example.com/sonar/api/'
    token = '...'
    sq = SonarQube(url, token)
    sq.list_projects()
    ```

    Using SonarCloud:

    ```python
    from zabel.elements.clients import SonarQube

    url = 'https://sonarcloud.io/api/'
    token = '...'
    sq = SonarQube(url, token)
    sq.list_projects(organization_key='my_organization')
    ```
    """

    def __init__(self, url: str, token: str, verify: bool = True) -> None:
        """Create a SonarQube instance object.

        If a required operation is not allowed for the specified token,
        an _ApiError_ will be raised.

        # Required parameters

        - url: a non-empty string
        - token: a string

        # Optional parameters

        - verify: a boolean (True by default)

        # Usage

        The `url` parameter is the top-level API point. For example:

            'https://sonar.example.com/sonar/api/'

        If you are using the public SonarCloud instance, it would be:

            'https://sonarcloud.io/api/'

        `verify` can be set to False if disabling certificate checks for
        SonarQube communication is required.  Tons of warnings will
        occur if this is set to False.
        """
        ensure_nonemptystring('url')
        ensure_instance('token', str)

        self.url = url
        self.auth = (token, '')
        self.verify = verify
        self.session = prepare_session(self.auth, verify=verify)

    def __str__(self) -> str:
        return f'{self.__class__.__name__}: {self.url}'

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}: {self.url!r}, '{self.auth[0][:4]}****'>"

    ####################################################################
    # SonarQube applications
    #
    # create_application
    # get_application

    @api_call
    def create_application(
        self,
        name: str,
        description: Optional[str] = None,
        key: Optional[str] = None,
        visibility: str = 'private',
    ) -> Dict[str, Any]:
        """Create a new application.

        # Required parameters

        - name: a non-empty string

        # Optional parameters

        - description: a string or None (None by default)
        - key: a string or None (None by default)
        - visibility: `'public'` or `'private'` (`'private'` by default)

        # Returned value

        A dictionary with the following entry:

        - application: a dictionary

        The `application` dictionary has the following entries:

        - key: a string
        - name: a string
        - description: a string
        - visibility: a string
        - projects: a possibly empty list of dictionaries
        """
        ensure_nonemptystring('name')
        ensure_noneornonemptystring('description')
        ensure_noneornonemptystring('key')
        ensure_in('visibility', ['private', 'public'])

        data = {'name': name, 'visibility': visibility}
        add_if_specified(data, 'key', key)
        add_if_specified(data, 'description', description)

        result = self._post('applications/create', data)
        return result  # type: ignore

    @api_call
    def get_application(
        self, key: str, branch: Optional[str] = None
    ) -> Dict[str, Any]:
        """Return the application details.

        # Required parameters

        - key: a non-empty string

        # Optional parameters

        - branch: a non-empty string or None (None by default)

        # Returned value

        A dictionary with the following content:

        ```python
        {
          "application": {
            "key": a string,
            "name": a string,
            "branch": a string,
            "isMain": a boolean,
            "projects": [
              {
                "key": a string,
                "name": a string,
                "branch": a string,
                "isMain": a boolean,
                "enabled": a boolean,
                "selected": a boolean
              },
              ...
            ],
            "branches": [
              {
                "name": a string,
                "isMain": a boolean
              },
              ...
            ]
          }
        }
        ```
        """
        ensure_nonemptystring('key')
        ensure_noneornonemptystring('branch')

        params = {'application': key}
        add_if_specified(params, 'branch', branch)

        result = self._get('applications/show', params=params)
        return result  # type: ignore

    ####################################################################
    # SonarQube components
    #
    # list_components

    @api_call
    def list_components(
        self,
        qualifiers: str,
        language: Optional[str] = None,
        organization_key: Optional[str] = None,
    ) -> List[Dict[str, str]]:
        """Return the matching components list.

        If `language` is provided, only components for the given
        language are returned.

        `qualifiers` is a comma-separated list of qualifiers.  Each
        qualifier must be in `QUALIFIERS`.

        # Required parameters

        - qualifiers: a non-empty string

        # Optional parameters

        - language: a non-empty string or None (None by default)
        - organization_key: a non-empty string or None (None by default)

        # Returned value

        A list of _components_.  Each component is a dictionary with the
        following entries:

        - organization: a string
        - id: a string
        - key: a string
        - qualifier: a string
        - name: a string
        - project: a string
        """
        ensure_nonemptystring('qualifiers')
        ensure_noneornonemptystring('language')
        ensure_noneornonemptystring('organization_key')

        params = {'qualifiers': qualifiers}
        add_if_specified(params, 'language', language)
        add_if_specified(params, 'organization', organization_key)

        return self._collect_data('components/search', 'components', params)

    ####################################################################
    # SonarQube languages
    #
    # list_languages

    @api_call
    def list_languages(self) -> List[Dict[str, str]]:
        """Return a list of supported languages.

        # Returned value

        A list of _languages_.  Each language is a dictionary with the
        following entries:

        - key: a string
        - name: a string
        """
        return self._get('languages/list').json()['languages']  # type: ignore

    ####################################################################
    # SonarQube measures
    #
    # list_component_measures

    @api_call
    def list_component_measures(
        self,
        component_key: str,
        metric_keys: str,
        additional_fields: Optional[str] = None,
        branch: Optional[str] = None,
        pull_request: Optional[Union[int, str]] = None,
    ) -> List[Dict[str, Any]]:
        """Return component with specified measures.

        # Required parameters

        - component_key: a string
        - metric_keys: a string

        # Optional parameters

        - additional_fields: a string or None (None by default)
        - branch: a string or None (None by default)
        - pull_request: a integer or a string or None (None by default)

        # Returned value

        A dictionary.
        """
        ensure_instance('component_key', str)
        ensure_instance('metric_keys', str)

        params = {'component': component_key, 'metricKeys': metric_keys}
        add_if_specified(params, 'additionalFields', additional_fields)
        add_if_specified(params, 'branch', branch)
        add_if_specified(params, 'pullRequest', pull_request)

        result = self._get('measures/component', params=params).json()
        return result.get('component', {}).get('measures')

    ####################################################################
    # SonarQube permissions
    #
    # add_permission_group
    # add_permission_user
    # remove_permission_group
    # remove_permission_user

    @api_call
    def add_permission_group(
        self,
        permission: str,
        *,
        group_id: Optional[int] = None,
        group_name: Optional[str] = None,
        project_id: Optional[int] = None,
        project_key: Optional[str] = None,
    ) -> None:
        """Add a permission to a group.

        If neither `project_id` nor `project_key` are provided, it will
        change the global permissions for the specified group.

        # Required parameters

        - permission: a string
        - group_id: an integer or None
        - group_name: a string or None

        One and only one of `group_id` or `group_name` must be provided.

        # Optional parameters

        - project_id: an integer or None
        - project_key: a string or None

        At most one of `project_id` or `project_key` can be provided.
        """
        ensure_onlyone('group_id', 'group_name')
        if project_id is None and project_key is None:
            if permission not in GLOBAL_PERMISSIONS:
                raise ValueError('Invalid global permission')
        elif permission not in PROJECT_PERMISSIONS:
            raise ValueError('Invalid project permission')

        data = {'permission': permission}
        add_if_specified(data, 'groupId', group_id)
        add_if_specified(data, 'groupName', group_name)
        add_if_specified(data, 'projectId', project_id)
        add_if_specified(data, 'projectKey', project_key)

        result = self._post('permissions/add_group', data)
        return result  # type: ignore

    @api_call
    def add_permission_user(
        self,
        permission: str,
        login: str,
        *,
        project_id: Optional[int] = None,
        project_key: Optional[str] = None,
    ) -> None:
        """Add a permission to a user.

        If neither `project_id` nor `project_key` are provided, it will
        change the global permissions for the specified user.

        # Required parameters

        - permission: a string
        - login: a string

        # Optional parameters

        - project_id: an integer or None
        - project_key: a string or None

        At most one of `project_id` or `project_key` can be provided.
        """
        ensure_instance('permission', str)
        ensure_instance('login', str)

        if project_id is None and project_key is None:
            if permission not in GLOBAL_PERMISSIONS:
                raise ValueError('Invalid global permission')
        elif permission not in PROJECT_PERMISSIONS:
            raise ValueError('Invalid project permission')

        data = {'login': login, 'permission': permission}
        add_if_specified(data, 'projectId', project_id)
        add_if_specified(data, 'projectKey', project_key)

        result = self._post('permissions/add_user', data)
        return result  # type: ignore

    @api_call
    def remove_permission_group(
        self,
        permission: str,
        *,
        group_id: Optional[int] = None,
        group_name: Optional[str] = None,
        project_id: Optional[int] = None,
        project_key: Optional[str] = None,
    ) -> None:
        """Remove a permission from a group.

        If neither `project_id` nor `project_key` are provided, it will
        change the global permissions for the specified group.

        # Required parameters

        - permission: a string
        - group_id: an integer or None
        - group_name: a string or None

        One and only one of `group_id` or `group_name` must be provided.

        # Optional parameters

        - project_id: an integer or None
        - project_key: a string or None

        At most one of `project_id` or `project_key` can be provided.
        """
        ensure_onlyone('group_id', 'group_name')
        if project_id is None and project_key is None:
            if permission not in GLOBAL_PERMISSIONS:
                raise ValueError('Invalid global permission')
        elif permission not in PROJECT_PERMISSIONS:
            raise ValueError('Invalid project permission')

        data = {'permission': permission}
        add_if_specified(data, 'groupId', group_id)
        add_if_specified(data, 'groupName', group_name)
        add_if_specified(data, 'projectId', project_id)
        add_if_specified(data, 'projectKey', project_key)

        result = self._post('permissions/remove_group', data)
        return result  # type: ignore

    @api_call
    def remove_permission_user(
        self,
        permission: str,
        login: str,
        *,
        project_id: Optional[int] = None,
        project_key: Optional[str] = None,
    ) -> None:
        """Remove a permission from a user.

        If neither `project_id` nor `project_key` are provided, it will
        change the global permissions for the specified user.

        # Required parameters

        - permission: a string
        - login: a string

        # Optional parameters

        - project_id: an integer or None
        - project_key: a string or None

        At most one of `project_id` or `project_key` can be provided.
        """
        if project_id is None and project_key is None:
            if permission not in GLOBAL_PERMISSIONS:
                raise ValueError('Invalid global permission')
        elif permission not in PROJECT_PERMISSIONS:
            raise ValueError('Invalid project permission')

        data = {'login': login, 'permission': permission}
        add_if_specified(data, 'projectId', project_id)
        add_if_specified(data, 'projectKey', project_key)

        result = self._post('permissions/remove_user', data)
        return result  # type: ignore

    ####################################################################
    # SonarQube permissionstemplates
    #
    # create_permissionstemplate
    # list_permissionstemplates
    # update_permissionstemplate
    # add_permissionstemplate_group
    # apply_permissionstemplate

    @api_call
    def create_permissionstemplate(
        self,
        name: str,
        description: Optional[str] = None,
        project_key_pattern: Optional[str] = None,
        organization_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new permissions template.

        If provided, `project_key_pattern` must be a valid Java regular
        expression.

        # Required parameters

        - name: a string

        # Optional parameters

        - description: a string or None (None by default)
        - project_key_pattern: a string or None (None by default)
        - organization_key: a non-empty string or None (None by default)

        # Returned value

        A dictionary with the following entry:

        - permissionTemplate: a dictionary

        The `permissionTemplate` dictionary has the following entries:

        - description: a string
        - name: a string
        - projectKeyPattern: a string
        """
        ensure_nonemptystring('name')
        ensure_noneorinstance('description', str)
        ensure_noneorinstance('project_key_pattern', str)
        ensure_noneornonemptystring('organization_key')

        data = {'name': name}
        add_if_specified(data, 'description', description)
        add_if_specified(data, 'projectKeyPattern', project_key_pattern)
        add_if_specified(data, 'organization', organization_key)

        result = self._post('permissions/create_template', data)
        return result  # type: ignore

    @api_call
    def list_permissionstemplates(
        self,
        query: Optional[str] = None,
        organization_key: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List the matching permissions templates.

        If `query` is specified, will only returns the permissions
        templates that contain it in their names.

        # Optional parameters

        - query: a string or None (None by default)
        - organization_key: a non-empty string or None (None by default)

        # Returned value

        A list of _permissions templates_.  Each permissions template
        is a dictionary with the following entries:

        - createdAt: a string (containing a timestamp)
        - description: a string
        - id: a string
        - name: a string
        - permissions: a list
        - projectKeyPattern: a string (if present)
        - updatedAt: a string (containing a timestamp)

        Each entry in the `permissions` list is a dictionary with the
        following entries:

        - usersCount: an integer
        - groupsCount: an integer
        - key: a string
        - withProjectCreator: a boolean
        """
        ensure_noneorinstance('query', str)
        ensure_noneornonemptystring('organization_key')

        params = {}
        add_if_specified(params, 'organization', organization_key)
        add_if_specified(params, 'q', query)

        return self._collect_data(
            'permissions/search_templates',
            'permissionTemplates',
            params,
        )

    @api_call
    def update_permissionstemplate(
        self,
        permissionstemplate_id: str,
        description: Optional[str] = None,
        name: Optional[str] = None,
        project_key_pattern: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update a permissions template.

        If provided, `project_key_pattern` must be a valid Java regular
        expression.

        # Required parameters

        - permissionstemplate_id: a non-empty string

        # Optional parameters

        - description: a string or None (None by default)
        - name: a string or None (None by default)
        - project_key_pattern: a string or None (None by default)

        # Returned value

        A dictionary with the following entry:

        - permissionTemplate: a dictionary

        The `permissionTemplate` dictionary has the following entries:

        - createdAt: a string (an ISO timestamp)
        - description: a string
        - id: a string
        - name: a string
        - projectKeyPattern: a string
        - updatedAt: a string (an ISO timestamp)
        """
        ensure_nonemptystring('permissionstemplate_id')
        ensure_noneorinstance('description', str)
        ensure_noneorinstance('name', str)
        ensure_noneorinstance('project_key_pattern', str)

        data = {'id': permissionstemplate_id}
        add_if_specified(data, 'description', description)
        add_if_specified(data, 'name', name)
        add_if_specified(data, 'projectKeyPattern', project_key_pattern)

        result = self._post('permissions/update_template', data)
        return result  # type: ignore

    @api_call
    def add_permissionstemplate_group(
        self, template_name: str, group_name: str, permission: str
    ) -> None:
        """Add a group to permissions template with specified permission.

        If more than one permission is to be added to a group, call this
        method repeatedly.

        # Required parameters

        - template_name: a non-empty string
        - group_name: a non-empty string
        - permission: a non-empty string
        """
        ensure_nonemptystring('template_name')
        ensure_nonemptystring('group_name')
        ensure_nonemptystring('permission')

        if permission not in PROJECT_PERMISSIONS:
            raise ValueError(f'Unexpected value {permission} for permission')

        data = {
            'groupName': group_name,
            'templateName': template_name,
            'permission': permission,
        }

        result = self._post('permissions/add_group_to_template', data)
        return result  # type: ignore

    @api_call
    def apply_permissionstemplate(
        self,
        template_name: str,
        *,
        project_id: Optional[int] = None,
        project_key: Optional[str] = None,
    ) -> None:
        """Apply a permission template to one project.

        # Required parameters

        - template_name: a non-empty string
        - project_id: an integer or None
        - project_key: a non-empty string or None (None by default)

        One and only one of `project_id` or `project_key` must be
        provided.
        """
        ensure_nonemptystring('template_name')
        ensure_onlyone('project_id', 'project_key')

        data = {'templateName': template_name}
        add_if_specified(data, 'projectKey', project_key)
        add_if_specified(data, 'projectId', project_id)

        result = self._post('permissions/apply_template', data)
        return result  # type: ignore

    ####################################################################
    # SonarQube users
    #
    # create_user
    # list_user_groups
    # search_users
    # get_user
    # update_user
    # deactivate_user

    @api_call
    def create_user(
        self,
        login: str,
        name: str,
        password: Optional[str] = None,
        email: Optional[str] = None,
        local: bool = True,
    ) -> Dict[str, Any]:
        """Create a new user.

        # Required parameters

        - login: a non-empty string
        - name: a string

        # Optional parameters

        - password: a string or None (None by default)
        - email: a string or None (None by default)
        - local: a boolean (True by default)

        `password` must be set for local users.
        `password` must not be set for non-local users.

        `scmAccount` not yet implemented.

        # Returned value

        A dictionary with the following entry:

        - user: a dictionary

        The `user` dictionary with the following entries:

        - active: a boolean
        - email: a string
        - local: a boolean
        - login: a string
        - name: a string
        - scmAccount: a list of strings
        """
        ensure_nonemptystring('login')
        ensure_instance('name', str)

        if local and password is None:
            raise ValueError('password must be set for local users')
        if not local and password is not None:
            raise ValueError('password must not be set for non-local users')

        data = {
            'login': login,
            'name': name,
            'local': 'true' if local else 'false',
        }
        add_if_specified(data, 'password', password)
        add_if_specified(data, 'email', email)

        result = self._post('users/create', data)
        return result  # type: ignore

    @api_call
    def list_user_groups(
        self,
        login: str,
        selected: str = 'selected',
        query: Optional[str] = None,
        organization_key: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List the groups a user belongs to.

        # Required parameters

        - login: a non-empty string

        # Optional parameters

        - selected: a string (`'selected'` by default)
        - query: a string or None (None by default)
        - organization_key: a non-empty string or None (None by default)

        # Returned value

        A list of _groups_.  Each group is a dictionary with the
        following entries:

        - default: a boolean
        - description: a string
        - id: an integer
        - name: a string
        - selected: a boolean
        """
        ensure_nonemptystring('login')
        ensure_instance('selected', str)
        ensure_noneorinstance('query', str)
        ensure_noneornonemptystring('organization_key')

        params = {'login': login, 'selected': selected}
        add_if_specified(params, 'q', query)
        add_if_specified(params, 'organization', organization_key)

        return self._collect_data('users/groups', 'groups', params)

    @api_call
    def search_users(
        self, query: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Return the matching users list.

        # Optional parameters

        - query: a non-empty string or None (None by default)

        # Returned value

        A list of _users_.  Each user is a dictionary with the following
        entries:

        - active: a boolean
        - avatar: a string
        - email: a string, possibly empty
        - externalIdentity: a string
        - externalProvider: a string
        - groups: a list of strings
        - lastConnectionDate
        - local: a boolean
        - login: a string
        - name: a string
        - tokensCount: an integer
        """
        ensure_noneornonemptystring('query')

        return self._collect_data(
            'users/search', 'users', None if query is None else {'q': query}
        )

    @api_call
    def get_user(self, login: str) -> Dict[str, Any]:
        """Return a user details.

        Performs a case-insensitive strict match (i.e., `login` case
        is insignificant, but no fuzzy matching occurs).

        # Required parameters

        - login: a non-empty string

        # Returned value

        A dictionary.  Refer to #search_users() for more information.

        # Raised exceptions

        Raises an _ApiError_ if user not known.
        """
        ensure_nonemptystring('login')

        users: List[Dict[str, Any]] = [
            user
            for user in self._collect_data(
                'users/search', 'users', {'q': login}
            )
            if user['login'].upper() == login.upper()
        ]

        if not users:
            raise ApiError(f'User not known ({login})')

        return users[0]

    @api_call
    def update_user(
        self,
        login: str,
        email: Optional[str] = None,
        name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update a user details.

        At least one of the optional parameters must be specified.

        # Required parameters

        - login: a non-empty string

        # Optional parameters

        - email: a non-empty string or None (None by default)
        - name: a non-empty string or None (None by default)

        # Returned value

        A dictionary.  Refer to #search_users() for more information.
        """
        ensure_nonemptystring('login')
        ensure_noneornonemptystring('email')
        ensure_noneornonemptystring('name')

        data = {'login': login}
        add_if_specified(data, 'email', email)
        add_if_specified(data, 'name', name)

        result = self._post('users/update', data)
        return result  # type: ignore

    @api_call
    def deactivate_user(
        self, login: str, anonymize: bool = False
    ) -> Dict[str, Any]:
        """Deactivate a user and optionally anonymize it.

        # Required parameters

        - login: a non-empty string

        # Optional parameters

        - anonymize: a boolean (False by default)

        # Returned value

        A dictionary with the following entry:

        - user: a dictionary

        Refer to #create_user() for more details on its content.
        """
        ensure_nonemptystring('login')
        ensure_instance(anonymize, bool)

        data = {'login': login, 'anonymize': anonymize}

        result = self._post('users/deactivate', json=data)
        return result  # type: ignore

    @api_call
    def update_identity_provider(
        self,
        login: str,
        provider: str,
        external_identity: Optional[str] = None,
    ):
        """Update identity provider

        # Required parameters

        - login: a non-empty string
        - provider: a non-empty string

        # Optional parameters

        - external_identity: a string or None (None by default)
        """
        ensure_nonemptystring('login')
        ensure_noneornonemptystring('provider')
        ensure_noneornonemptystring('external_identity')

        data = {'login': login, 'newExternalProvider': provider}
        add_if_specified(data, 'newExternalIdentity', external_identity)

        self._post('users/update_identity_provider', data)

    ####################################################################
    # SonarQube qualitygates
    #
    # create_qualitygate
    # delete_qualitygate
    # list_qualitygates
    # TODO set_project_qualitygate (?)

    @api_call
    def create_qualitygate(
        self, name: str, organization_key: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create a new quality gate.

        # Required parameters

        - name: a non-empty string

        # Optional parameters

        - organization_key: a non-empty string or None (None by default)

        # Returned value

        A dictionary with the following two entries:

        - id: an integer
        - name: a string

        # Raised exceptions

        If a quality gate with the same name already exists, an
        _ApiError_ exception is raised.
        """
        ensure_nonemptystring('name')
        ensure_noneornonemptystring('organization_key')

        params = {'name': name}
        add_if_specified(params, 'organization', organization_key)

        result = self._post('qualitygates/create', params)
        return result  # type: ignore

    @api_call
    def delete_qualitygate(
        self, name: str, organization_key: Optional[str] = None
    ) -> None:
        """Delete a quality gate.

        # Required parameters

        - name: a string

        # Optional parameters

        - organization_key: a non-empty string or None (None by default)

        # Raised exceptions

        An _ApiError_ exception is raised if the quality gate does not
        exist.
        """
        ensure_instance('name', str)
        ensure_noneornonemptystring('organization_key')

        params = {'name': name}
        add_if_specified(params, 'organization', organization_key)

        result = self._post('qualitygates/destroy', params)
        return result  # type: ignore

    @api_call
    def list_qualitygates(
        self, organization_key: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Return a list of existing quality gates.

        # Optional parameters

        - organization_key: a non-empty string or None (None by default)

        # Returned value

        A list of _quality gates_.  Each quality gate is a dictionary
        with the following two entries:

        - id: an integer
        - name: a string
        """
        ensure_noneornonemptystring('organization_key')

        if organization_key:
            params = {'organization': organization_key}
        else:
            params = None

        return self._collect_data('qualitygates/list', 'qualitygates', params)

    ####################################################################
    # SonarQube qualityprofiles
    #
    # create_qualityprofile
    # list_qualityprofiles
    # update_qualityprofile_parent
    # add_qualityprofile_group
    # add_qualityprofile_project
    # add_qualityprofile_user

    @api_call
    def create_qualityprofile(
        self,
        profile_name: str,
        language: str,
        organization_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new quality profile.

        # Required parameters

        - profile_name: a non-empty string
        - language: a non-empty string

        `language` must be a valid language.

        # Optional parameters

        - organization_key: a non-empty string or None (None by default)

        # Returned value

        A dictionary with the following two entries:

        - profile: a dictionary
        - ?warnings: a list of strings

        `profile` is a dictionary with the following entries:

        - isDefault: a boolean
        - isInherited: a boolean
        - key: a string
        - language: a string
        - languageName: a string
        - name: a string
        """
        ensure_nonemptystring('profile_name')
        ensure_in('language', [l['key'] for l in self.list_languages()])
        ensure_noneornonemptystring('organization_key')

        params = {'name': profile_name, 'language': language}
        add_if_specified(params, 'organization', organization_key)
        result = self._post(
            'qualityprofiles/create',
            params,
        )
        return result  # type: ignore

    @api_call
    def list_qualityprofiles(
        self,
        defaults: bool = False,
        language: Optional[str] = None,
        project_key: Optional[str] = None,
        profile_name: Optional[str] = None,
        organization_key: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return a list of matching quality profiles.

        # Optional parameters

        - defaults: a boolean (False by default)
        - language: a string or None (None by default)
        - project_key: a string or None (None by default)
        - profile_name: a string or None (None by default)
        - organization_key: a non-empty string or None (None by default)

        # Returned value

        A list of _quality profiles_.  Each quality profile is a
        dictionary with the following entries:

        - actions: a dictionary
        - activeDeprecatedRuleCount: an integer
        - activeRuleCount: an integer
        - isBuiltIn: a boolean
        - isDefault: a boolean
        - isInherited: a boolean
        - key: a string
        - language: a string
        - languageName: a string
        - lastUsed: a string
        - name: a string
        - ruleUpdatedAt: a string
        """
        ensure_instance('defaults', bool)
        ensure_noneornonemptystring('language')
        ensure_noneornonemptystring('project_key')
        ensure_noneornonemptystring('profile_name')
        ensure_noneornonemptystring('organization_key')
        if language is not None:
            ensure_in('language', [l['key'] for l in self.list_languages()])

        params = {'defaults': 'true' if defaults else 'false'}
        add_if_specified(params, 'language', language)
        add_if_specified(params, 'project', project_key)
        add_if_specified(params, 'qualityProfile', profile_name)
        add_if_specified(params, 'organization', organization_key)

        result = self._get('qualityprofiles/search', params=params).json()
        return result['profiles']  # type: ignore

    @api_call
    def add_qualityprofile_project(
        self,
        profile_name: str,
        language: str,
        project_key: str,
        organization_key: Optional[str] = None,
    ) -> None:
        """Associate quality profile to project.

        If the project is already added, nothing occurs.

        # Required parameters

        - profile_name: a non-empty string
        - language: a non-empty string
        - project_key: a non-empty string

        # Optional parameters

        - organization_key: a non-empty string or None (None by default)

        # Raised exceptions

        An _ApiError_ exception is raised if `profile_name` or
        `project_key` does not exist.
        """
        ensure_nonemptystring('profile_name')
        ensure_nonemptystring('language')
        ensure_nonemptystring('project_key')
        ensure_noneornonemptystring('organization_key')

        params = {
            'qualityProfile': profile_name,
            'language': language,
            'project': project_key,
        }
        add_if_specified(params, 'organization', organization_key)

        result = self._post(
            'qualityprofiles/add_project',
            params,
        )
        return result  # type: ignore

    @api_call
    def update_qualityprofile_parent(
        self, profile_name: str, language: str, parent_name: str
    ) -> None:
        """Change quality profile parent.

        # Required parameters

        - profile_name: a non-empty string
        - language: a non-empty string
        - parent_name: a non-empty string
        """
        ensure_nonemptystring('profile_name')
        ensure_nonemptystring('language')
        ensure_nonemptystring('parent_name')

        result = self._post(
            'qualityprofiles/change_parent',
            {
                'qualityProfile': profile_name,
                'language': language,
                'parentQualityProfile': parent_name,
            },
        )
        return result  # type: ignore

    @api_call
    def add_qualityprofile_user(
        self, profile_name: str, language: str, login: str
    ) -> None:
        """Add user to quality profile writers.

        Internal API.

        # Required parameters

        - profile_name: a non-empty string
        - language: a non-empty string, the quality profile language
        - login: a non-empty string, the user login to add
        """
        ensure_nonemptystring('profile_name')
        ensure_nonemptystring('language')
        ensure_nonemptystring('login')

        data = {
            'qualityProfile': profile_name,
            'language': language,
            'login': login,
        }

        result = self._post('qualityprofiles/add_user', data)
        return result  # type: ignore

    @api_call
    def add_qualityprofile_group(
        self, profile_name: str, language: str, group: str
    ) -> None:
        """Add group to quality profile writers.

        Internal API.

        # Required parameters

        - profile_name: a non-empty string
        - language: a non-empty string, the quality profile language
        - group: a non-empty string, the user group to add
        """
        ensure_nonemptystring('profile_name')
        ensure_nonemptystring('language')
        ensure_nonemptystring('group')

        data = {
            'qualityProfile': profile_name,
            'language': language,
            'group': group,
        }

        result = self._post('qualityprofiles/add_group', data)
        return result  # type: ignore

    ####################################################################
    # SonarQube tokens
    #
    # generate_token
    # revoke_token
    # list_tokens

    @api_call
    def generate_token(self, login: str, name: str) -> Dict[str, str]:
        """Generate a new token.

        # Required parameters

        - login: a non-empty string
        - name: a non-empty string

        # Returned value

        A dictionary with the following entries:

        - login: a string
        - name: a string
        - token: a string
        """
        ensure_nonemptystring('login')
        ensure_nonemptystring('name')

        result = self._post(
            'user_tokens/generate', {'login': login, 'name': name}
        )
        return result  # type: ignore

    @api_call
    def revoke_token(self, login: str, name: str) -> None:
        """Revoke token.

        It is not an error to revoke a token that does not exist.

        # Required parameters

        - login: a non-empty string
        - name: a non-empty string
        """
        ensure_nonemptystring('login')
        ensure_nonemptystring('name')

        result = self._post(
            'user_tokens/revoke', {'login': login, 'name': name}
        )
        return result  # type: ignore

    @api_call
    def list_tokens(self, login: str) -> List[Dict[str, Any]]:
        """List existing tokens for user.

        # Required parameters

        - login: a non-empty string

        # Returned value

        A list of _tokens_.  Each token is a dictionary with the
        following two entries:

        - createdAt: a string (a timestamp)
        - name: a string
        """
        ensure_nonemptystring('login')

        return self._collect_data(
            'user_tokens/search', 'userTokens', {'login': login}
        )

    ####################################################################
    # SonarQube projects
    #
    # list_projects
    # delete project

    @api_call
    def list_projects(
        self,
        analyze_before: Optional[str] = None,
        on_provisioned_only: bool = False,
        projects: Optional[str] = None,
        qualifiers: str = 'TRK',
        organization_key: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return a list of matching projects.

        `organization_key` is required when querying a SonarCloud
        instance.

        # Optional parameters

        - analyze_before: a string (ISO Timestamp representation) or
          None (None by default)
        - on_provisioned_only: a boolean (False by default)
        - projects: a string (comma-separated list of project keys) or
          None (None by default)
        - qualifiers: a string (comma-separated list, `'TRK'` by
          default)
        - organization_key: a non-empty string or None (None by default)

        # Returned value

        A list of _projects_.  Each project is a dictionary with the
        following entries:

        - id: a string
        - key: a string
        - lastAnalysisDate: a string (ISO Timestamp representation)
        - name: a string
        - organization: a string
        - qualifier: a string, one of `'APP'`, `'VW'`, or `'TRK'`
        - visibility: a string, either `'public'` or `'private'`
        """
        ensure_noneornonemptystring('analyze_before')
        ensure_noneorinstance('on_provisioned_only', bool)
        ensure_noneornonemptystring('projects')
        ensure_nonemptystring('qualifiers')
        ensure_noneornonemptystring('organization_key')

        params = {
            'onProvisionedOnly': 'true' if on_provisioned_only else 'false',
            'qualifiers': qualifiers,
        }
        add_if_specified(params, 'analyzedBefore', analyze_before)
        add_if_specified(params, 'projects', projects)
        add_if_specified(params, 'organization', organization_key)

        return self._collect_data('projects/search', 'components', params)

    @api_call
    def delete_project(self, project_key: str) -> None:
        """Delete a sonarQube project.

        # Required parameters

        - project_key: a non-empty string
        """
        ensure_nonemptystring('project_key')

        return self._post('projects/delete', {'project': project_key})

    ####################################################################
    # SonarQube projectanalyses
    #
    # list_projectanalyses

    @api_call
    def list_projectanalyses(
        self,
        project_key: str,
        category: Optional[str] = None,
        from_date: Optional[str] = None,
        to_date: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return a list of matching project analyses.

        `to_date` and `from_date` are both inclusive.

        `category`, if specified, must be a value listed in
        `EVENT_CATEGORIES`.

        # Required parameters

        - project_key: a non-empty string

        # Optional parameters

        - category: a non-empty string or None (None by default)
        - from_date: a non-empty string (a date or datetime) or None
          (None by default)
        - to_date: a non-empty string (a date or datetime) or None (None
          by default)

        # Returned value

        A list of _project analyses_.  Each project analysis is a
        dictionary with the following three entries:

        - date: a string (ISO timestamp representation)
        - events: a list of dictionaries
        - key: a string

        Entries in the `events` list have the following entries:

        - category: a string
        - key: a string
        - name: a string

        There may be other entries, depending on the event category.
        """
        ensure_nonemptystring('project_key')
        ensure_noneornonemptystring('category')
        ensure_noneornonemptystring('from_date')
        ensure_noneornonemptystring('to_date')
        if category:
            ensure_in('category', EVENT_CATEGORIES)

        params = {'project': project_key}
        add_if_specified(params, 'category', category)
        add_if_specified(params, 'from', from_date)
        add_if_specified(params, 'to', to_date)

        return self._collect_data(
            'project_analyses/search', 'analyses', params
        )

    ####################################################################
    # SonarQube project links
    #
    # list_projectlinks

    @api_call
    def list_projectlinks(
        self,
        *,
        project_id: Optional[int] = None,
        project_key: Optional[str] = None,
    ) -> List[Dict[str, str]]:
        """List links of a project.

        # Required parameters

        - project_id: an integer or None (None by default)
        - project_key: a non-empty string or None (None by defult)

        One and only one of `project_id` or `project_key` must be
        provided.

        # Returned value

        A list of _project links_.  Each project links_ is a dictionary
        with the following four entries:

        - id: a string
        - name: a string
        - type: a string
        - url: a string
        """
        ensure_onlyone('project_id', 'project_key')

        params = {}
        add_if_specified(params, 'projectId', project_id)
        add_if_specified(params, 'projectKey', project_key)

        result = self._get('project_links/search', params=params).json()
        return result.get('links', [])

    ####################################################################
    # SonarQube project branches
    #
    # list_projectbranches

    @api_call
    def list_projectbranches(
        self,
        project_key: str,
    ) -> List[Dict[str, str]]:
        """List branches of a project.

        # Required parameters

        - project_key: a non-empty string

        # Returned value

        A list of _project branches_. Each project branch is a
        dictionary with the following four entries:

        - analysisDate: a string
        - excludedFromPurge: a boolean
        - isMain: a boolean
        - name: a string
        - status: a dictionary
        - type: a string
        """
        ensure_nonemptystring('project_key')

        result = self._get(
            'project_branches/list', params={'project': project_key}
        ).json()
        return result.get('branches', [])

    ####################################################################
    # SonarQube usergroups
    #
    # create_usergroup
    # add_usergroup_user
    # remove_usergroup_user
    # delete_usergroup
    # list_usergroups

    @api_call
    def create_usergroup(
        self,
        name: str,
        description: Optional[str] = None,
        organization_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new group.

        # Required parameters

        - name: a non-empty string

        # Optional parameters

        - description: a string or None (None by default)
        - organization_key: a non-empty string or None (None by default)

        # Returned value

        A dictionary with the following entry:

        - group: a dictionary

        The `group` dictionary has the following entries:

        - default: a boolean
        - description: a string
        - id: an integer or a string
        - membersCount: an integer
        - name: a string
        - organization: a string
        """
        ensure_nonemptystring('name')
        ensure_noneorinstance('description', str)
        ensure_noneornonemptystring('organization_key')

        data = {'name': name}
        add_if_specified(data, 'description', description)
        add_if_specified(data, 'organization', organization_key)

        result = self._post('user_groups/create', data)
        return result  # type: ignore

    @api_call
    def add_usergroup_user(
        self,
        *,
        group_id: Optional[int] = None,
        group_name: Optional[str] = None,
        login: Optional[str] = None,
    ) -> None:
        """Add a user to a group.

        If `login` is not specified, add current user to group.

        Adding a user that is already a member of the group is safely
        ignored.

        # Required parameters

        - group_id: an integer or None (None by default)
        - group_name: a string or None (None by default)

        One and only one of `group_id` or `group_name` must be provided.

        # Optional parameters

        - login: a non-empty string or None (None by default)
        """
        ensure_onlyone('group_id', 'group_name')
        ensure_noneornonemptystring('login')

        if group_id is None and group_name is None:
            raise ValueError('group_id or group_name must be specified')

        if group_id is not None:
            data: Dict[str, Any] = {'id': group_id}
        else:
            data = {'name': group_name}
        add_if_specified(data, 'login', login)

        result = self._post('user_groups/add_user', data)
        return result  # type: ignore

    @api_call
    def remove_usergroup_user(
        self,
        *,
        group_id: Optional[int] = None,
        group_name: Optional[str] = None,
        login: Optional[str] = None,
    ) -> None:
        """Remove a user from a group.

        If `login` is not specified, remove current user from group.

        Attempting to remove a known user that is not a member of the
        group is safely ignored.

        # Required parameters

        - group_id: an integer or None (None by default)
        - group_name: a string or None (None by default)

        One and only one of `group_id` or `group_name` must be provided.

        # Optional parameters

        - login: a non-empty string or None (None by default)
        """
        ensure_onlyone('group_id', 'group_name')
        ensure_noneornonemptystring('login')

        if group_id is not None:
            data: Dict[str, Any] = {'id': group_id}
        else:
            data = {'name': group_name}
        add_if_specified(data, 'login', login)

        result = self._post('user_groups/remove_user', data)
        return result  # type: ignore

    @api_call
    def delete_usergroup(
        self,
        *,
        group_id: Optional[int] = None,
        group_name: Optional[str] = None,
    ) -> None:
        """Delete a group.

        # Required parameters

        - group_id: an integer or None (None by default)
        - group_name: an non-empty string or None (None by default)

        One and only one of `group_id` or `group_name` must be provided.
        """
        ensure_onlyone('group_id', 'group_name')

        if group_id is not None:
            data: Dict[str, Any] = {'id': group_id}
        else:
            data = {'name': group_name}

        result = self._post('user_groups/delete', data)
        return result  # type: ignore

    @api_call
    def list_usergroups(
        self,
        query: Optional[str] = None,
        fields: Optional[str] = None,
        organization_key: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return the complete list of groups from SonarQube instance.

        # Optional parameters

        - query: a non-empty string or None (None by default)
        - fields: a non-empty string or None (None by default)
        - organization_key: a non-empty string or None (None by default)

        # Returned value

        A list of _groups_.  Each group is a dictionary with the
        following entries (assuming the default value for `fields`):

        - default: a boolean
        - description: a string
        - id: an integer
        - membersCount: an integer
        - name: a string
        """
        ensure_noneornonemptystring('query')
        ensure_noneornonemptystring('fields')
        ensure_noneornonemptystring('organization_key')

        params: Dict[str, str] = {}
        add_if_specified(params, 'q', query)
        add_if_specified(params, 'f', fields)
        add_if_specified(params, 'organization', organization_key)

        return self._collect_data(
            'user_groups/search', 'groups', params if params else None
        )

    ####################################################################
    # SonarQube misc. operations
    #
    # list_upgrades
    # TOTEST migrate_db
    # TOTEST get_db_migration_status
    # TOTEST get_status
    # TOTEST get_health
    # TOTEST get_ping
    # restart
    # TOTEST list_plugins
    # list_plugins_updates
    # TOTEST install_plugin
    # update_plugin

    @api_call
    def list_upgrades(self) -> List[Dict[str, Any]]:
        """Return the list of available upgrades for SonarQube instance.

        # Returned value

        A list of _available upgrades_.  An available upgrade is a
        dictionary with the following entries:

        - changeLogUrl: a string
        - description: a string
        - downloadUrl: a string
        - plugins: a dictionary
        - releaseDate: a string
        - version: a string

        The `plugins` entry is a dictionary with the following entries:

        - incompatible: a possibly empty list of plugins
        - requireUpdate: a possibly empty list of plugins

        Items in the `requireUpdate` list are dictionaries with the
        following entries:

        - category: a string
        - description: a string
        - homepageUrl: a sting
        - issueTrackerUrl: a string
        - key: a string
        - license: a string
        - name: a string
        - organizationName: a string
        - organizationUrl: a string
        - version: a string
        """
        return self._collect_data('system/upgrades', 'upgrades')

    @api_call
    def migrate_db(self) -> Dict[str, str]:
        """Migrate the database to match current version of SonarQube.

        # Returned value

        A dictionary with the following entries:

        - message: a string
        - startedAt: a string (a timestamp)
        - state: a string
        """
        return self._post('system/migrate_db')  # type: ignore

    @api_call
    def get_db_migration_status(self) -> Dict[str, str]:
        """Return database migration status.

        # Returned value

        A dictionary with the following entries:

        - message: a string
        - startedAt: a string (a timestamp)
        - state: a string

        `state` possible values are:

        - `'NO_MIGRATION'`
        - `'NOT_SUPPORTED'`
        - `'MIGRATION_RUNNING'`
        - `'MIGRATION_SUCCEEDED'`
        - `'MIGRATION_FAILED'`
        - `'MIGRATION_REQUIRES'`
        """
        return self._get('system/db_migration_status')  # type: ignore

    @api_call
    def get_status(self) -> Dict[str, str]:
        """Return state information about instance.

        # Returned value

        A dictionary with the following entries:

        - id: a string
        - status: a string
        - version: a string

        `status` possible values are:

        - `'STARTING'`
        - `'UP'`
        - `'DOWN'`
        - `'RESTARTING'`
        - `'DB_MIGRATION_NEEDED'`
        - `'DB_MIGRATION_RUNNING'`
        """
        return self._get('system/status')  # type: ignore

    @api_call
    def get_health(self) -> Dict[str, Any]:
        """Return system health.

        # Returned value

        A dictionary with the following entries:

        - causes: a dictionary
        - health: a string (`'GREEN'`, `'YELLOW'` or `'RED'`)
        - nodes: a list of dictionaries

        `causes` contains the following entry:

        - message: a string

        Items in `nodes` are dictionaries with the following entries:

        - causes: a dictionary
        - health: a string (`'GREEN'`, `'YELLOW'` or `'RED'`)
        - host: a string
        - name: a string
        - port: an integer
        - startedAt: a string (a timestamp)
        - type: a string
        """
        return self._get('system/health')  # type: ignore

    @api_call
    def ping(self) -> str:
        """Return "pong" as plain text."""
        return self._get('system/ping').text

    @api_call
    def restart(self) -> None:
        """Restart server."""
        return self._post('system/restart')  # type: ignore

    @api_call
    def list_plugins(
        self, fields: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Return the list of installed plugins.

        # Optional parameters

        - fields: a string, the comma-separated list of additional
          fields to return or None (None by default)

        # Returned value

        A list of _installed plugins_.  An installed plugin is a
        dictionary with the following entries:

        - description: a string
        - editionBundled: a boolean,
        - filename: a string
        - hash: a string
        - homepageUrl: a string
        - implementationBuild: a string
        - issueTrackerUrl: a string
        - key: a string
        - license: a string
        - name: a string
        - organizationName: a string
        - organizationUrl: a string
        - sonarLintSupported: a string
        - updatedAt: an integer
        - version: a string
        """
        ensure_noneornonemptystring('fields')

        return self._collect_data(
            'plugins/installed',
            'plugins',
            None if fields is None else {'f': fields},
        )

    @api_call
    def list_plugins_updates(self) -> List[Dict[str, Any]]:
        """Return the list of available plugin upgrades.

        # Returned value

        A list of _upgradeable plugins_.  An upgradeable plugin is a
        dictionary with the following entries:

        - category: a string
        - description: a string
        - editionBundled: a boolean
        - key: a string
        - license: a string
        - name: a string
        - organizationName: a string
        - organizationUrl: a string
        - termsAndConditionsUrl: a string
        - updates: a list of dictionaries

        Items in the `updates` list are dictionaries containing the
        following entries:

        - release: a dictionary
        - requires: a list
        - status: a string

        `release` is a dictionary with the following entries:

        - changeLogUrl: a string
        - date: a string
        - description: a string
        - version: a string
        """
        return self._collect_data('plugins/updates', 'plugins')

    @api_call
    def install_plugin(self, key: str) -> None:
        """Install the latest compatible version of plugin.

        # Required parameters

        - key: a non-empty string
        """
        ensure_nonemptystring('key')

        result = self._post('plugins/install', data={'key': key})
        return result  # type: ignore

    @api_call
    def update_plugin(self, key: str) -> None:
        """Update an installed plugin to the latest compatible version.

        # Required parameters

        - key: a non-empty string
        """
        ensure_nonemptystring('key')

        result = self._post('plugins/update', data={'key': key})
        return result  # type: ignore

    ####################################################################
    # SonarQube private helpers

    def _post(
        self,
        api: str,
        data: Optional[Union[MutableMapping[str, str], bytes]] = None,
        json: Optional[Mapping[str, Any]] = None,
    ) -> requests.Response:
        api_url = join_url(self.url, api)
        return self.session().post(api_url, data, json)

    def _get(
        self,
        api: str,
        params: Optional[Mapping[str, Union[str, List[str], None]]] = None,
    ) -> requests.Response:
        api_url = join_url(self.url, api)
        return self.session().get(api_url, params=params)

    def _collect_data(
        self,
        api: str,
        key: str,
        params: Optional[Mapping[str, Union[str, List[str], None]]] = None,
    ) -> List[Any]:
        """Return SonarQube API call results, collecting key values.

        The API call is expected to return an JSON structure.

        `params`, if specified, is a dictionary and will be passed to
        the API.
        """
        page_size = '100'
        page = 1
        api_url = join_url(self.url, api)
        _params: Dict[str, Union[str, List[str], None]] = {}
        if params is not None:
            _params.update(params)

        try:
            _params.update({'p': str(1), 'pageSize': page_size})
            req = self.session().get(api_url, params=_params).json()
        except ValueError:
            raise ApiError(
                f'Unexpected response, was expecting JSON ({api_url})'
            ) from None

        values: List[Any] = req[key]
        while 'paging' in req and len(values) < req['paging']['total']:
            page += 1
            _params.update({'p': str(page), 'pageSize': page_size})
            req = self.session().get(api_url, params=_params).json()
            if req:
                values += req[key]
            else:
                raise ApiError(f'Empty response ({api_url})')

        return values
