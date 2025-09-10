# Copyright (c) 2019 Martin Lafaix (martin.lafaix@external.engie.com)
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

"""Artifactory.

A base class wrapping Artifactory APIs.

There can be as many Artifactory instances as needed.

This module depends on the public **requests** library.  It also depends
on three **zabel-commons** modules, #::zabel.commons.exceptions,
#::zabel.commons.sessions, and #::zabel.commons.utils.

A base class wrapper only implements 'simple' API requests.  It handles
pagination if appropriate, but does not process the results or compose
API requests.
"""

from typing import (
    Any,
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Tuple,
    Union,
)

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

PACKAGE_TYPES = [
    'bower',
    'chef',
    'cocoapods',  # new
    'composer',
    'conan',
    'conda',  # really new (not on API documents :( )
    'cran',  # new
    'debian',
    'docker',
    'gems',
    'generic',
    'gitlfs',
    'go',  # new
    'gradle',
    'helm',  # new
    'ivy',
    'maven',
    'npm',
    'nuget',
    'opkg',  # new
    'puppet',
    'pypi',
    'rpm',  # new
    'sbt',
    'vagrant',
    'yum',
]

INCOMPATIBLE_PARAM = '%s cannot be specified when json is provided'

# Artifactory low-level api


class Artifactory:
    """Artifactory Low-Level Wrapper.

    There can be as many Artifactory instances as needed.

    This class depends on the public **requests** library.  It also
    depends on three **zabel.commons** modules,
    #::zabel.commons.exceptions, #::zabel.commons.sessions,
    and #::zabel.commons.utils.

    ## Reference URLs

    - <https://www.jfrog.com/confluence/display/RTF/Artifactory+REST+API>
    - <https://www.jfrog.com/confluence/display/XRAY2X/Xray+REST+API>

    ## Implemented features

    - artefacts
    - builds
    - groups
    - permission
    - repositories
    - token
    - users
    - misc. features (storageinfo, version, ping, ...)

    ## Examples

    ```python
    from zabel.elements.clients import Artifactory

    url = 'https://artifactory.example.com/artifactory/api/'
    user = '...'
    token = '...'
    af = Artifactory(url, basic_auth=(user, token))
    af.list_users()
    ```
    """

    def __init__(
        self,
        url: str,
        *,
        basic_auth: Optional[Tuple[str, str]] = None,
        bearer_auth: Optional[str] = None,
        xray_url: Optional[str] = None,
        verify: bool = True,
    ) -> None:
        """Create an Artifactory instance object.

        # Required parameters

        - url: a non-empty string
        - basic_auth: a strings tuple (user, token)
        - bearer_auth: a string

        # Optional parameters

        - xray_url: a string or None (None by default)
        - verify: a boolean (True by default)

        # Usage

        `url` is the top-level API endpoint.  For example:

            'https://artifactory.example.com/artifactory/api/'

        `xray_url`, if specified, is the top-level jfrog-xray API
        endpoint.  If not specified, will be as `url` with the
        `'artifactory/api'` ending replaced by `'xray/api'`

        `verify` can be set to False if disabling certificate checks for
        Artifactory communication is required.  Tons of warnings will
        occur if this is set to `False`.
        """
        ensure_nonemptystring('url')
        ensure_onlyone('basic_auth', 'bearer_auth')
        ensure_noneorinstance('basic_auth', tuple)
        ensure_noneorinstance('bearer_auth', str)

        self.url = url
        self.basic_auth = basic_auth
        self.bearer_auth = bearer_auth

        if xray_url is None:
            xray_url_segments = url.strip('/').split('/')
            xray_url_segments[-2] = 'xray'
            xray_url = '/'.join(xray_url_segments)

        if basic_auth is not None:
            self.auth = basic_auth
        if bearer_auth is not None:
            self.auth = BearerAuth(bearer_auth)

        self.url_xray = xray_url
        self.verify = verify
        self.session = prepare_session(self.auth, verify=verify)

    def __str__(self) -> str:
        return f'{self.__class__.__name__}: {self.url}'

    def __repr__(self) -> str:
        if isinstance(self.auth, tuple):
            auth = self.auth[0]
        else:
            auth = self.auth.pat[:10] + '...' + self.auth.pat[-10:]
        return f'<{self.__class__.__name__}: {self.url!r}, {auth!r}>'

    ####################################################################
    # artifactory builds
    #
    # list_builds

    @api_call
    def list_builds(self) -> List[Dict[str, Any]]:
        """Return the builds list.

        # Returned value

        A list of _builds_.  Each build is a dictionary with the
        following entries:

        - buildName: a string
        - buildNumber: a string
        - lastBuildTime: a string (a timestamp)
        - time: an integer (a timestamp)
        - userCanDistribute: a boolean
        """
        return self._get('builds')  # type: ignore

    ####################################################################
    # artifactory users
    #
    # list_users
    # list_users2
    # get_user
    # get_user2
    # create_or_replace_user
    # create_user
    # update_user
    # update_user2
    # delete_user
    # delete_user2
    # get_encryptedpassword
    # get_apikey
    # create_apikey
    # revoke_apikey

    @api_call
    def list_users(self) -> List[Dict[str, Any]]:
        """Return the users list.

        # Returned value

        A list of _users_.  Each user is a dictionary with the following
        entries:

        - name: a string
        - realm: a string
        - uri: a string
        """
        return self._get('security/users')  # type: ignore

    @api_call
    def list_users2(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """Return the users list.

        !!! important
            BearerAuth is mandatory to use this function.

        # Optional parameters

        - limit: an integer (`1000` by default), valid value between `1`
          and `99999`

        # Returned value

        A list of _users_.  Each user is a dictionary with the following
        entries:

        - name: a string
        - realm: a string
        - status: a string
        - uri: a string
        """
        ensure_instance('limit', int)
        if limit < 1 or limit > 99999:
            raise ValueError('limit must be between 1 and 99999')

        return self._get('access/api/v2/users', params={'limit': limit})  # type: ignore

    @api_call
    def get_user(self, username: str) -> Dict[str, Any]:
        """Return user details.

        # Required parameters

        - username: a non-empty string

        # Returned value

        A dictionary with the following entries:

        - admin: a boolean
        - disableUIAccess: a boolean
        - email: a string
        - groups: a list of strings
        - lastLoggedInMillis: an integer
        - ?lastLoggedIn: a string representing a date
        - name: a string
        - offlineMode: a boolean
        - profileUpdatable: a boolean
        - realm: a string
        """
        ensure_nonemptystring('username')

        return self._get(f'security/users/{username}')  # type: ignore

    @api_call
    def get_user2(self, username: str) -> Dict[str, Any]:
        """Return user details.

        !!! important
            BearerAuth is mandatory to use this function.

        # Required parameters

        - username: a non-empty string

        # Returned value

        A dictionary with the following entries:

        - admin: a boolean
        - disable_ui_access: a boolean
        - email: a string
        - groups: a list of strings
        - internal_password_disabled: a boolean
        - last_logged_in: a string representing a date
        - profile_updatable: a boolean
        - realm: a string
        - status: a string
        - username: a string
        """
        ensure_nonemptystring('username')

        return self._get(f'access/api/v2/users/{username}')  # type: ignore

    @api_call
    def create_or_replace_user(
        self,
        name: str,
        email: str,
        password: Optional[str] = None,
        admin: bool = False,
        profile_updatable: bool = True,
        disable_ui_access: bool = True,
        internal_password_disabled: bool = False,
        groups: Optional[List[str]] = None,
    ) -> None:
        """Create or replace a user.

        !!! important
            If the user already exists, it will be replaced and
            unspecified parameters will have their default values.  Use
            #update_user() if you want to change a parameter of an
            existing user while keeping the other parameters values.

        # Required parameters

        - name: a non-empty string
        - email: a non-empty string

        # Optional parameters

        - password: a non-empty string or None (None by default)
        - admin: a boolean (False by default)
        - profile_updatable: a boolean (True by default)
        - disable_ui_access: a boolean (True by default)
        - internal_password_disabled: a boolean (False by default)
        - groups: a list of strings or None (None by default)
        """
        ensure_nonemptystring('name')
        ensure_nonemptystring('email')
        ensure_instance('admin', bool)
        ensure_instance('profile_updatable', bool)
        ensure_instance('disable_ui_access', bool)
        ensure_instance('internal_password_disabled', bool)
        ensure_noneorinstance('groups', list)

        if not internal_password_disabled:
            ensure_nonemptystring('password')
        else:
            ensure_noneorinstance('password', str)

        data = {
            'name': name,
            'email': email,
            'admin': admin,
            'profileUpdatable': profile_updatable,
            'disableUIAccess': disable_ui_access,
            'internalPasswordDisabled': internal_password_disabled,
        }
        add_if_specified(data, 'groups', groups)
        add_if_specified(data, 'password', password)

        result = self._put(f'security/users/{name}', json=data)
        return result  # type: ignore

    @api_call
    def create_user(
        self,
        name: str,
        email: str,
        password: Optional[str] = None,
        admin: bool = False,
        profile_updatable: bool = True,
        disable_ui_access: bool = True,
        internal_password_disabled: bool = False,
        groups: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Create an user.

        !!! important
            BearerAuth is mandatory to use this function.

        # Required parameters

        - name: a non-empty string
        - email: a non-empty string

        # Optional parameters

        - password: a non-empty string or None (None by default)
        - admin: a boolean (False by default)
        - profile_updatable: a boolean (True by default)
        - disable_ui_access: a boolean (True by default)
        - internal_password_disabled: a boolean (False by default)
        - groups: a list of strings or None (None by default)

        # Returned value

        A dictionary with the following entries:

        - admin: a boolean
        - disable_ui_access: a boolean
        - email: a string
        - groups: a list of strings
        - internal_password_disabled: a boolean
        - profile_updatable: a boolean
        - realm: a string
        - status: a string
        - username: a string
        """
        ensure_nonemptystring('name')
        ensure_nonemptystring('email')
        ensure_instance('admin', bool)
        ensure_instance('profile_updatable', bool)
        ensure_instance('disable_ui_access', bool)
        ensure_instance('internal_password_disabled', bool)
        ensure_noneorinstance('groups', list)

        if not internal_password_disabled:
            ensure_nonemptystring('password')
        else:
            ensure_noneorinstance('password', str)

        data = {
            'username': name,
            'email': email,
            'admin': admin,
            'profile_updatable': profile_updatable,
            'disable_ui_access': disable_ui_access,
            'internal_password_disabled': internal_password_disabled,
        }
        add_if_specified(data, 'password', password)
        add_if_specified(data, 'groups', groups)
        add_if_specified(data, 'password', password)

        result = self._post('access/api/v2/users', json=data)
        return result  # type: ignore

    @api_call
    def update_user(
        self,
        name: str,
        email: Optional[str] = None,
        password: Optional[str] = None,
        admin: Optional[bool] = None,
        profile_updatable: Optional[bool] = None,
        disable_ui_access: Optional[bool] = None,
        internal_password_disabled: Optional[bool] = None,
        groups: Optional[Iterable[str]] = None,
    ) -> None:
        """Update an existing user.

        # Required parameters

        - name: a non-empty string

        # Optional parameters

        - email: a non-empty string or None (None by default)
        - password: a non-empty string or None (None by default)
        - admin: a boolean or None (None by default)
        - profile_updatable: a boolean or None (None by default)
        - disable_ui_access: a boolean or None (None by default)
        - internal_password_disabled: a boolean or None (None by
          default)
        - groups: a list of strings or None (None by default)

        If an optional parameter is not specified, or is None, its
        existing value will be preserved.
        """
        ensure_nonemptystring('name')

        if (
            email is None
            and password is None
            and admin is None
            and profile_updatable is None
            and disable_ui_access is None
            and internal_password_disabled is None
            and groups is None
        ):
            raise ValueError(
                'At least one parameter must be specified in addition to the user name'
            )

        ensure_noneornonemptystring('email')
        ensure_noneornonemptystring('password')
        ensure_noneorinstance('admin', bool)
        ensure_noneorinstance('profile_updatable', bool)
        ensure_noneorinstance('disable_ui_access', bool)
        ensure_noneorinstance('internal_password_disabled', bool)
        ensure_noneorinstance('groups', list)

        _user = self.get_user(name)
        if admin is None:
            admin = _user['admin']
        if profile_updatable is None:
            profile_updatable = _user['profileUpdatable']
        if disable_ui_access is None:
            disable_ui_access = _user['disableUIAccess']
        if internal_password_disabled is None:
            internal_password_disabled = _user['internalPasswordDisabled']
        if groups is None:
            groups = _user['groups'] if 'groups' in _user else None

        data = {'name': name}
        add_if_specified(data, 'email', email)
        add_if_specified(data, 'password', password)
        add_if_specified(data, 'admin', admin)
        add_if_specified(data, 'profileUpdatable', profile_updatable)
        add_if_specified(data, 'disableUIAccess', disable_ui_access)
        add_if_specified(
            data, 'internalPasswordDisabled', internal_password_disabled
        )
        add_if_specified(data, 'groups', groups)

        result = self._post(f'security/users/{name}', json=data)
        return result  # type: ignore

    @api_call
    def update_user2(
        self,
        name: str,
        email: Optional[str] = None,
        password: Optional[str] = None,
        admin: Optional[bool] = None,
        profile_updatable: Optional[bool] = None,
        disable_ui_access: Optional[bool] = None,
        internal_password_disabled: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Update an existing user.

        !!! important
            BearerAuth is mandatory to use this function.

        # Required parameters

        - name: a non-empty string

        # Optional parameters

        - email: a non-empty string or None (None by default)
        - password: a non-empty string or None (None by default)
        - admin: a boolean or None (None by default)
        - profile_updatable: a boolean or None (None by default)
        - disable_ui_access: a boolean or None (None by default)
        - internal_password_disabled: a boolean or None (None by
          default)

        If an optional parameter is not specified, or is None, its
        existing value will be preserved.

        # Returned value

        A dictionary with the following entries:

        - admin: a boolean
        - disable_ui_access: a boolean
        - email: a string
        - groups: a list of strings
        - internal_password_disabled: a boolean
        - profile_updatable: a boolean
        - realm: a string
        - status: a string
        - username: a string
        """
        ensure_nonemptystring('name')

        if (
            email is None
            and password is None
            and admin is None
            and profile_updatable is None
            and disable_ui_access is None
            and internal_password_disabled is None
        ):
            raise ValueError(
                'At least one parameter must be specified in addition to the user name'
            )

        ensure_noneornonemptystring('email')
        ensure_noneornonemptystring('password')
        ensure_noneorinstance('admin', bool)
        ensure_noneorinstance('profile_updatable', bool)
        ensure_noneorinstance('disable_ui_access', bool)
        ensure_noneorinstance('internal_password_disabled', bool)

        data = {}
        add_if_specified(data, 'email', email)
        add_if_specified(data, 'password', password)
        add_if_specified(data, 'admin', admin)
        add_if_specified(data, 'profile_updatable', profile_updatable)
        add_if_specified(data, 'disable_ui_access', disable_ui_access)
        add_if_specified(
            data, 'internal_password_disabled', internal_password_disabled
        )
        result = self._patch(f'access/api/v2/users/{name}', json=data)
        return result  # type: ignore

    @api_call
    def delete_user(self, username: str) -> bool:
        """Delete user.

        # Required parameters

        - username: a non-empty string

        # Returned value

        A boolean.  True if successful.
        """
        ensure_nonemptystring('username')

        return self._delete(f'security/users/{username}').status_code == 200

    @api_call
    def delete_user2(self, username: str) -> bool:
        """Delete user.

        !!! important
            BearerAuth is mandatory to use this function.

        # Required parameters

        - username: a non-empty string

        # Returned value

        A boolean.  True if successful.
        """
        ensure_nonemptystring('username')

        return (
            self._delete(f'access/api/v2/users/{username}').status_code == 204
        )

    @api_call
    def create_apikey(self, auth: Optional[Tuple[str, str]] = None) -> str:
        """Generate the user API key.

        If `auth` is not specified, generate the current user API key.

        # Optional parameters

        - auth: a (string, string) tuple or None (None by default)

        # Returned value

        A string, the new API key.

        # Raised exceptions

        If the API key already exists, an _ApiError_ exception is
        raised.
        """
        ensure_noneorinstance('auth', tuple)

        result = self._post2('security/apiKey', auth=auth or self.auth).json()
        if 'apiKey' not in result:
            raise ApiError('Error while creating apiKey, already exists?')
        return result['apiKey']  # type: ignore

    @api_call
    def get_apikey(
        self, auth: Optional[Tuple[str, str]] = None
    ) -> Optional[str]:
        """Return the user API key.

        If `auth` is not specified, return the current user API key.

        # Optional parameters

        - auth: a (string, string) tuple or None (None by default)

        # Returned value

        A string, the API key, or None, if no API key has been created
        yet.
        """
        ensure_noneorinstance('auth', tuple)

        result = (
            self._get2('security/apiKey', auth=auth or self.auth)
            .json()
            .get('apiKey')
        )
        return result  # type: ignore

    @api_call
    def revoke_apikey(self, auth: Optional[Tuple[str, str]] = None) -> None:
        """Revoke the user API key.

        If `auth` is not specified, revoke the current user API key.

        If no API key has been created, does nothing.

        # Optional parameters

        - auth: a (string, string) tuple or None (None by default)

        # Raised exceptions

        If the specified credentials are invalid, raises an _ApiError_
        exception.
        """
        ensure_noneorinstance('auth', tuple)

        result = self._delete2('security/apiKey', auth=auth or self.auth)
        if 'errors' in result.json():
            raise ApiError('Errors while revoking apiKey, bad credentials?')

    @api_call
    def get_encryptedpassword(
        self, auth: Optional[Tuple[str, str]] = None
    ) -> str:
        """Return the user encrypted password.

        If `auth` is not specified, return the current user encrypted
        password.

        # Optional parameters

        - auth: a (string, string) tuple or None (None by default)

        # Returned value

        A string.
        """
        ensure_noneorinstance('auth', tuple)

        return self._get2(
            'security/encryptedPassword', auth=auth or self.auth
        ).text

    ####################################################################
    # artifactory groups
    #
    # list_groups
    # list_groups2
    # get_group
    # get_group2
    # create_or_replace_group
    # create_group
    # update_group
    # update_group2
    # delete_group
    # delete_group2
    # add_remove_group_users

    @api_call
    def list_groups(self) -> List[Dict[str, Any]]:
        """Return the groups list.

        # Returned value

        A list of _groups_.  Each group is a dictionary with the
        following entries:

        - name: a string
        - uri: a string
        """
        return self._get('security/groups')  # type: ignore

    @api_call
    def list_groups2(self) -> List[Dict[str, Any]]:
        """Return the groups list.

        !!! important
            BearerAuth is mandatory to use this function.

        # Returned value

        A list of _groups_.  Each group is a dictionary with the
        following entries:

        - name: a string
        - uri: a string
        """
        return self._get('access/api/v2/groups')  # type: ignore

    @api_call
    def get_group(
        self, group_name: str, include_users: bool = False
    ) -> Dict[str, Any]:
        """Return group details.

        # Required parameters

        - group_name: a non-empty string

        # Optional parameters

        - include_users: a boolean (False by default)

        # Returned value

        A dictionary with the following entries:

        - adminPrivileges: a string
        - autoJoin: a boolean
        - description: a string
        - name: a string
        - realm: a string
        - userNames: a list of strings if `include_users` is True
        """

        ensure_nonemptystring('group_name')
        ensure_instance('include_users', bool)

        params = {'includeUsers': include_users}

        return self._get(f'security/groups/{group_name}', params=params)  # type: ignore

    @api_call
    def get_group2(self, group_name: str) -> Dict[str, Any]:
        """Return group details.

        !!! important
            BearerAuth is mandatory to use this function.

        # Required parameters

        - group_name: a non-empty string

        # Returned value

        A dictionary with the following entries:

        - adminPrivileges: a string
        - autoJoin: a boolean
        - description: a string
        - external_id: a string
        - members: a list of strings
        - name: a string
        - realm: a string
        - realm_attributes: a string
        """
        ensure_nonemptystring('group_name')

        return self._get(f'access/api/v2/groups/{group_name}')  # type: ignore

    @api_call
    def create_or_replace_group(
        self,
        name: str,
        description: Optional[str] = None,
        auto_join: bool = False,
        admin_priviledge: bool = False,
        realm: Optional[str] = None,
        realm_attributes: Optional[str] = None,
    ) -> None:
        """Create or replace a group.

        !!! important
            If the group already exists, it will be replaced and
            unspecified parameters will have their default values. Use
            #update_group() if you want to change a parameter of an
            existing group while keeping the other parameters values.

        # Required parameters

        - name: a non-empty string

        # Optional parameters

        - description: a non-empty string or None (None by default)
        - auto_join: a boolean (False by default)
        - admin_priviledge: a boolean (False by default)
        - realm: a non-empty string or None (None by default)
        - realm_attributes: a non-empty string or None (None by default)
        """
        ensure_nonemptystring('name')

        if admin_priviledge and auto_join:
            raise ValueError(
                'auto_join cannot be True if admin_priviledge  is True'
            )

        ensure_noneornonemptystring('description')
        ensure_instance('auto_join', bool)
        ensure_instance('admin_priviledge', bool)
        # ?? is '' an allowed value for realm or realm_attributes?
        ensure_noneornonemptystring('realm')
        ensure_noneornonemptystring('realm_attributes')

        data = {
            'name': name,
            'description': description,
            'autoJoin': auto_join,
            'adminPrivileges': admin_priviledge,
            'realm': realm,
            'realmAttributes': realm_attributes,
        }

        result = self._put(f'security/groups/{name}', json=data)
        return result  # type: ignore

    @api_call
    def create_group(
        self,
        name: str,
        description: Optional[str] = None,
        auto_join: bool = False,
        admin_priviledge: bool = False,
        realm: Optional[str] = None,
        realm_attributes: Optional[str] = None,
        external_id: Optional[str] = None,
        members: Optional[List[str]] = None,
    ) -> None:
        """Create a group.

        !!! important
            BearerAuth is mandatory to use this function.

        !!! important
            If the group already exists, it will be replaced and
            unspecified parameters will have their default values. Use
            #update_group() if you want to change a parameter of an
            existing group while keeping the other parameters values.

        # Required parameters

        - name: a non-empty string

        # Optional parameters

        - description: a non-empty string or None (None by default)
        - auto_join: a boolean (False by default)
        - admin_priviledge: a boolean (False by default)
        - realm: a non-empty string or None (None by default)
        - realm_attributes: a non-empty string or None (None by default)
        - external_id: a non-empty string or None (None by default)
        - members : a list of strings or None (None by default)
        """
        ensure_nonemptystring('name')
        ensure_noneornonemptystring('description')
        ensure_instance('auto_join', bool)
        ensure_instance('admin_priviledge', bool)
        # ?? is '' an allowed value for realm or realm_attributes?
        ensure_noneornonemptystring('realm')
        ensure_noneornonemptystring('realm_attributes')
        ensure_noneorinstance('members', list)

        if admin_priviledge and auto_join:
            raise ValueError(
                'auto_join cannot be True if admin_priviledge is True'
            )

        data = {
            'name': name,
            'description': description,
            'auto_join': auto_join,
            'adminPrivileges': admin_priviledge,
            'realm': realm,
            'realmAttributes': realm_attributes,
            'external_id': external_id,
            'members': members or [],
        }

        result = self._post('access/api/v2/groups', json=data)
        return result  # type: ignore

    @api_call
    def update_group(
        self,
        name: str,
        description: Optional[str] = None,
        auto_join: Optional[bool] = None,
        admin_priviledge: Optional[bool] = None,
        realm: Optional[str] = None,
        realm_attributes: Optional[str] = None,
    ) -> None:
        """Update an existing group.

        # Required parameters

        - name: a non-empty string

        # Optional parameters

        - description: a non-empty string or None (None by default)
        - auto_join: a boolean or None (None by default)
        - admin_priviledge: a boolean or None (None by default)
        - realm: a non-empty string or None (None by default)
        - realm_attributes: a non-empty string or None (None by default)

        If an optional parameter is not specified, or is None, its
        existing value will be preserved.
        """
        ensure_nonemptystring('name')
        ensure_noneornonemptystring('description')
        ensure_noneorinstance('auto_join', bool)
        ensure_noneorinstance('admin_priviledge', bool)
        # ?? is '' an allowed value for realm or realm_attributes?
        ensure_noneornonemptystring('realm')
        ensure_noneornonemptystring('realm_attributes')

        if admin_priviledge and auto_join:
            raise ValueError(
                'auto_join cannot be True if admin_priviledge is True'
            )

        _group = self.get_group(name)
        if admin_priviledge is None:
            admin_priviledge = _group['adminPrivileges']
        if auto_join is None:
            auto_join = _group['autoJoin']

        data = {'name': name}
        add_if_specified(data, 'adminPrivileges', admin_priviledge)
        add_if_specified(data, 'autoJoin', auto_join)
        add_if_specified(data, 'description', description)
        add_if_specified(data, 'realm', realm)
        add_if_specified(data, 'realmAttributes', realm_attributes)

        result = self._post(f'security/groups/{name}', json=data)
        return result  # type: ignore

    @api_call
    def update_group2(
        self,
        name: str,
        description: Optional[str] = None,
        auto_join: Optional[bool] = None,
        admin_priviledge: Optional[bool] = None,
        realm: Optional[str] = None,
        realm_attributes: Optional[str] = None,
        external_id: Optional[str] = None,
        members: Optional[List[str]] = None,
    ) -> None:
        """Update an existing group.

        !!! important
            BearerAuth is mandatory to use this function.

        # Required parameters

        - name: a non-empty string

        # Optional parameters

        - description: a non-empty string or None (None by default)
        - auto_join: a boolean or None (None by default)
        - admin_priviledge: a boolean or None (None by default)
        - realm: a non-empty string or None (None by default)
        - realm_attributes: a non-empty string or None (None by default)
        - external_id: a non-empty string or None (None by default)
        - members : a list of strings or None (None by default)

        If an optional parameter is not specified, or is None, its
        existing value will be preserved.
        """
        ensure_nonemptystring('name')
        ensure_noneornonemptystring('description')
        ensure_noneorinstance('auto_join', bool)
        ensure_noneorinstance('admin_priviledge', bool)
        ensure_noneornonemptystring('realm')
        ensure_noneornonemptystring('realm_attributes')
        ensure_noneornonemptystring('external_id')
        ensure_noneorinstance('members', list)

        if admin_priviledge and auto_join:
            raise ValueError(
                'auto_join cannot be True if admin_priviledge is True'
            )

        data = {'name': name}
        add_if_specified(data, 'admin_priviledges', admin_priviledge)
        add_if_specified(data, 'auto_join', auto_join)
        add_if_specified(data, 'description', description)
        add_if_specified(data, 'realm', realm)
        add_if_specified(data, 'realm_attributes', realm_attributes)
        add_if_specified(data, 'external_id', external_id)
        add_if_specified(data, 'members', members or [])

        result = self._patch(f'access/api/v2/groups/{name}', json=data)
        return result  # type: ignore

    @api_call
    def delete_group(self, group_name: str) -> bool:
        """Delete group.

        Deleting a group automatically remove the specified group for
        users.

        # Required parameters

        - group_name: a non-empty string

        # Returned value

        A boolean.  True if successful.
        """
        ensure_nonemptystring('group_name')

        return self._delete(f'security/groups/{group_name}').status_code == 200

    @api_call
    def delete_group2(self, group_name: str) -> bool:
        """Delete group.

        !!! important
            BearerAuth is mandatory to use this function.

        Deleting a group automatically remove the specified group for
        users.

        # Required parameters

        - group_name: a non-empty string

        # Returned value

        A boolean.  True if successful.
        """
        ensure_nonemptystring('group_name')

        return (
            self._delete(f'access/api/v2/groups/{group_name}').status_code
            == 204
        )

    @api_call
    def add_remove_group_users(
        self,
        group_name: str,
        add_users: Optional[List[str]] = None,
        rm_users: Optional[List[str]] = None,
    ) -> List[str]:
        """Add or remove users from group.

        # Required parameters

        - group_name: a string

        # Optional parameters

        - add_users: a list of strings or None (None by default)
        - rm_users: a list of strings or None (None by default)

        # Returned value

        A list of strings - The list of group members
        """
        ensure_nonemptystring('group_name')
        ensure_noneorinstance('add_users', list)
        ensure_noneorinstance('rm_users', list)

        data = {}
        add_if_specified(data, 'add', add_users)
        add_if_specified(data, 'remove', rm_users)

        result = self._patch(
            f'access/api/v2/groups/{group_name}/members', json=data
        )
        return result  # type: ignore

    ####################################################################
    # artifactory repositories
    #
    # list_repositories
    # get_repository
    # create_repository
    # update_repository
    # delete_repository

    @api_call
    def list_repositories(self) -> List[Dict[str, Any]]:
        """Return the repositories list.

        # Returned value

        A list of _repositories_.  Each repository is a dictionary with
        the following entries:

        - description: a string
        - key: a string
        - type: a string
        - url: a string
        """
        return self._get('repositories')  # type: ignore

    @api_call
    def get_repository(self, repository_name: str) -> Dict[str, Any]:
        """Return the repository details.

        # Required parameters

        - repository_name: a non-empty string

        # Returned value

        A dictionary with entries like:

        - artifactoryRequestsCanRetrieveRemoteArtifacts: a boolean
        - blockPushingSchema1: a boolean
        - cachingLocalForeignLayersEnabled: a boolean
        - cargoAnonymousAccess: a boolean
        - cargoInternalIndex: a boolean
        - ddebSupported: a boolean
        - debianTrivialLayout: a boolean
        - defaultDeploymentRepo: a string
        - description: a string
        - dockerApiVersion: a string
        - dockerProjectId: a string
        - enableBowerSupport: a boolean
        - enableChefSupport: a boolean
        - enableCocoaPodsSupport: a boolean
        - enableComposerSupport: a boolean
        - enableConanSupport: a boolean
        - enableDebianSupport: a boolean
        - enableDistRepoSupport: a boolean
        - enableDockerSupport: a boolean
        - enableGemsSupport: a boolean
        - enableGitLfsSupport: a boolean
        - enableNormalizedVersion: a boolean
        - enableNpmSupport: a boolean
        - enableNuGetSupport: a boolean
        - enablePuppetSupport: a boolean
        - enablePypiSupport: a boolean
        - enableVagrantSupport: a boolean
        - environments: a list
        - excludesPattern: a string
        - externalDependenciesEnabled: a boolean
        - forceConanAuthentication: a boolean
        - forceMavenAuthentication: a boolean
        - forceMetadataNameVersion: a boolean
        - forceNonDuplicateChart: a boolean
        - forceNugetAuthentication: a boolean
        - forceP2Authentication: a boolean
        - hideUnauthorizedResources: a boolean
        - includesPattern: a string
        - key: a string
        - keyPair: a string
        - notes: a string
        - packageType: a string
        - pomRepositoryReferencesCleanupPolicy: a string
        - priorityResolution: a boolean
        - rclass: a string
        - repositories: a list of strings
        - resolveDockerTagsByTimestamp: a boolean
        - signedUrlTtl: an integer
        - useNamespaces: a boolean
        - virtualRetrievalCachePeriodSecs: an integer

        The actual entries list depends on the repository type and
        configuration.
        """
        ensure_nonemptystring('repository_name')

        return self._get(f'repositories/{repository_name}')  # type: ignore

    @api_call
    def create_repository(
        self,
        name: str,
        rclass: Optional[str] = None,
        package_type: Optional[str] = None,
        url: Optional[str] = None,
        description: Optional[str] = None,
        notes: Optional[str] = None,
        includes_pattern: Optional[str] = None,
        excludes_pattern: Optional[str] = None,
        repositories: Optional[List[str]] = None,
        json: Optional[Dict[str, Any]] = None,
        pos: Optional[int] = None,
        default_deployment_repo: Optional[str] = None,
    ) -> None:
        """Create a repository.

        Provides a minimal direct interface.  In order to fully qualify
        a repository, use the `json` parameter.

        # Required parameters

        - name: a non-empty string
        - json: a dictionary (if `rclass` and `package_type` are not
          specified, None otherwise)
        - rclass: a non-empty string (if `json` is not specified,
          `'local'`, `'remote'`, or `'virtual'` otherwise)
        - package_type: a non-empty string (if `json` is not specified)

        Either `json` or `rclass` and `package_type` must be specified.

        # Optional parameters

        - pos: an integer or None (None by default)

        If `json` is not specified:

        - url: a string
        - description: a string
        - notes: a string
        - includes_pattern: a string
        - excludes_pattern: a string
        - repositories: a list of strings
        - default_deployment_repo: a string (optional, for virtual
            repositories only)

        # Raised exceptions

        An _ApiError_ exception is raised if the repository creation
        was not successful.

        # Usage

        A position may be specified using the `pos` parameter. If the
        map size is shorter than `pos` the repository is the last one
        (default).

        <h5>Minimal direct interface</h5>

        When using the direct interface, `name`, `rclass`, and
        `package_type` are required parameters, and `json` must not be
        specified.

        `url` is required for remote repositories.

        `repositories` and `default_deployment_repo` are only
        applicable to virtual repositories.

        <h5>Full interface</h5>

        When using the full interface, only `name` and `json` are
        required parameters, and `pos` is the only allowed optional
        parameter.

        The `json` content depends of the desired repository class.

        The following sections describe the JSON content for the
        different repository classes (local, remote, virtual, and
        federated).

        > Legend: `'+'` = required entry, `'-'` = optional entry.

        <h6>JSON for a local repository</h6>

        ```text
        {
          - "key": "local-repo1",
          - "projectKey": "projx",
          - "environments": ["DEV"] (mandatory when assigning repo to project),
          + "rclass": "local",
          - "packageType": "alpine" | "cargo" | "composer" | "bower"
                           | "chef" | "cocoapods" | "conan" | "conda"
                           | "cran" | "debian" | "docker" | "helm"
                           | "helmoci" | "huggingfaceml" | "gems"
                           | "gitlfs" | "go" | "gradle" | "ivy"
                           | "maven" | "npm" | "nuget" | "oci" | "opkg"
                           | "pub" | "puppet" | "pypi" | "rpm" | "sbt"
                           | "swift" | "terraform" | "terraformbackend"
                           | "vagrant" | "ansible" | "generic" (default),
          - "description": "The local repository public description",
          - "notes": "Some internal notes",
          - "includesPattern": "**/*" (default),
          - "excludesPattern": "" (default),
          - "repoLayoutRef": "maven-2-default" (default),
          - "debianTrivialLayout": false,
          - "checksumPolicyType": "client-checksums" (default)
                           | "server-generated-checksums",
          - "handleReleases": true (default),
          - "handleSnapshots": true (default),
          - "maxUniqueSnapshots": 0 (default),
          - "maxUniqueTags": 0 (default),
          - "snapshotVersionBehavior": "unique" (default) | "non-unique"
                           | "deployer",
          - "suppressPomConsistencyChecks": false (default),
          - "blackedOut": false (default),
          - "xrayIndex": false       (default),
          - "propertySets": ["ps1", "ps2"],
          - "archiveBrowsingEnabled": false,
          - "calculateYumMetadata": false,
          - "yumRootDepth": 0,
          - "dockerApiVersion": "V2" (default),
          - "terraformType": "MODULE" | "PROVIDER",
          - "enableFileListsIndexing": "false" (default),
          - "optionalIndexCompressionFormats": ["bz2", "lzma", "xz"],
          - "downloadRedirect": "false" (default),
          - "cdnRedirect": "false" (default, Applies to Artifactory Cloud Only),
          - "blockPushingSchema1": "false",
          - "primaryKeyPairRef": "mygpgkey",
          - "secondaryKeyPairRef": "mysecgpgkey",
          - "forceNugetAuthentication": false (default),
          - "forceP2Authentication": false (default),
          - "forceConanAuthentication": false (default),
          - "encryptStates": true (default),
          - "priorityResolution": "false" (default, Applies to all
            repository types excluding CocoaPods, Git LFS, NuGet V2,
            Opkg, Rust, Vagrant and VCS repositories)
        }
        ```

        <h6>JSON for a remote repository</h6>

        ```text
        {
          - "key": "remote-repo1",
          - "projectKey": "projx",
          - "environments": ["DEV"] (mandatory when assigning repo to project),
          + "rclass" : "remote",
          - "packageType": "alpine" | "cargo" | "composer" | "bower"
                           | "chef" | "cocoapods" | "conan" | "conda"
                           | "cran" | "debian" | "docker" | "helm"
                           | "helmoci" | "huggingfaceml" | "gems"
                           | "gitlfs" | "go" | "gradle" | "ivy"
                           | "maven" | "npm" | "nuget" | "oci" | "opkg"
                           | "pub" | "puppet" | "pypi" | "rpm" | "sbt"
                           | "swift" | "terraform" | "ansible"
                           | "generic" (default),
          + "url" : "http://host:port/some-repo",
          - "username": "remote-repo-user",
          - "password": "pass",
          - "proxy": "proxy1",
          - "disableProxy": false (default),
          - "description": "The remote repository public description",
          - "notes": "Some internal notes",
          - "includesPattern": "**/*" (default),
          - "excludesPattern": "" (default),
          - "repoLayoutRef" : "maven-2-default",
          - "remoteRepoLayoutRef" : "" (default),
          - "remoteRepoChecksumPolicyType":
                           "generate-if-absent" (default)
                           | "fail" | "ignore-and-generate"
                           | "pass-thru",
          - "handleReleases": true (default),
          - "handleSnapshots": true (default),
          - "maxUniqueSnapshots": 0 (default),
          - "suppressPomConsistencyChecks": false (default),
          - "hardFail": false (default),
          - "offline": false (default),
          - "blackedOut": false (default),
          - "storeArtifactsLocally": true (default),
          - "socketTimeoutMillis": 15000 (default),
          - "localAddress": "212.150.139.167",
          - "retrievalCachePeriodSecs": 7200 (default),
          - "missedRetrievalCachePeriodSecs": 1800 (default),
          - "unusedArtifactsCleanupPeriodHours": 0 (default),
          - "assumedOfflinePeriodSecs" : 300 (default),
          - "fetchJarsEagerly": false (default),
          - "fetchSourcesEagerly": false (default),
          - "shareConfiguration": false (default),
          - "synchronizeProperties": false (default),
          - "blockMismatchingMimeTypes" : true (default),
          - "xrayIndex": false (default),
          - "propertySets": ["ps1", "ps2"],
          - "allowAnyHostAuth": false (default),
          - "enableCookieManagement": false (default),
          - "enableTokenAuthentication": false (default),
          - "forceNugetAuthentication": false (default),
          - "forceP2Authentication": false (default),
          - "forceConanAuthentication": false (default),
          - "metadataRetrievalTimeoutSecs": 60 (default),
          - "bowerRegistryUrl": "https://registry.bower.io" (default),
          - "gitRegistryUrl": "https://github.com/rust-lang/crates.io-index" (default),
          - "composerRegistryUrl": "https://packagist.org" (default),
          - "pyPIRegistryUrl": "https://pypi.org" (default),
          - "vcsType": "GIT" (default),
          - "vcsGitProvider": "GITHUB" (default) | "GITHUBENTERPRISE"
                           | "BITBUCKET" | "OLDSTASH" | "STASH"
                           | "ARTIFACTORY" | "CUSTOM",
          - "vcsGitDownloadUrl": "" (default),
          - "bypassHeadRequests" : false (default),
          - "clientTlsCertificate": "" (default),
          + "externalDependenciesEnabled": false (default, Applies to Docker repositories only),
          - "externalDependenciesPatterns": [
              "**/*microsoft*/**",
              "**/*github*/**"
            ] (Applies to Docker repositories only)
          - "downloadRedirect" : "false" (default),
          - "cdnRedirect": "false" (default, Applies to Artifactory Cloud Only),
          - "feedContextPath":"api/v2",
          - "downloadContextPath":"api/v2/package",
          - "v3FeedUrl":"https://api.nuget.org/v3/index.json",
          - "listRemoteFolderItems": "false" (default),
          - "contentSynchronisation": {
              "enabled": false (default),
              "statistics": {
                "enabled": false (default)
              },
              "properties": {
                "enabled": false (default)
              },
              "source": {
                "originAbsenceDetection": false (default)
              }
            },
           - "blockPushingSchema1": false,
           - "priorityResolution": false (default),
           - "disableUrlNormalization": false (default)
        }
        ```

        <h6>JSON for a virtual repository</h6>

        ```text
        {
          - "key": "virtual-repo1",
          - "projectKey": "projx",
          - "environments": ["DEV"] (mandatory when assigning repo to project),
          + "rclass" : "virtual",
          + "packageType": "alpine" | "composer" | "bower" | "chef"
                           | "conan" | "conda" | "cran" | "debian"
                           | "docker" | "helm" | "helmoci"
                           | "huggingfaceml" | "gems" | "gitlfs" | "go"
                           | "gradle" | "ivy" | "maven" | "npm"
                           | "nuget" | "oci" | "pub" | "puppet" | "pypi"
                           | "rpm" | "sbt" | "swift" | "terraform"
                           | "ansible" | "generic" (default),
          - "repositories": ["local-rep1", "local-rep2", "remote-rep1", "virtual-rep2"]
          - "description": "The virtual repository public description",
          - "notes": "Some internal notes",
          - "includesPattern": "**/*" (default),
          - "excludesPattern": "" (default),
          - "repoLayoutRef": "maven-2-default",
          - "debianTrivialLayout" : false,
          - "debianDefaultArchitectures" : "arm64,amd64", (applies to Debian repositories only),
          - "artifactoryRequestsCanRetrieveRemoteArtifacts": false,
          - "keyPair": "keypair1",
          - "pomRepositoryReferencesCleanupPolicy":
                           "discard_active_reference" (default)
                           | "discard_any_reference" | "nothing"
          - "defaultDeploymentRepo": "local-repo1",
          - "optionalIndexCompressionFormats" : ["bz2", "lzma", "xz"],
          - "forceMavenAuthentication": false, (default - Applies to Maven repositories only),
          + "externalDependenciesEnabled": false (default - Applies to Bower, npm and Go repositories only),
          - "externalDependenciesPatterns": [
              "**/*microsoft*/**",
              "**/*github*/**"
            ] (Applies to Bower, npm and Go repositories only),
          - "externalDependenciesRemoteRepo": "" (Applies to Bower and npm repositories only),
          - "primaryKeyPairRef": "mygpgkey",
          - "secondaryKeyPairRef": "mysecgpgkey"
        }
        ```

        <h6>JSON for a federated repository</h6>

        ```text
        {
          - "key": "federated-repo1",
          - "projectKey": "projx",
          - "environments": ["DEV"] (mandatory when assigning repo to project),
          + "rclass" : "federated",
          - "packageType": "alpine" | "maven" | "gradle" | "ivy" | "sbt"
                           | "helm" | "helmoci" |"huggingfaceml"
                           | "cargo" | "cocoapods" | "opkg" | "rpm"
                           | "nuget" | "cran" | "gems" | "npm" | "bower"
                           | "debian" | "composer" | "oci" | "pypi"
                           | "docker" | "vagrant" | "gitlfs" | "go"
                           | "ansible" | "conan" | "conda" | "chef"
                           | "puppet" | "generic" (default)
          - "members": [
              {
                "url": "http://targetartifactory/artifactory/repositoryName",
                "enabled":"true"
              }
            ],
          - "description": "The federated repository public description",
          - "proxy": "proxy-key",
          - "disableProxy": false (default),
          - "notes": "Some internal notes",
          - "includesPattern": "**/*" (default),
          - "excludesPattern": "" (default),
          - "repoLayoutRef" : "maven-2-default" (default),
          - "debianTrivialLayout" : false,
          - "checksumPolicyType": "client-checksums" (default)
                           | "server-generated-checksums"
          - "handleReleases": true (default),
          - "handleSnapshots": true (default),
          - "maxUniqueSnapshots": 0 (default),
          - "maxUniqueTags": 0 (default),
          - "snapshotVersionBehavior": "unique" (default) | "non-unique"
                           | "deployer",
          - "suppressPomConsistencyChecks": false (default),
          - "blackedOut": false (default),
          - "xrayIndex" : false (default),
          - "propertySets": ["ps1", "ps2"],
          - "archiveBrowsingEnabled" : false,
          - "calculateYumMetadata" : false,
          - "yumRootDepth" : 0,
          - "dockerApiVersion" : "V2" (default),
          - "enableFileListsIndexing" : "false" (default),
          - "optionalIndexCompressionFormats" : ["bz2", "lzma", "xz"],
          - "downloadRedirect" : "false" (default),
          - "cdnRedirect": "false" (default, Applies to Artifactory Cloud Only),
          - "blockPushingSchema1": "false",
          - "primaryKeyPairRef": "mygpgkey",
          - "secondaryKeyPairRef": "mysecgpgkey",
          - "priorityResolution": false (default)
        }
        ```
        """
        ensure_nonemptystring('name')
        ensure_noneorinstance('pos', int)

        if json is not None:
            if rclass is not None:
                raise ValueError(INCOMPATIBLE_PARAM % 'rclass')
            if package_type is not None:
                raise ValueError(INCOMPATIBLE_PARAM % 'package_type')
            if url is not None:
                raise ValueError(INCOMPATIBLE_PARAM % 'url')
            if description is not None:
                raise ValueError(INCOMPATIBLE_PARAM % 'description')
            if notes is not None:
                raise ValueError(INCOMPATIBLE_PARAM % 'notes')
            if includes_pattern is not None:
                raise ValueError(INCOMPATIBLE_PARAM % 'includes_pattern')
            if excludes_pattern is not None:
                raise ValueError(INCOMPATIBLE_PARAM % 'excludes_pattern')
            if repositories is not None:
                raise ValueError(INCOMPATIBLE_PARAM % 'repositories')
            data = json
        else:
            if rclass is None:
                raise ValueError('rclass required if json is not provided')
            if package_type is None:
                raise ValueError(
                    'package_type required if json is not provided'
                )

            ensure_in('rclass', ['local', 'remote', 'virtual'])
            ensure_in('package_type', PACKAGE_TYPES)

            if rclass == 'remote' and url is None:
                raise ValueError('url required for remote repositories')
            if rclass != 'virtual':
                if repositories is not None:
                    raise ValueError(
                        'repositories cannot be specified for '
                        'non-virtual repositories'
                    )
                if default_deployment_repo is not None:
                    raise ValueError(
                        'default deployment repository cannot '
                        'be specified for non-virtual repositories'
                    )

            data = {'key': name, 'rclass': rclass, 'packageType': package_type}
            add_if_specified(data, 'url', url)
            add_if_specified(data, 'description', description)
            add_if_specified(data, 'notes', notes)
            add_if_specified(data, 'includesPattern', includes_pattern)
            add_if_specified(data, 'excludesPattern', excludes_pattern)
            add_if_specified(data, 'repositories', repositories)
            add_if_specified(
                data, 'defaultDeploymentRepo', default_deployment_repo
            )

        api_url = f'repositories/{name}'
        if pos is not None:
            api_url += f'?pos={pos}'

        result = self._put(api_url, json=data)
        return None if result.status_code == 200 else result  # type: ignore

    @api_call
    def update_repository(
        self, repository_name: str, json: Dict[str, Any]
    ) -> None:
        """Update an existing repository.

        No direct interface for now.

        # Required parameters

        - repository_name: a non-empty string
        - json: a dictionary

        # Raised exceptions

        An _ApiError_ exception is raised  if the update was not
        successful.
        """
        ensure_nonemptystring('repository_name')

        result = self._post(f'repositories/{repository_name}', json=json)
        return None if result.status_code == 200 else result  # type: ignore

    @api_call
    def delete_repository(self, repository_name: str) -> bool:
        """Delete repository.

        # Required parameters

        - repository_name: a non-empty string

        # Returned value

        A boolean.  True if successful.
        """
        ensure_nonemptystring('repository_name')

        return (
            self._delete(f'repositories/{repository_name}').status_code == 200
        )

    ####################################################################
    # artifactory permission targets
    #
    # list_permissions
    # get_permission
    # create_or_replace_permission
    # delete_permission

    @api_call
    def list_permissions(self) -> List[Dict[str, str]]:
        """Return the permission targets list.

        # Returned value

        A list of _permission targets_.  Each permission target is a
        dictionary with the following entries:

        - name: a string
        - uri: a string
        """
        return self._get('security/permissions')  # type: ignore

    @api_call
    def get_permission(self, permission_name: str) -> Dict[str, Any]:
        """Return the permission target details.

        # Required parameters

        - permission_name: a non-empty string

        # Returned value

        A dictionary with the following entries:

        - excludesPattern: a string
        - includesPattern: a string
        - name: a string
        - principals: a dictionary
        - repositories: a list of strings
        """
        ensure_nonemptystring('permission_name')

        return self._get(f'security/permissions/{permission_name}')  # type: ignore

    @api_call
    def create_or_replace_permission(
        self,
        permission_name: str,
        repositories: List[str],
        includes_pattern: str = '**/*',
        excludes_pattern: str = '',
        principals: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Create or replace permission target.

        # Required parameters

        - permission_name: a non-empty string
        - repositories: a list of strings

        # Optional parameters

        - includes_pattern: a string (`'**/*'` by default)
        - excludes_pattern: a string  (`''` by default)
        - principals: a dictionary or None (None by default)

        # Usage

        `repositories` is a list of repository names.

        `includes_pattern` and `excludes_pattern` may contain more than
        one pattern, separated by comas.

        `principals` is a dictionary or None:

        > Legend: `'m'`=admin, `'d'`=delete, `'w'`=deploy,
        > `'n'`=annotate, `'r'`=read.

        ```json
        {
          "users" : {
            "bob": ["r", "w", "m"],
            "alice" : ["d", "w", "n", "r"]
          },
          "groups" : {
            "dev-leads" : ["m", "r", "n"],
            "readers" : ["r"]
          }
        }
        ```
        """
        ensure_nonemptystring('permission_name')

        data = {
            'name': permission_name,
            'includesPattern': includes_pattern,
            'excludesPattern': excludes_pattern,
            'repositories': repositories,
        }
        add_if_specified(data, 'principals', principals)

        result = self._put(
            f'security/permissions/{permission_name}', json=data
        )
        return result  # type: ignore

    @api_call
    def delete_permission(self, permission_name: str) -> bool:
        """Delete permission target.

        # Required parameters

        - permission_name: a non-empty string

        # Returned value

        A boolean.  True if successful.
        """
        ensure_nonemptystring('permission_name')

        return (
            self._delete(f'security/permissions/{permission_name}').status_code
            == 200
        )

    ####################################################################
    # artifactory token
    #
    # create_token
    # create_token2
    # list_tokens
    # list_token2

    @api_call
    def create_token(
        self,
        username: str,
        scope: Optional[str] = None,
        grant_type: str = 'client_credentials',
        expires_in: int = 3600,
        refreshable: bool = False,
        audience: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new token.

        # Required parameters

        - username: a string
        - scope: a string (only required if `username` does not exists)

        # Optional parameters

        - grant_type: a string (`'client_credentials'` by default)
        - expires_in: an integer (`3600` by default)
        - refreshable: a boolean (False by default)
        - audience: a string or None (None by default)

        `expires_in` is in seconds (1 hour by default). Administrators
        can set it to 0 so that the token never expires.

        TODO: check `username` existence.

        # Returned value

        A dictionary with the following entries:

        - access_token: a string
        - expires_in: an integer
        - scope: a string
        - token_type: a string
        """
        ensure_instance('username', str)
        ensure_noneorinstance('scope', str)
        ensure_instance('grant_type', str)
        ensure_instance('expires_in', int)
        ensure_instance('refreshable', bool)
        ensure_noneorinstance('audience', str)

        data = {
            'username': username,
            'grant_type': grant_type,
            'expires_in': str(expires_in),
            'refreshable': str(refreshable),
        }
        add_if_specified(data, 'scope', scope)
        add_if_specified(data, 'audience', audience)

        result = self._post('security/token', data=data)
        return result  # type: ignore

    @api_call
    def create_token2(
        self,
        username: str,
        scope: Optional[str] = None,
        grant_type: str = 'client_credentials',
        expires_in: int = 3600,
        refreshable: bool = False,
        audience: Optional[str] = None,
        project_key: Optional[str] = None,
        description: Optional[str] = None,
        include_reference_token: bool = False,
    ) -> Dict[str, Any]:
        """Create a new access token.

        # Required parameters

        - username: a string
        - scope: a string (only required if `username` does not exists)

        # Optional parameters

        - grant_type: a string (`'client_credentials'` by default)
        - expires_in: an integer (`3600` by default)
        - refreshable: a boolean (False by default)
        - audience: a string or None (None by default)
        - project_key: a string or None (None by default)
        - description: a string or None (None by default)
        - include_reference_token: a boolean (False by default)

        `expires_in` is in seconds (1 hour by default). Administrators
        can set it to `0` so that the token never expires.

        # Returned value

        A dictionary with the following entries:

        - access_token: a string
        - expires_in: an integer
        - scope: a string
        - token_id: a string
        - token_type: a string
        """
        ensure_instance('username', str)
        ensure_noneorinstance('scope', str)
        ensure_instance('grant_type', str)
        ensure_instance('expires_in', int)
        ensure_instance('refreshable', bool)
        ensure_noneorinstance('audience', str)
        ensure_noneorinstance('project_key', str)
        ensure_noneorinstance('description', str)
        ensure_instance('include_reference_token', bool)

        data = {
            'username': username,
            'grant_type': grant_type,
            'expires_in': str(expires_in),
            'refreshable': str(refreshable),
            'include_reference_token': str(include_reference_token),
        }
        add_if_specified(data, 'scope', scope)
        add_if_specified(data, 'audience', audience)
        add_if_specified(data, 'project_key', project_key)
        add_if_specified(data, 'description', description)

        return self._post('access/api/v1/tokens', data=data)  # type: ignore

    @api_call
    def list_tokens(self) -> List[Dict[str, Any]]:
        """Return list of tokens.

        The returned `subject` contains the token creator ID.

        # Returned value

        A list of _tokens_.  Each token is a dictionary with the
        following entries:

        - issued_at: an integer (a timestamp)
        - issuer: a string
        - refreshable: a boolean
        - subject: a string
        - token_id: a string
        """
        return self._get('security/token').json()['tokens']  # type: ignore

    @api_call
    def list_tokens2(self) -> List[Dict[str, Any]]:
        """Return list of tokens.

        The returned `subject` contains the token creator ID.

        # Returned value

        A list of _tokens_.  Each token is a dictionary with the
        following entries:

        - description: a string
        - expiry: an integer (a timestamp)
        - issued_at: an integer (a timestamp)
        - issuer: a string
        - refreshable: a boolean
        - subject: a string
        - token_id: a string
        """
        return self._get('access/api/v1/tokens').json()['tokens']  # type: ignore

    ####################################################################
    # artifactory artefacts information
    #
    # get_file_info
    # get_folder_info
    # get_file_properties
    # get_file_stats

    @api_call
    def get_file_info(self, repository_name: str, path: str) -> Dict[str, Any]:
        """Return folder information

        For virtual use the virtual repository returns the resolved
        file. Supported by local, local-cached and virtual repositories.

        # Required parameters

        - repository_name: a non-empty string
        - path: a non-empty string

        # Returned value

        A dictionary with the following entries:

        - checksums: a dictionary
        - created: a string (ISO8601, yyyy-MM-dd'T'HH:mm:ss.SSSZ)
        - createdBy: a string
        - downloadUri: a string
        - lastModified: a string (ISO8601)
        - lastUpdated: a string (ISO8601)
        - mimeType: a string
        - modifiedBy: a string
        - originalChecksums: a dictionary
        - path: a string (same as `path`)
        - remoteUrl: a string
        - repo: a string (same as `repository_name`)
        - size: a string (in bytes)
        - uri: a string

        The `checksums` and the `originalChecksums` dictionaries have
        the following entries:

        - md5: a string
        - sha1: a string
        - sha256: a string
        """
        ensure_nonemptystring('repository_name')
        ensure_nonemptystring('path')

        return self._get(f'storage/{repository_name}/{path}')  # type: ignore

    @api_call
    def get_folder_info(
        self, repository_name: str, path: str
    ) -> Dict[str, Any]:
        """Return folder information

        For virtual use, the virtual repository returns the unified
        children. Supported by local, local-cached and virtual
        repositories.

        # Required parameters

        - repository_name: a non-empty string
        - path: a non-empty string

        # Returned value

        A dictionary with the following entries:

        - children: a list of dictionaries
        - created: a string (ISO8601, yyyy-MM-dd'T'HH:mm:ss.SSSZ)
        - createdBy: a string
        - lastModified: a string (ISO8601)
        - lastUpdated: a string (ISO8601)
        - modifiedBy: a string
        - path: a string (same as `path`)
        - repo: a string (same as `repository_name`)
        - uri: a string

        Each dictionary in the `children` list has the following
        entries:

        - folder: a boolean
        - uri: a string
        """
        ensure_nonemptystring('repository_name')
        ensure_nonemptystring('path')

        return self._get(f'storage/{repository_name}/{path}')  # type: ignore

    @api_call
    def get_file_properties(
        self,
        repository_name: str,
        path: str,
        properties: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Return file statistics.

        Item statistics record the number of times an item was
        downloaded, last download date and last downloader. Supported by
        local and local-cached repositories.

        # Required parameters

        - repository_name: a non-empty string
        - path: a non-empty string

        # Optional parameters

        - properties: a list of strings or None (None by default, i.e.,
          returns all properties)

        # Returned value

        A dictionary with the following entries:

        - properties: a dictionary.
        - uri: a string

        The `properties` dictionary has one entry per property.  The key
        is the property name (a string) and the value is the property
        value (property-dependent).

        # Raised exceptions

        If no property exists, an _ApiError_ exception is raised.
        """
        ensure_nonemptystring('repository_name')
        ensure_nonemptystring('path')

        props = 'properties'
        if properties is not None:
            properties += '=' + ','.join(properties)

        return self._get(f'storage/{repository_name}/{path}?{props}')  # type: ignore

    @api_call
    def get_file_stats(
        self, repository_name: str, path: str
    ) -> Dict[str, Any]:
        """Return file statistics.

        Item statistics record the number of times an item was
        downloaded, last download date and last downloader. Supported by
        local and local-cached repositories.

        # Required parameters

        - repository_name: a non-empty string
        - path: a non-empty string

        # Returned value

        A dictionary with the following entries:

        - downloadCount: an integer
        - lastDownloaded: an integer (a timestamp)
        - lastDownloadedBy: a string
        - uri: a string
        """
        ensure_nonemptystring('repository_name')
        ensure_nonemptystring('path')

        return self._get(f'storage/{repository_name}/{path}?stats')  # type: ignore

    ####################################################################
    # artifactory information
    #
    # get_storageinfo
    # get_version

    @api_call
    def get_version(self) -> Dict[str, Any]:
        """Return version information.

        # Returned value

        A dictionary with the following entries:

        - addons: a list of strings
        - license: a string
        - revision: a string
        - version: a string (the currently installed version)
        """
        return self._get('system/version')  # type: ignore

    @api_call
    def get_storageinfo(self) -> Dict[str, Any]:
        """Return storage information.

        # Returned value

        A dictionary with the following 4 entries:

        - binariesSummary: a dictionary
        - fileStoreSummary: a dictionary
        - repositoriesSummaryList: a list of dictionaries
        - storageSummary: a dictionary

        `binariesSummary` has the following entries:

        - artifactsCount: a string (`'15,492'`)
        - artifactsSize: a string (`'144.68 GB'`)
        - binariesCount: a string (`'13,452'`)
        - binariesSize: a string (`'116.97 GB'`)
        - itemsCount: a string (`'28,348'`)
        - optimization: a string (`'80.85%'`)

        `fileStoreSummary` has the following entries:

        - freeSpace: a string (`'145.32 GB (29.53%)'`)
        - storageDirectory: a string
            (`'/data/artifactory/data/filestore'`)
        - storageType: a string (`'file-system'`)
        - totalSpace: a string (`'492.03 GB'`)
        - usedSpace: a string (`'346.71 GB (70.47%)'`)

        `storageSummary` has the following entries:

        - binariesSummary: a dictionary (same as above)
        - fileStoreSummary:a dictionary (same as above)
        - repositoriesSummaryList: a list of dictionaries (same as
            below)

        Dictionaries in the `repositoriesSummaryList` list have the
        following entries:

        - filesCount: an integer
        - foldersCount: an integer
        - itemsCount: an integer
        - packageType: a string
        - percentage: a string (`'0%'`)
        - repoKey: a string (`'project-maven-scratch'`)
        - repoType: a string (`'VIRTUAL'`, `'LOCAL'`, `'CACHE'`, or
            `'NA'`)
        - usedSpace: a string (`'0 bytes'`)

        Two 'virtual' items are added to the `repositoriesSummaryList`
        list: the 'auto-trashcan' item and the 'TOTAL' item.

        Please note that the 'TOTAL' item has no `packageType` entry
        (but the 'auto-trashcan' has one, valued to `'NA'`).

        Those two items have a `repoType` entry valued to `'NA'`.
        """
        return self._get('storageinfo')  # type: ignore

    ####################################################################
    # artifactory health check
    #
    # ping

    @api_call
    def ping(self) -> bool:
        """Check if instance is OK.

        # Returned value

        A boolean.  True if Artifactory is working properly.
        """
        response = self._get('system/ping')
        return response.status_code == 200 and response.text == 'OK'

    ####################################################################
    # jfrog xray indexing
    #
    # get_reposindexing_configuration
    # update_reposindexing_configuration

    @api_call
    def get_reposindexing_configuration(
        self, bin_mgr_id: str = 'default'
    ) -> Dict[str, Any]:
        """Get indexed and not indexed repositories for binmgr.

        # Optional parameters

        - bin_mgr_id: a string (`'default'` by default)

        # Returned value

        A dictionary with the following entries:

        - bin_mgr_id: a string
        - indexed_repos: a list of dictionaries
        - non_indexed_repos: a list of dictionaries

        Items in `indexed_repos` and `non_indexed_repositories` have the
        following entries:

        - name: a string
        - pkg_type: a string
        - type: a string (`'local'` or `'remote'`)
        """
        ensure_nonemptystring('bin_mgr_id')

        return self._get_xray(f'/v1/binMgr/{bin_mgr_id}/repos')  # type: ignore

    @api_call
    def update_reposindexing_configuration(
        self,
        indexed_repos: List[Dict[str, Any]],
        non_indexed_repos: List[Dict[str, Any]],
        bin_mgr_id: str = 'default',
    ) -> Dict[str, Any]:
        """Update indexed and not indexed repositories for binmgr.

        # Required parameters

        - indexed_repos: a list of dictionaries
        - non_indexed_repos: a list of dictionaries

        # Optional parameters

        - bin_mgr_id: a string (`'default'` by default)

        # Returned value

        A status dictionary, with an `info` entry (a string) describing
        the operation result.
        """
        ensure_instance('indexed_repos', list)
        ensure_instance('non_indexed_repos', list)
        ensure_nonemptystring('bin_mgr_id')

        what = {
            'indexed_repos': indexed_repos,
            'non_indexed_repos': non_indexed_repos,
        }
        return self._put_xray(f'/v1/binMgr/{bin_mgr_id}/repos', json=what)  # type: ignore

    ####################################################################
    # artifactory private helpers

    def _get(
        self,
        api: str,
        params: Optional[
            Mapping[str, Union[str, Iterable[str], int, bool]]
        ] = None,
    ) -> requests.Response:
        """Return artifactory api call results, as Response."""
        api_url = join_url(self.url, api)
        return self.session().get(api_url, params=params)

    def _get_xray(self, api: str) -> requests.Response:
        """Return xray api call results, as Response."""
        api_url = join_url(self.url_xray, api)
        return self.session().get(api_url)

    def _get_batch(self, apis: Iterable[str]) -> List[Dict[str, Any]]:
        """Return list of JSON results."""
        return [
            self.session().get(join_url(self.url, api)).json() for api in apis
        ]

    def _patch(
        self,
        api: str,
        json: Optional[Mapping[str, Any]] = None,
        data: Optional[Union[MutableMapping[str, str], bytes]] = None,
    ) -> requests.Response:
        api_url = join_url(self.url, api)
        return self.session().patch(api_url, json=json, data=data)

    def _post(
        self,
        api: str,
        json: Optional[Mapping[str, Any]] = None,
        data: Optional[Union[MutableMapping[str, str], bytes]] = None,
    ) -> requests.Response:
        api_url = join_url(self.url, api)
        return self.session().post(api_url, json=json, data=data)

    def _put(self, api: str, json: Dict[str, Any]) -> requests.Response:
        api_url = join_url(self.url, api)
        return self.session().put(api_url, json=json)

    def _put_xray(self, api: str, json: Dict[str, Any]) -> requests.Response:
        api_url = join_url(self.url_xray, api)
        return self.session().put(api_url, json=json)

    def _delete(self, api: str) -> requests.Response:
        api_url = join_url(self.url, api)
        return self.session().delete(api_url)

    # variants with explicit credentials

    def _get2(self, api: str, auth: Tuple[str, str]) -> requests.Response:
        """Return artifactory api call results w/ auth."""
        api_url = join_url(self.url, api)
        return requests.get(api_url, auth=auth)

    def _post2(self, api: str, auth: Tuple[str, str]) -> requests.Response:
        """Return artifactory api call results w/ auth."""
        api_url = join_url(self.url, api)
        return requests.post(api_url, auth=auth)

    def _delete2(self, api: str, auth: Tuple[str, str]) -> requests.Response:
        """Return artifactory api call results w/ auth."""
        api_url = join_url(self.url, api)
        return requests.delete(api_url, auth=auth)
