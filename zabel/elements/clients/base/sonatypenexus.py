# Copyright (c) 2025 Martin Lafaix (mlafaix@henix.com)
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

"""Sonatype Nexus Repository Manager.

A class wrapping Sonatype Nexus APIs.

There can be as many Sonatype Nexus instances as needed.

!!! note
    Does not use the **nexus_api_client** library, as it fails on
    components and assets validation.

This module depends on the **requests** public library.  It also depends
on three **zabel-commons** modules, #::zabel.commons.exceptions,
#::zabel.commons.sessions, and #::zabel.commons.utils.
"""

from typing import Any, Dict, List, Mapping, Optional, Tuple, Union

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

# Sonatype Nexus low-level API


class SonatypeNexus:
    """Sonatype Nexus Low-Level Wrapper.

    ## Reference URLs

    - <https://help.sonatype.com/en/api-reference.html>
    - <https://pypi.org/project/nexus_api_client/>

    !!! note
        Does not use the **nexus_api_client** library, as it fails on
        components and assets validation on some supported versions
        (PRO 3.70.4-02)

    ## Implemented features

    - repositories
    - tags
    - users
    - roles
    - privileges
    - misc. features (sources, metrics, ...)

    ## Examples

    ```python
    # standard use
    from zabel.elements.clients import SonatypeNexus

    url = 'https://nexus.example.com/nexus/service/rest'
    token = '...'
    nx = SonatypeNexus(url, bearer_token=token)
    nx.list_repositories()
    ```
    """

    def __init__(
        self,
        url: str,
        *,
        basic_auth: Optional[Tuple[str, str]] = None,
        bearer_token: Optional[str] = None,
        verify: Union[bool, str] = True,
    ) -> None:
        """Create a Sonatype Nexus instance object.

        You can only specify either `basic_auth` or both `bearer_token`.

        # Required parameters

        - url: a non-empty string

        and one of

        - basic_auth: a strings tuple (user, token)
        - bearer_token: a non-empty string

        # Optional parameters

        - verify: a boolean or string

        # Usage

        `url` is the top-level API point.  For example:

            'https://nexus.example.com/nexus/service/rest'

        `verify` can be set to False if disabling certificate checks for
        Sonatype Nexus communication is required.  Tons of warnings will
        occur if this is set to False.
        """
        ensure_nonemptystring('url')
        ensure_noneorinstance('basic_auth', tuple)
        ensure_noneorinstance('bearer_token', str)
        ensure_onlyone('basic_auth', 'bearer_token')
        ensure_instance('verify', (bool, str))

        self.url = url
        if bearer_token:
            self.auth = BearerAuth(bearer_token)
        else:
            self.auth = basic_auth
        self.verify = verify
        self.session = prepare_session(self.auth, verify=self.verify)

    def __str__(self) -> str:
        return f'{self.__class__.__name__}: {self.url}'

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__}: {self.url!r}>'

    ####################################################################
    # Repositories
    #
    # list_repositories
    # list_repositorysettings
    # get_repository
    # list_repository_assets
    # list_repository_components

    @api_call
    def list_repositories(self) -> List[Dict[str, Any]]:
        """Return a list of repositories.

        # Returned value

        A list of _repositories_.  Each repository is a dictionary
        containing the following keys:

        - attributes: a dictionary
        - format: a string
        - name: a string
        - type: a string
        - url: a string
        """
        result = self._get('v1/repositories')
        return result  # type: ignore

    @api_call
    def list_repositorysettings(self) -> List[Dict[str, Any]]:
        """Return a list of repository settings.

        # Returned value

        A list of _repository settings_.  Each repository setting is a
        dictionary containing the following keys:

        - format: a string
        - name: a string
        - online: a boolean
        - type: a string
        - url: a string
        """
        result = self._get('v1/repositorySettings')
        return result  # type: ignore

    @api_call
    def get_repository(self, repository_name: str) -> Dict[str, Any]:
        """Return a repository.

        # Required parameters

        - repository_name: a non-empty string

        # Returned value

        A _repository_ dictionary containing the following keys:

        - attributes: a dictionary
        - format: a string
        - name: a string
        - type: a string
        - url: a string
        """
        ensure_nonemptystring('repository_name')

        result = self._get(f'v1/repositories/{repository_name}')
        return result  # type: ignore

    @api_call
    def list_repository_assets(
        self, repository_name: str
    ) -> List[Dict[str, Any]]:
        """Return a list of assets in a repository.

        # Required parameters

        - repository_name: a non-empty string

        # Returned value

        A list of _assets_.  Each asset is a dictionary containing the
        following keys:

        - blobCreated: a string (`'2025-05-05T09:48:40.935+00:00'`)
        - checksum: a dictionary of checksums
        - contentType: a string
        - downloadUrl: a string
        - fileSize: an integer
        - format: a string (`'pypi'`, ...)
        - id: a string
        - lastDownloaded: a string (`'2025-05-05T09:56:21.840+00:00'`)
        - lastModified: a string (`'2025-05-05T09:48:40.935+00:00'`)
        - path: a string
        - repository: a string
        - uploader: a string
        - uploaderIp: a string

        It may contain additional entries depending on the asset's
        format.
        """
        ensure_nonemptystring('repository_name')

        return self._collect_data(
            'v1/assets', params={'repository': repository_name}
        )

    @api_call
    def list_repository_components(
        self, repository_name: str
    ) -> List[Dict[str, Any]]:
        """Return a list of components in a repository.

        # Required parameters

        - repository_name: a non-empty string

        # Returned value

        A list of _components_.  Each component is a dictionary
        containing the following keys:

        - assets: a list of dictionaries
        - format: a string (`'pypi'`, ...)
        - group: a string or None
        - id: a string
        - name: a string
        - repository: a string
        - tags: a list of dictionaries
        - version: a string
        """
        ensure_nonemptystring('repository_name')

        return self._collect_data(
            'v1/components', params={'repository': repository_name}
        )

    ####################################################################
    # Tags
    #
    # list_tags

    @api_call
    def list_tags(self) -> List[Dict[str, Any]]:
        """Return a list of tags.

        # Returned value

        A list of _tags_.  Each tag is a dictionary containing the
        following keys:

        - attributes: a dictionary
        - firstCreated: a string (`'2025-03-01T00:00:00Z'`)
        - lastUpdated: a string (`'2025-03-01T00:00:00Z'`)
        - name: a string
        """
        return self._collect_data('v1/tags')

    ####################################################################
    # Users
    #
    # create_user
    # list_users

    @api_call
    def create_user(
        self,
        user_id: str,
        first_name: str,
        last_name: str,
        email_address: str,
        password: str,
        status: str,
        roles: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Create a user.

        # Required parameters

        - user_id: a non-empty string
        - first_name: a non-empty string
        - last_name: a non-empty string
        - email_address: a non-empty string
        - password: a non-empty string
        - status: a non-empty string (one of `'active'`, `'locked'`,
         `'disabled'`, or `'changepassword'`)

        # Optional parameters

        - roles: a list of strings (default None)

        # Returned value

        A dictionary containing the created user data.
        """
        ensure_nonemptystring('user_id')
        ensure_nonemptystring('first_name')
        ensure_nonemptystring('last_name')
        ensure_nonemptystring('email_address')
        ensure_nonemptystring('password')
        ensure_in('status', ('active', 'locked', 'disabled', 'changepassword'))
        ensure_noneorinstance('roles', list)

        data = {
            'userId': user_id,
            'firstName': first_name,
            'lastName': last_name,
            'emailAddress': email_address,
            'password': password,
            'status': status,
            'roles': roles or [],
        }

        return self._post('v1/security/users', data)  # type: ignore

    @api_call
    def list_users(
        self, source: Optional[str] = None, user_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Return the list of users.

        # Optional parameters

        - source: a non-empty string or None
        - user_id: a non-empty string or None

        # Returned value

        A list of _users_.  Each user is a dictionary containing the
        following keys:

        - emailAddress: a string
        - externalRoles: a list of strings
        - firstName: a string
        - lastName: a string
        - readOnly: a boolean
        - roles: a list of strings
        - source: a string
        - status: a string (`'active'`)
        - userId: a string
        """
        ensure_noneornonemptystring('source')
        ensure_noneornonemptystring('user_id')

        params = {}
        add_if_specified(params, 'source', source)
        add_if_specified(params, 'userId', user_id)

        return self._get('v1/security/users', params=params)  # type: ignore

    ####################################################################
    # Roles
    #
    # list_roles
    # get_role

    @api_call
    def list_roles(self, source: Optional[str] = None) -> List[Dict[str, Any]]:
        """Return the list of roles.

        # Optional parameters

        - source: a non-empty string or None (None by default)

        # Returned value

         A list of _roles_.  Each role is a dictionary containing the
         following keys:

        - description: a string
        - id: a string
        - name: a string
        - privileges: a list of strings
        - readOnly: a boolean
        - roles: a list of strings
        - source: a string
        """
        ensure_noneornonemptystring('source')

        params = {}
        add_if_specified(params, 'source', source)

        return self._get('v1/security/roles', params=params)  # type: ignore

    @api_call
    def get_role(
        self, role_id: str, source: str = 'default'
    ) -> Dict[str, Any]:
        """Get role details.

         # Required parameters

         - role_id: a non-empty string

         # Optional parameters

         - source: a non-empty string (`'default'` by default)

         # Returned value

         A _role_.  A role is a dictionary containing the following
         keys:

        - description: a string
        - id: a string
        - name: a string
        - privileges: a list of strings
        - readOnly: a boolean
        - roles: a list of strings
        - source: a string
        """
        ensure_nonemptystring('role_id')
        ensure_nonemptystring('source')

        return self._get(f'v1/security/roles/{role_id}', params={'source': source})  # type: ignore

    ####################################################################
    # Privileges
    #
    # list_privileges
    # get_privilege

    @api_call
    def list_privileges(self) -> List[Dict[str, Any]]:
        """Return the list of privileges.

        # Returned value

         A list of _privileges_.  Each privilege is a dictionary
         containing the following keys:

        - description: a string
        - name: a string
        - readOnly: a boolean
        - type: a string
        """
        return self._get('v1/security/privileges')  # type: ignore

    @api_call
    def get_privilege(self, privilege_id: str) -> Dict[str, Any]:
        """Get privilege details.

         # Required parameters

         - privilege_id: a non-empty string

         # Returned value

         A _privilege_.  A privilege is a dictionary containing the
         following keys:

        - description: a string
        - name: a string
        - readOnly: a boolean
        - type: a string
        """
        ensure_nonemptystring('privilege_id')

        return self._get(f'v1/security/privileges/{privilege_id}')  # type: ignore

    ####################################################################
    # User sources
    #
    # list_sources

    @api_call
    def list_sources(self) -> List[Dict[str, str]]:
        """Return the list of user sources.

        # Returned value

        A list of _user source_.  A user source is a dictionary with
        the following keys:

        - id: a string
        - name: a string
        """
        return self._get('v1/security/user-sources')  # type: ignore

    ####################################################################
    # Miscellaneous
    #
    # get_monthly_metrics

    @api_call
    def get_monthly_metrics(self) -> List[Dict[str, Any]]:
        """Return monthly metrics.

        For versions that support this endpoint.

        # Returned value

        A list of dictionaries containing the following keys for the
        last 12 months:

        - componentCount: an integer
        - metricDate: a string (`'2025-03-01T00:00:00Z'`)
        - percentageChangeComponent
        - percentageChangeRequest
        - requestCount: an integer
        """
        return self._get('v1/monthly-metrics')  # type: ignore

    ####################################################################
    # Wrapper helpers
    #
    # All helpers are api_call-compatibles (i.e., they can be used as
    # a return value)

    def _get(
        self,
        api: str,
        params: Optional[Mapping[str, Union[str, List[str], None]]] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> requests.Response:
        """Return API call results, as Response."""
        api_url = join_url(self.url, api)
        return self.session().get(api_url, headers=headers, params=params)

    def _collect_data(
        self,
        api: str,
        params: Optional[Dict[str, Union[str, List[str], None]]] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> List[Dict[str, Any]]:
        """Return Sonatype Nexus API call results, collected.

        The API call is expected to return a list of items. If not,
        an _ApiError_ exception is raised.
        """
        api_url = join_url(self.url, api)
        collected: List[Dict[str, Any]] = []
        params = params or {}
        while True:
            response = self.session().get(
                api_url, params=params, headers=headers
            )
            if response.status_code // 100 != 2:
                raise ApiError(response.text)
            try:
                resp = response.json()
                collected += resp['items']
            except Exception as exception:
                raise ApiError(exception)
            if resp.get('continuationToken'):
                params['continuationToken'] = resp['continuationToken']
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
