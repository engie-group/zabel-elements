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

from typing import Any, Dict, List, Mapping, Optional, Union

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

# Sonatype Nexus low-level api


class SonatypeNexus:
    """Sonatype Nexus Low-Level Wrapper.

    # Reference URL

    - <https://help.sonatype.com/en/api-reference.html>
    - <https://pypi.org/project/nexus_api_client/>

    # Implemented features

    - ...

    # Sample use

    ```python
    # standard use
    from zabel.elements.clients import SonatypeNexus

    url = 'https://nexus.example.com/nexus/service/rest'
    nx = SonatypeNexus(url, access_token=access_token)
    nx.list_project_protectedbranches()
    ```

    !!! note
        Reuse the nexus_api_client library whenever possible, but always
        returns 'raw' values (dictionaries, ..., not classes).
    """

    def __init__(
        self,
        url: str,
        *,
        username: Optional[str] = None,
        password: Optional[str] = None,
        access_token: Optional[str] = None,
        verify: Union[bool, str] = True,
    ) -> None:
        """Create a GitLab instance object.

        You can only specify either `access_token` or both `username`
        and `password`.

        # Required parameters

        - url: a non-empty string

        and one of

        - username: a non-empty string or None (None by default)
        - password: a non-empty string or None (None by default)
        - access_token: a non-empty string or None (None by default)

        # Optional parameters

        - verify: a boolean or string

        `verify` can be set to False if disabling certificate checks for
        GitLab communication is required.  Tons of warnings will occur
        if this is set to False.
        """
        ensure_nonemptystring('url')
        ensure_noneorinstance('username', str)
        ensure_noneorinstance('password', str)
        ensure_noneorinstance('access_token', str)
        if access_token and (username or password):
            raise ValueError(
                'You can only specify either "access_token" or both "username" and "password".'
            )
        ensure_instance('verify', (bool, str))

        self.url = url
        if access_token:
            self.auth = BearerAuth(access_token)
        else:
            self.auth = (username, password)
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

    @api_call
    def list_repositories(self) -> List[Dict[str, Any]]:
        """Return a list of repositories.

        # Returned value

        A list of _repositories_.  Each _repository_ is a dictionary
        containing the following keys:

        - name: a string
        - format: a string
        - type: a string
        - url: a string
        - attributes: a dictionary
        """
        result = self._get('v1/repositories')
        return result  # type: ignore

    @api_call
    def list_repositorysettings(self) -> List[Dict[str, Any]]:
        """Return a list of repository settings.

        # Returned value

        A list of _repository settings_.  Each _repository setting_ is a
        dictionary containing the following keys:

        - name: a string
        - format: a string
        - type: a string
        - url: a string
        - online: a boolean
        """
        result = self._get('v1/repositorySettings')
        return result  # type: ignore

    @api_call
    def get_repository(self, repository_name: str) -> Dict[str, Any]:
        """Return a repository.

        # Parameters

        - repository_name: a non-empty string

        # Returned value

        A _repository_ dictionary containing the following keys:

        - name: a string
        - format: a string
        - type: a string
        - url: a string
        - attributes: a dictionary
        """
        ensure_nonemptystring('repository_name')

        result = self._get(f'v1/repositories/{repository_name}')
        return result  # type: ignore

    ####################################################################
    # Assets
    #
    # list_repository_assets

    @api_call
    def list_repository_assets(
        self, repository_name: str
    ) -> List[Dict[str, Any]]:
        """Return a list of assets in a repository.

        # Parameters

        - repository_name: a non-empty string

        # Returned value

        A list of _assets_.  Each _asset_ is a dictionary containing the
        following keys:

        - downloadUrl: a string
        - path: a string
        - id: a string
        - repository: a string
        - format: a string (`pypi`, ...)
        - checksum: a dictionary of checksums
        - contentType: a string
        - lastModified: a string ('2025-05-05T09:48:40.935+00:00')
        - lastDownloaded: a string ('2025-05-05T09:56:21.840+00:00')
        - uploader: a string
        - uploaderIp: a string
        - fileSize: an integer
        - blobCreated: a string ('2025-05-05T09:48:40.935+00:00')

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

        # Parameters

        - repository_name: a non-empty string

        # Returned value

        A list of _components_.  Each _component_ is a dictionary
        containing the following keys:

        - id: a string
        - repository: a string
        - format: a string (`pypi`, ...)
        - group: a string or None
        - name: a string
        - version: a string
        - assets: a list of dictionaries
        - tags: a list of dictionaries
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

        A list of _tags_.  Each _tag_ is a dictionary containing the
        following keys:

        - name: a string
        - attributes: a dictionary
        - firstCreated: a string ('2025-03-01T00:00:00Z')
        - lastUpdated: a string ('2025-03-01T00:00:00Z')
        """
        return self._collect_data('v1/tags')

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

        - requestCount: an integer
        - componentCount: an integer
        - metricDate: a string ('2025-03-01T00:00:00Z')
        - percentageChangeRequest
        - percentageChangeComponent
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
