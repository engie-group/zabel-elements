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
PROJECT_EXPAND = 'description,lead,url,projectKeys,issueTypes'


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
        expand: str = PROJECT_EXPAND,
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
