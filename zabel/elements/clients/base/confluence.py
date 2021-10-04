# Copyright (c) 2019 Martin Lafaix (martin.lafaix@external.engie.com)
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

"""Confluence.

A class wrapping Confluence APIs.

There can be as many Confluence instances as needed.

This class depends on the public **requests** library.  It also depends
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
)


########################################################################
########################################################################

# Helpers


def _get_atl_token(html: str) -> str:
    atl_token = html[html.find('"atl_token"') :]
    atl_token = atl_token[atl_token.find('value="') + 7 :]
    return atl_token[: atl_token.find('"')]


# Confluence Jenkins low-level api

CONTENT_TYPES = ['page', 'blogpost', 'comment', 'attachment']
CONTENT_STATUSES = ['current', 'trashed', 'historical', 'draft']


class BearerAuth(requests.auth.AuthBase):
    """A Bearer handler class for requests."""

    def __init__(self, pat: str):
        self.pat = pat

    def __eq__(self, other):
        return self.pat == getattr(other, 'pat', None)

    def __ne__(self, other):
        return not self == other

    def __call__(self, r):
        r.headers['Authorization'] = f'Bearer {self.pat}'
        return r


class Confluence:
    """Confluence Low-Level Wrapper.

    # Reference URL

    <https://docs.atlassian.com/ConfluenceServer/rest/latest>
    <https://developer.atlassian.com/confdev/confluence-server-rest-api>
    <https://docs.atlassian.com/atlassian-confluence/REST/latest-server/>
    <https://developer.atlassian.com/server/confluence/remote-confluence
        -methods>

    A non-admin interface (no API for user&group admin features) to
    Confluence.

    Groups and users are defined on Jira or Crowd.  Changes can take up
    to one hour to propagate.

    # Implemented features

    - search
    - groups&users
    - pages
    - spaces

    What is accessible through the API depends on account rights.

    Whenever applicable, the provided features handle pagination (i.e.,
    they return all relevant elements, not only the first n).

    # Sample use

    ```python
    >>> from zabel.elements.clients import Confluence
    >>>
    >>> url = 'https://confluence.example.com'
    >>> confluence = Confluence(url, basic_auth=(user, token))
    >>> confluence.get_users()
    ```
    """

    def __init__(
        self,
        url: str,
        basic_auth: Optional[Tuple[str, str]] = None,
        oauth: Optional[Dict[str, str]] = None,
        bearer_auth: Optional[str] = None,
        verify: bool = True,
    ) -> None:
        """Create a Confluence instance object.

        You can only specify either `basic_auth`, `bearer_auth`, or
        `oauth`.

        The `oauth` dictionary is expected to have the following
        entries:

        - access_token: a string
        - access_token_secret: a string
        - consumer_key: a string
        - key_cert: a string

        Please note that the `bearer_auth` support does not give access
        to JSON-RPC methods.

        # Required parameters

        - url: a non-empty string
        - basic_auth: a string tuple (user, token)
        - bearer_auth: a string
        - oauth: a dictionary

        # Optional parameters

        - verify: a boolean (True by default)

        `verify` can be set to False if disabling certificate checks for
        Confluence communication is required.  Tons of warnings will
        occur if this is set to False.
        """
        ensure_nonemptystring('url')
        ensure_onlyone('basic_auth', 'oauth', 'bearer_auth')
        ensure_noneorinstance('basic_auth', tuple)
        ensure_noneorinstance('oauth', dict)
        ensure_noneorinstance('bearer_auth', str)
        ensure_instance('verify', bool)

        self.url = url
        self.basic_auth = basic_auth
        self.oauth = oauth
        self.bearer_auth = bearer_auth
        self.verify = verify

        if basic_auth is not None:
            self.auth = basic_auth
        if oauth is not None:
            from requests_oauthlib import OAuth1
            from oauthlib.oauth1 import SIGNATURE_RSA

            self.auth = OAuth1(
                oauth['consumer_key'],
                'dont_care',
                oauth['access_token'],
                oauth['access_token_secret'],
                signature_method=SIGNATURE_RSA,
                rsa_key=oauth['key_cert'],
                signature_type='auth_header',
            )
        if bearer_auth is not None:
            self.auth = BearerAuth(bearer_auth)
        self.session = prepare_session(self.auth, verify=verify)

    def __str__(self) -> str:
        return '{self.__class__.__name__}: {self.url}'

    def __repr__(self) -> str:
        if self.basic_auth:
            rep = self.basic_auth[0]
        elif self.bearer_auth:
            rep = f'***{self.bearer_auth[-6:]}'
        else:
            rep = self.oauth['consumer_key']  # type: ignore
        return f'<{self.__class__.__name__}: {self.url!r}, {rep!r}>'

    ####################################################################
    # Confluence search
    #
    # search

    @api_call
    def search(
        self,
        cql: str,
        cql_context: Optional[str] = None,
        start: Optional[int] = None,
        limit: int = 25,
        expand: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return the result of a query.

        # Required parameters

        - cql: a string

        # Optional parameters

        - cql_context: a string or None (None by default)
        - start: an integer or None (None by default)
        - limit: an integer (`25` by default)
        - expand: a string or None (None by default)

        # Returned value

        A possibly empty list of items.

        Items are dictionaries with the following entries (assuming the
        default `expand` values):

        - title: a string
        - type: a string
        - id: a string or an integer
        - status: a string
        - restrictions: a dictionary

        # Raised exceptions

        If the query is invalid, an _ApiError_ is raised.
        """
        ensure_instance('cql', str)
        ensure_noneorinstance('cql_context', str)
        ensure_noneorinstance('start', int)
        ensure_noneorinstance('limit', int)
        ensure_noneorinstance('expand', str)

        params = {'cql': cql, 'limit': str(limit)}
        add_if_specified(params, 'start', start)
        add_if_specified(params, 'cqlContext', cql_context)
        add_if_specified(params, 'expand', expand)

        return self._collect_data('content/search', params=params)

    ####################################################################
    # Confluence groups&users
    #
    # list_groups
    # create_group*
    # delete_group*
    # add_group_user*
    # remove_group_user*
    # list_group_members
    # get_user
    # create_user*
    # delete_user*
    # update_user*
    # update_user2*
    # list_user_groups
    # get_user_current
    # deactivate_user
    #
    # '*' denotes an API based on json-rpc, deprecated but not (yet?)
    # available as a REST API.  It is not part of the method name.

    @api_call
    def list_groups(self) -> List[Dict[str, Any]]:
        """Return a list of confluence groups.

        # Returned value

        A list of _groups_.  Each group is a dictionary with the
        following entries:

        - name: a string
        - type: a string ('group')
        - _links: a transient dictionary

        `_links` is a dictionary with the following entries:

        - self: a string

        Handles pagination (i.e., it returns all groups, not only the
        first n groups).
        """
        return self._collect_data('group')

    @api_call
    def create_group(self, group_name: str) -> bool:
        """Create a new group.

        !!! warning
            This uses the json-rpc interface that is deprecated (but
            there is no substitute as of this writing).

        `group_name` must be in lower case.

        # Required parameters

        - group_name: a non-empty string

        # Returned value

        A boolean.  True if successful, False otherwise.
        """
        ensure_nonemptystring('group_name')

        return (
            self.session()
            .post(
                join_url(
                    self.url, '/rpc/json-rpc/confluenceservice-v2/addGroup'
                ),
                json=[group_name],
            )
            .text
            == 'true'
        )

    @api_call
    def delete_group(self, group_name: str) -> bool:
        """Delete group.

        !!! warning
            This uses the json-rpc interface that is deprecated (but
            there is no substitute as of this writing).

        # Required parameters

        - group_name: a non-empty string

        # Returned value

        A boolean.  True if successful, False otherwise.
        """
        ensure_nonemptystring('group_name')

        return (
            self.session()
            .post(
                join_url(
                    self.url, '/rpc/json-rpc/confluenceservice-v2/removeGroup'
                ),
                json=[group_name, None],
            )
            .text
            == 'true'
        )

    @api_call
    def add_group_user(self, group_name: str, user_name: str) -> bool:
        """Add user to group.

        !!! warning
            This uses the json-rpc interface that is deprecated (but
            there is no substitute as of this writing).

        # Required parameters

        - group_name: a non-empty string
        - user_name: a non-empty string

        # Returned value

        A boolean.  True if successful, False if the operation failed.
        """
        ensure_nonemptystring('group_name')
        ensure_nonemptystring('user_name')

        return (
            self.session()
            .post(
                join_url(
                    self.url,
                    '/rpc/json-rpc/confluenceservice-v2/addUserToGroup',
                ),
                json=[user_name, group_name],
            )
            .text
            == 'true'
        )

    @api_call
    def remove_group_user(self, group_name: str, user_name: str) -> bool:
        """Add user to group.

        !!! warning
            This uses the json-rpc interface that is deprecated (but
            there is no substitute as of this writing).

        # Required parameters

        - group_name: a non-empty string
        - user_name: a non-empty string

        # Returned value

        A boolean.  True if successful, False if the operation failed.
        """
        ensure_nonemptystring('group_name')
        ensure_nonemptystring('user_name')

        return (
            self.session()
            .post(
                join_url(
                    self.url,
                    '/rpc/json-rpc/confluenceservice-v2/removeUserFromGroup',
                ),
                json=[user_name, group_name],
            )
            .text
            == 'true'
        )

    @api_call
    def list_group_members(self, group_name: str) -> List[Dict[str, Any]]:
        """Return a list of users in the group.

        # Required parameters

        - group_name: a string

        # Returned value

        A list of _users_.  Each user is a dictionary with the following
        entries:

        - username: a string
        - displayName: a string
        - userKey: a string
        - profilePicture: a dictionary
        - type: a string (`'known'`)

        Handles pagination (i.e., it returns all group members, not only
        the first n users).
        """
        ensure_nonemptystring('group_name')

        return self._collect_data(f'group/{group_name}/member')

    @api_call
    def get_user(
        self,
        user_name: Optional[str] = None,
        key: Optional[str] = None,
        expand: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return confluence user details.

        # Required parameters

        - `user_name` or `key`: a non-empty string

        You can only specify one of them.

        # Optional parameters

        - expand: a string or None (None by default)

        # Returned value

        A dictionary with the following entries (assuming the default
        for 'expand'):

            type: a string
            username: a string
            userKey: a string
            profilePicture: a dictionary
            displayName: a string

        It may also contains 'transient' entries (i.e., entries starting
        with '_').
        """
        ensure_onlyone('user_name', 'key')
        ensure_noneornonemptystring('user_name')
        ensure_noneornonemptystring('key')
        ensure_noneorinstance('expand', str)

        if user_name is not None:
            params = {'username': user_name}
        else:
            params = {'key': key}  # type: ignore
        add_if_specified(params, 'expand', expand)

        result = self._get('user', params=params)
        return result  # type: ignore

    @api_call
    def create_user(
        self,
        name: str,
        password: Optional[str],
        email_address: str,
        display_name: str,
    ) -> bool:
        """Create a new user.

        !!! warning
            This uses the json-rpc interface that is deprecated (but
            there is no substitute as of this writing).

        `name` must be in lower case.

        # Required parameters

        - name: a non-empty string
        - password: a non-empty string or None
        - email_address: a non-empty string
        - display_name: a string

        # Returned value

        True if the creation was successful, False otherwise.
        """
        ensure_nonemptystring('name')
        ensure_noneornonemptystring('password')
        ensure_nonemptystring('email_address')
        ensure_instance('display_name', str)

        user = {'email': email_address, "fullname": display_name, "name": name}

        return (
            self.session()
            .post(
                join_url(
                    self.url, '/rpc/json-rpc/confluenceservice-v2/addUser'
                ),
                json=[user, password],
            )
            .text
            == ''
        )

    @api_call
    def delete_user(self, user_name: str) -> bool:
        """Delete user.

        !!! warning
            This uses the json-rpc interface that is deprecated (but
            there is no substitute as of this writing).

        # Required parameters

        - user_name: a non-empty string

        # Returned value

        True if the creation was successful, False otherwise.
        """
        ensure_nonemptystring('user_name')

        return (
            self.session()
            .post(
                join_url(
                    self.url, '/rpc/json-rpc/confluenceservice-v2/removeUser'
                ),
                json=[user_name],
            )
            .text
            == 'true'
        )

    @api_call
    def update_user(
        self, user_name: str, user: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update user.

        !!! warning
            This uses the json-rpc interface that is deprecated (but
            there is no substitute as of this writing).

        `user` is a dictionary with possible replacement values for
        those two entries: `fullname` and `email`.  Other entries are
        ignored.

        # Required parameters

        - user_name: a non-empty string
        - user: a dictionary

        # Returned value

        True if the update was successful, False otherwise.
        """
        ensure_nonemptystring('user_name')
        ensure_instance('user', dict)

        request = {'name': user_name}
        if 'fullname' in user:
            request['fullname'] = user['fullname']
        if 'email' in user:
            request['email'] = user['email']

        return (
            self.session()
            .post(
                join_url(
                    self.url, '/rpc/json-rpc/confluenceservice-v2/editUser'
                ),
                json=[request],
            )
            .text
            == 'true'
        )

    @api_call
    def update_user2(self, user_name: str, new: str) -> bool:
        """Update username.

        # Required parameters

        - user_name: a non-empty string
        - new: a non-empty string

        # Returned value

        True if the update was successful, False otherwise.
        """
        ensure_nonemptystring('user_name')
        ensure_nonemptystring('new')

        user = self.get_user(user_name)
        form = self.session().get(
            join_url(self.url, '/admin/users/edituser.action'),
            params={'username': user_name},
        )
        atl_token = form.text.split('atl_token=')[1].split('&')[0]
        user_key = form.text.split(';userKey=')[1].split('"')[0]
        email = (
            form.text.split('id="email"')[1].split('value="')[1].split('"')[0]
        )

        result = self.session().post(
            self.url + '/admin/users/doedituser.action',
            params={'atl_token': atl_token, 'userKey': user_key},
            data={
                'username': new,
                'email': email,
                'fullName': user['displayName'],
                'confirm': 'Submit',
            },
            cookies=form.cookies,
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-Atlassian-Token': 'no-check',
            },
        )
        return result.status_code == 200

    @api_call
    def deactivate_user(self, user_name) -> bool:
        """Deactivate confluence user.

        !!! warning
            This uses the json-rpc interface that is deprecated (but
            there is no substitute as of this writing).

        # Required parameters

        - `user_name`: a non-empty string

        # Returned value

        True if the deactivation was successful, False otherwise.
        """
        ensure_nonemptystring('user_name')

        return (
            self.session()
            .post(
                join_url(
                    self.url,
                    '/rpc/json-rpc/confluenceservice-v2/deactivateUser',
                ),
                json=[user_name],
            )
            .text
            == 'true'
        )

    @api_call
    def list_user_groups(
        self,
        user_name: Optional[str] = None,
        key: Optional[str] = None,
        expand: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return a list of groups user is a member of.

        # Required parameters

        - `user_name` or `key`: a non-empty string

        You can only specify one of them.

        # Optional parameters

        - expand: a string or None (None by default)

        # Returned value

        A list of _groups_.  Groups are dictionaries with the following
        entries (assuming the default for `expand`):

        - type: a string (`'group'`)
        - name: a string

        Handles pagination (i.e., it returns all groups, not only the
        first _n_ groups the user is a member of).
        """
        ensure_onlyone('user_name', 'key')
        ensure_noneornonemptystring('user_name')
        ensure_noneornonemptystring('key')
        ensure_noneorinstance('expand', str)

        if user_name is not None:
            params = {'username': user_name}
        else:
            params = {'key': key}  # type: ignore
        add_if_specified(params, 'expand', expand)

        return self._collect_data('user/memberof', params=params)

    @api_call
    def get_user_current(self, expand: Optional[str] = None) -> Dict[str, Any]:
        """Return confluence current user details.

        # Optional parameters

        - expand: a string or None (None by default)

        # Returned value

        A dictionary with the following entries (assuming the default
        for `expand`):

        - type: a string
        - username: a string
        - userKey: a string
        - profilePicture: a dictionary
        - displayName: a string

        It may also contains 'transient' entries (i.e., entries starting
        with '_').
        """
        ensure_noneorinstance('expand', str)

        params: Dict[str, str] = {}
        add_if_specified(params, 'expand', expand)

        result = self._get('user/current', params=params)
        return result  # type: ignore

    ####################################################################
    # Confluence spaces
    #
    # list_spaces
    # get_space
    # get_space_content
    # list_space_pages
    # list_space_blogposts
    # list_space_permissions*
    # list_space_permissionsets*
    # create_space
    # add_space_label*
    # remove_space_permission*
    # add_space_permissions*
    #
    # '*' denotes an API based on json-rpc, deprecated but not (yet?)
    # available as a REST API.  It is not part of the method name.

    @api_call
    def list_spaces(self) -> List[Dict[str, Any]]:
        """Return a list of spaces.

        # Returned value

        A list of _spaces_.  Each space is a dictionary with the
        following entries:

        - key: a string
        - type: a string
        - name: a string
        - id: an integer
        - _links: a dictionary
        - _expandable: a dictionary

        Handles pagination (i.e., it returns all spaces, not only the
        first _n_ spaces).
        """
        return self._collect_data('space')

    @api_call
    def get_space(
        self, space_key: str, expand: Optional[str] = None
    ) -> Dict[str, Any]:
        """Return space details.

        # Required parameters

        - space_key: a non-empty string

        # Optional parameters

        - expand: a string or None (None by default)

        # Returned value

        A dictionary with the following entries:

        - id: an integer
        - key: a string
        - name: a string
        - type: a string
        """
        ensure_nonemptystring('space_key')
        ensure_noneorinstance('expand', str)

        if expand is not None:
            params: Optional[Dict[str, str]] = {'expand': expand}
        else:
            params = None

        result = self._get(f'space/{space_key}', params=params)
        return result  # type: ignore

    @api_call
    def get_space_content(
        self, space_key: str, expand: Optional[str] = None, depth: str = 'all'
    ) -> Dict[str, Any]:
        """Return space content.

        # Required parameters

        - space_key: a non-empty string

        # Optional parameters

        - expand: a string or None (None by default)
        - depth: a string (`'all'` by default)

        # Returned value

        A dictionary with the following entries:

        - page: a dictionary
        - blogpost: a dictionary
        - _links: a dictionary

        `page` and `blogpost` are dictionaries with the following
        entries:

        - results: a list of dictionaries
        - size: an integer
        - limit: an integer
        - start: an integer
        - _links: a dictionary

        `_links` is a dictionary with the following entries:

        - context: a string
        - base: a string (an URL)
        """
        ensure_nonemptystring('space_key')
        ensure_noneorinstance('expand', str)
        ensure_in('depth', ['all', 'root'])

        params = {'depth': depth}
        add_if_specified(params, 'expand', expand)

        return self._get(f'space/{space_key}/content')  # type: ignore

    @api_call
    def list_space_pages(
        self, space_key: str, expand: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Return a list of all space pages.

        # Required parameters

        - space_key: a non-empty string

        # Optional parameters

        - expand: a string or None (None by default)

        # Returned value

        A list of _pages_.  Each page is a dictionary. Refer to
        #get_page() for details on its content.
        """
        ensure_nonemptystring('space_key')
        ensure_noneornonemptystring('expand')

        return self._collect_data(
            f'space/{space_key}/content/page',
            {'expand': expand} if expand else None,
        )

    @api_call
    def list_space_blogposts(
        self, space_key: str, expand: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Return a list of all space blog posts.

        # Required parameters

        - space_key: a non-empty string

        # Optional parameters

        - expand: a string or None (None by default)

        # Returned value

        A list of _blog posts_.  Each blog post is a dictionary.
        """
        ensure_nonemptystring('space_key')
        ensure_noneornonemptystring('expand')

        return self._collect_data(
            f'space/{space_key}/content/blogpost',
            {'expand': expand} if expand else None,
        )

    @api_call
    def list_space_permissions(self) -> List[str]:
        """Return the list of all possible permissions for spaces.

        !!! warning
            This uses the json-rpc interface that is deprecated (but
            there is no substitute as of this writing).

        # Returned value

        A list of strings.
        """
        return list(
            set(
                self.session()
                .post(
                    join_url(
                        self.url,
                        '/rpc/json-rpc/confluenceservice-v2/getSpaceLevelPermissions',
                    ),
                    json=[],
                )
                .json()
            )
        )

    @api_call
    def list_space_permissionsets(
        self, space_key: str
    ) -> List[Dict[str, Any]]:
        """Return a list of all permissionsets for space.

        !!! warning
            This uses the json-rpc interface that is deprecated (but
            there is no substitute as of this writing).

        # Required parameters

        - space_key: a non-empty string

        # Returned value

        A list of _permissionsets_.  Each permissionset is a dictionary
        with the following entries:

        - type: a string
        - spacePermissions: a list of dictionaries

        `type` is a space permission (as returned by
        #list_space_permissions()).

        Dictionaries in `spacePermissions` have the following entries:

        - type: a string
        - groupName: a string
        - userName: a string
        """
        ensure_nonemptystring('space_key')

        result = self.session().post(
            join_url(
                self.url,
                '/rpc/json-rpc/confluenceservice-v2/getSpacePermissionSets',
            ),
            json=[space_key],
        )
        return result  # type: ignore

    @api_call
    def create_space(
        self,
        space_key: str,
        name: str,
        description: Optional[str] = None,
        public: bool = True,
    ) -> Dict[str, Any]:
        """Create a new public space.

        # Required parameters

        - space_key: a non-empty string
        - name: a non-empty string

        # Optional parameters

        - description: a non-empty string or None (None by default)
        - public: a boolean (True by default)

        # Returned value

        A dictionary with the following entries:

        - id: an integer
        - key: a string
        - name: a string
        - description: a dictionary
        - metadata: a dictionary
        - _links: a dictionary

        Some entries may be missing, and there may be additional ones.
        """
        ensure_nonemptystring('space_key')
        ensure_nonemptystring('name')
        ensure_noneornonemptystring('description')
        ensure_instance('public', bool)

        definition: Dict[str, Any] = {'key': space_key, 'name': name}

        if description:
            definition['description'] = {
                'plain': {'value': description, 'representation': 'plain'}
            }

        result = self._post(
            'space' if public else 'space/_private', definition
        )
        return result  # type: ignore

    @api_call
    def add_space_label(self, space_key: str, label: str) -> bool:
        """Add label to space.

        !!! warning
            This uses the json-rpc interface that is deprecated (but
            there is no substitute as of this writing).

        # Required parameters

        - space_key: a non-empty string
        - label: a string

        # Returned value

        True if successful.
        """
        ensure_nonemptystring('space_key')
        ensure_nonemptystring('label')

        result = self.session().post(
            join_url(
                self.url,
                '/rpc/json-rpc/confluenceservice-v2/addLabelByNameToSpace',
            ),
            json=[f'team:{label}', space_key],
        )
        return result  # type: ignore

    @api_call
    def remove_space_permission(
        self, space_key: str, entity: str, permission: str
    ) -> bool:
        """Remove permission from space.

        !!! warning
            This uses the json-rpc interface that is deprecated (but
            there is no substitute as of this writing).

        The permission is removed from the existing entity
        permissions.  (It is not an error to remove a given permission
        from an entity multiple times.)

        An entity is either a group or a user.  It must be known and
        visible to Confluence.

        # Required parameters

            space_key: a non-empty string
            entity: a non-empty string
            permission: a non-empty string

        # Returned value

        True if successful.
        """
        ensure_nonemptystring('space_key')
        ensure_nonemptystring('entity')
        ensure_nonemptystring('permission')

        result = self.session().post(
            join_url(
                self.url,
                '/rpc/json-rpc/confluenceservice-v2/removePermissionFromSpace',
            ),
            json=[permission, entity, space_key],
        )
        return result  # type: ignore

    @api_call
    def add_space_permissions(
        self, space_key: str, entity: str, permissions: List[str]
    ) -> bool:
        """Add permissions to space.

        !!! warning
            This uses the json-rpc interface that is deprecated (but
            there is no substitute as of this writing).

        An `entity` is either a group or a user.  It must be known and
        visible to Confluence.

        The permissions are added to the existing entity permissions.
        (It is not an error to add a given permission to an entity
        multiple times.)

        # Required parameters

        - space_key: a non-empty string
        - entity: a non-empty string
        - permissions: a list of strings

        # Returned value

        True if successful.
        """
        ensure_nonemptystring('space_key')
        ensure_nonemptystring('entity')
        ensure_instance('permissions', list)

        result = self.session().post(
            join_url(
                self.url,
                '/rpc/json-rpc/confluenceservice-v2/addPermissionsToSpace',
            ),
            json=[permissions, entity, space_key],
        )
        return result  # type: ignore

    ####################################################################
    # Confluence pages
    #
    # search_pages
    # get_page
    # create_page
    # update_page
    # delete_page
    # delete_page_version
    # list_page_labels
    # add_page_labels
    # list_page_children
    # list_page_attachments
    # add_page_attachment
    # list_page_restrictions
    # set_page_restrictions

    @api_call
    def search_pages(
        self,
        space_key: str,
        status: str = 'current',
        typ: str = 'page',
        title: Optional[str] = None,
        expand: Optional[str] = None,
        start: Optional[int] = None,
        posting_day: Optional[str] = None,
        limit: int = 25,
    ) -> List[Dict[str, Any]]:
        """Return a list of contents.

        # Required parameters

        - space_key: a string

        # Optional parameters

        - status: a string (`'current'` by default)
        - typ: a string (`'page'` by default)
        - title: a string or None (None by default)
        - expand: a string or None (None by default)
        - start: an integer or None (None by default)
        - posting_day: a string or None (None by default).  **Required
          if `typ` = `'blogpost'`.**
        - limit: an integer (`25` by default)

        # Returned value

        A possibly empty list of items.  Items are dictionaries.

        Assuming the default `expand` values, an item contains the
        following entries:

        - title: a string
        - type: a string
        - id: an integer or a string
        - status: a string
        - extensions: a dictionary
        """
        ensure_instance('space_key', str)
        ensure_in('status', ['current', 'any', 'trashed'])
        ensure_in('typ', ['page', 'blogpost'])
        if typ == 'page':
            ensure_nonemptystring('title')
        if typ == 'blogpost':
            ensure_nonemptystring('posting_day')

        params = {'spaceKey': space_key, 'limit': str(limit), 'status': status}
        add_if_specified(params, 'type', typ)
        add_if_specified(params, 'title', title)
        add_if_specified(params, 'expand', expand)
        add_if_specified(params, 'postingDay', posting_day)
        add_if_specified(params, 'start', start)

        return self._collect_data('content', params=params)

    @api_call
    def list_page_children(
        self,
        page_id: Union[str, int],
        typ: str,
        expand: Optional[str] = None,
        start: Optional[int] = None,
        limit: int = 25,
        parent_version: int = 0,
    ) -> List[Dict[str, Any]]:
        """Return a list of contents.

        Valid values for `typ` are those in `CONTENT_TYPES`.

        # Required parameters

        - page_id: an integer or a string
        - typ: a string

        # Optional parameters

        - expand: a string or None (None by default)
        - start: an integer or None (None by default)
        - limit: an integer (`25` by default)
        - parent_version: an integer (`0` by default)

        # Returned value

        A possibly empty list of items.  Items are dictionaries.

        Assuming the default `expand` values, an item contains the
        following entries:

        - title: a string
        - type: a string
        - id: an integer or a string
        - status: a string
        - extensions: a dictionary
        """
        ensure_instance('page_id', (str, int))
        ensure_in('typ', CONTENT_TYPES)
        ensure_noneornonemptystring('expand')
        ensure_noneorinstance('start', int)
        ensure_instance('limit', int)
        ensure_instance('parent_version', int)

        api = f'content/{page_id}/child'
        if typ is not None:
            api += f'/{typ}'
        params = {'limit': str(limit), 'parentVersion': str(parent_version)}
        add_if_specified(params, 'expand', expand)
        add_if_specified(params, 'start', start)

        return self._collect_data(api, params=params)

    @api_call
    def get_page(
        self,
        page_id: Union[str, int],
        expand: str = 'body.storage,version',
        version: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Return the definition of a page.

        # Required parameters

        - page_id: an integer or a string

        # Optional parameters

        - expand: a string (`'body.storage,version'` by default)
        - version: an integer or None (None by default)

        # Returned value

        A dictionary with the following entries (assuming the default
        for `expand`):

        - type: a string
        - title: a string
        - id: a string
        - version: a dictionary
        - body: a dictionary

        `version` is a dictionary with the following entries:

        - by: a dictionary
        - number: an integer
        - minorEdit: a boolean
        - when: a string (a timestamp)
        - message: a string
        - hidden: a boolean

        `by` is a dictionary with the following entries:

        - type: a string
        - username: a string
        - userkey: a string
        - displayName: a string

        `body` is a dictionary with the following entries:

            - storage: a dictionary

        `storage` is a dictionary with the following entries:

        - representation: a string
        - value: a string

        `value` is the HTML text of the page.
        """
        ensure_instance('page_id', (str, int))
        ensure_instance('expand', str)

        params = {'expand': expand}
        add_if_specified(params, 'version', version)
        result = self._get(f'content/{page_id}', params=params)
        return result  # type: ignore

    @api_call
    def create_page(
        self,
        space_key: str,
        title: str,
        body: Optional[Dict[str, Any]] = None,
        ancestors: Optional[List[Dict[str, Any]]] = None,
        typ: str = 'page',
        status: str = 'current',
    ) -> Dict[str, Any]:
        """Create a new page.

        The `body` dictionary, if provided, is a standard Confluence
        body specification.  Please refer to #get_page() for more.

        The `ancestors` list of dictionaries, if provided, is a standard
        Confluence ancestors specification, with just the id, such as:

        ```python
        [
            {
                'id': '1234'
            }
        ]
        ```

        Valid values for `typ` are those in `CONTENT_TYPES`.

        Valid values for `status` are those in `CONTENT_STATUSES`.

        # Required parameters

        - space_key: a non-empty string
        - title: a non-empty string

        # Optional parameters

        - body: a dictionary or None (None by default)
        - ancestors: a list of dictionaries or None (None by default)
        - typ: a string (`'page'` by default)
        - status: a string (`'current'` by default)

        # Returned value

        A dictionary with the following entries:

        - ancestors: a list of dictionaries
        - body: a dictionary
        - container: a dictionary
        - extensions: a dictionary
        - history: a dictionary
        - id: an integer or a string
        - space: a dictionary
        - status: a string
        - title: a string
        - type: a string
        - version: a dictionary

        It may also contain standard _meta_ entries, such as `_links`
        or `_expandable`.

        Refer to #get_page() for more details on common entries in this
        dictionary.
        """
        ensure_nonemptystring('space_key')
        ensure_nonemptystring('title')
        ensure_noneorinstance('body', dict)
        ensure_noneorinstance('ancestors', list)
        ensure_in('typ', CONTENT_TYPES)
        ensure_in('status', CONTENT_STATUSES)

        definition = {
            'space': {'key': space_key},
            'title': title,
            'type': typ,
            'status': status,
        }
        add_if_specified(definition, 'body', body)
        add_if_specified(definition, 'ancestors', ancestors)

        result = self._post('content', json=definition)
        return result  # type: ignore

    @api_call
    def delete_page(self, page_id: Union[str, int]) -> bool:
        """Delete a page.

        # Required parameters

        - page_id: an integer or a string

        # Returned value

        A boolean.  True if deletion was successful.
        """
        ensure_instance('page_id', (str, int))

        result = self.session().delete(
            join_url(self.url, f'rest/api/content/{page_id}')
        )
        return result.status_code // 100 == 2

    @api_call
    def delete_page_version(
        self, page_id: Union[str, int], version: int
    ) -> None:
        """Delete a page version.

        # Required parameters

        - page_id: an integer or a string
        - version: an integer
        """
        ensure_instance('page_id', (str, int))
        ensure_instance('version', int)

        result = self.session().delete(
            join_url(
                self.url,
                f'rest/experimental/content/{page_id}/version/{version}',
            )
        )
        return result  # type: ignore

    @api_call
    def update_page(
        self, page_id: Union[str, int], page: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update an existing page.

        This method should not be used to create a page.  It is only
        intended to update an existing one.

        The typical usage is:

        ```python
        >>> page = confluence.get_page(n)
        >>> page['body']['storage']['value'] = '....'
        >>> page['version'] = {'number': page['version']['number']+1}
        >>> confluence.update_page(n, page)
        ```

        See #get_page() for a description of the `page` dictionary.

        # Required parameters

        - page_id: an integer or a string
        - page: a dictionary

        # Returned value

        A dictionary.  Refer to #create_page() for more information.
        """
        ensure_instance('page_id', (str, int))
        ensure_instance('page', dict)

        result = self._put(f'content/{page_id}', json=page)
        return result  # type: ignore

    @api_call
    def add_page_labels(
        self, page_id: Union[str, int], labels: List[Mapping[str, str]]
    ) -> List[Dict[str, Any]]:
        """Add labels to page.

        !!! warning
            It only returns the first 200 labels by default.  Use
            #list_page_labels() if you want the complete list of labels
            attached to a page.

        # Required parameters

        - page_id: an integer or a string
        - labels: a non-empty list of dictionaries

        Dictionaries in `labels` have the following entries:

        - name: a string
        - prefix: a string (`'global'`, ...)

        Labels in the list are added to the page.  Existing labels are
        not removed if they are not in the list.

        # Returned value

        A list of _labels_, one per label attached to the page.  Each
        label is a dictionary with the following entries:

        - id: an integer or a string
        - name: a string
        - prefix: a string
        """
        ensure_instance('page_id', (str, int))
        ensure_instance('labels', list)
        if not labels:
            raise ValueError('labels must not be empty.')

        response = self._post(f'content/{page_id}/label', json=labels).json()
        return response['results']  # type: ignore

    @api_call
    def list_page_labels(
        self, page_id: Union[str, int]
    ) -> List[Dict[str, Any]]:
        """Get labels attached to page.

        # Required parameters

        - page_id: an integer or a string

        # Returned value

        A list of _labels_.  Each label is a  dictionary with the
        following entries:

        - id: an integer or a string
        - name: a string
        - prefix: a string
        """
        ensure_instance('page_id', (str, int))

        return self._collect_data(f'content/{page_id}/label')

    @api_call
    def list_page_attachments(
        self, page_id: Union[str, int]
    ) -> List[Dict[str, Any]]:
        """Get attachments attached to page.

        # Required parameters

        - page_id: an integer or a string

        # Returned value

        A list of _labels_.  Each label is a  dictionary with the
        following entries:

        - id: an integer or a string
        - name: a string
        - prefix: a string
        """
        ensure_instance('page_id', (str, int))

        return self._collect_data(f'content/{page_id}/child/attachment')

    @api_call
    def add_page_attachment(
        self,
        page_id: Union[str, int],
        filename: str,
        comment: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Add attachment to page.

        # Required parameters

        - page_id: an integer or a string
        - filename: a string

        # Optional parameters

        - comment: a non-empty string or None (None by default)

        # Returned value

        A dictionary.  Refer to #create_page() for more information.
        """
        ensure_instance('page_id', (str, int))
        ensure_nonemptystring('filename')
        ensure_noneornonemptystring('comment')

        with open(filename, 'rb') as f:
            files = {'file': (filename, f.read())}
        if comment:
            data = {'comment': comment}
        else:
            data = None
        api_url = join_url(
            self.url, f'rest/api/content/{page_id}/child/attachment'
        )
        response = self.session().post(
            api_url,
            files=files,
            data=data,
            headers={'X-Atlassian-Token': 'nocheck'},
        )
        return response  # type: ignore

    @api_call
    def update_page_attachment_data(
        self,
        page_id: Union[str, int],
        attachment_id: Union[str, int],
        filename: str,
        comment: Optional[str] = None,
        minor_edit: bool = True,
    ) -> Dict[str, Any]:
        """Update attachment content.

        # Required parameters

        - page_id: an integer or a string
        - attachment_id: an integer or a string
        - filename: a string

        # Optional parameters

        - comment: a non-empty string or None (None by default)
        - minor_edit: a boolean (True by default)

        # Returned value

        A dictionary.  Refer to #create_page() for more information.
        """
        ensure_instance('page_id', (str, int))
        ensure_instance('attachment_id', (str, int))
        ensure_nonemptystring('filename')
        ensure_noneornonemptystring('comment')
        ensure_instance('minor_edit', bool)

        with open(filename, 'rb') as f:
            files = {'file': (filename, f.read())}
        data = {'minorEdit': minor_edit}
        if comment:
            data['comment'] = comment
        api_url = join_url(
            self.url,
            f'rest/api/content/{page_id}/child/attachment/{attachment_id}/data',
        )
        response = self.session().post(
            api_url,
            files=files,
            data=data,
            headers={'X-Atlassian-Token': 'nocheck'},
        )
        return response  # type: ignore

    @api_call
    def list_page_restrictions(
        self, page_id: Union[str, int]
    ) -> List[Dict[str, Any]]:
        """Returns the list of access restrictions on a given page.

        # Required parameters

        - `page_id` : integer or string

        # Returned value

        A list of _restrictions_ . Restrictions are structured as follow :

        - `type`: str, either "Edit" or "View"
        - `contentPermissions`: a dictionary structured as follow
            * `type`: str, either "Edit" or "View"
            * `userName`: str, or None if groupName is set,
            * `groupName`: str, or None if userName is set
        ```

        # See
        <https://developer.atlassian.com/server/confluence/remote-confluence-methods/#permissions>
        """
        ensure_instance('page_id', (str, int))

        response = self.session().post(
            join_url(
                self.url,
                '/rpc/json-rpc/confluenceservice-v2/getContentPermissionSets',
            ),
            json=[page_id],
        )

        return response  # type: ignore

    @api_call
    def set_page_restrictions(
        self,
        page_id: Union[str, int],
        permission_type: str,
        restrictions: List[Dict[str, Any]],
    ) -> bool:
        """
        Will set the restrictions on a page given its id. The permission_type is either 'View' or 'Edit'.

        # Required parameters

        - `page_id`: integer or string
        - `permission_type`: str, either "View" or "Edit"
        - `restrictions`: a list of dictionaries structured as follow :
           * `type`: string, either "Edit", "View" or None.
                     If set, must be consistent with `permission_type`.
                     If None, will inherit `permission_type`.
           * `userName`: str, or None if `groupName` is set
           * `groupName`: str, or None if `userName` is set

        # Example

        These rules means that this invocation :
        ```python
            self.set_page_restrictions('page_id', 'Edit', [{'userName': 'bob'}, {'groupName': 'ATeam'}])
        ```
        Is equivalent to the fully formed data as expected by the json-rpc API :
        ```python
            self.set_page_restrictions(
                'page_id',
                'Edit',
                [{'type': 'Edit', 'userName': 'bob', 'groupName': None},
                {'type': 'Edit', 'userName': None, 'groupName': 'ATeam'}]
            )
        ```

        # Behavior rules

        You may have noticed that permissions 'View' and 'Edit' are managed separately, but they need to be thought of together
        when designing restrictions schemes. The default behavior when no permissions are set are the following:
        - when no restrictions is set for type 'View' -> anyone can view the page.
        - when no restrictions is set for type 'Edit' -> anyone can edit the page.

        So if you want to absolutely restrict access to a particular user or group, be user to specify both 'View' and 'Edit'
        restrictions (setting restrictions on 'Edit' only won't necessarily imply that 'View' restrictions will be set as well).
        As a result you will often have to call this method twice in a row.

        # See
        <https://developer.atlassian.com/server/confluence/remote-confluence-methods/#permissions>

        :param page_id:
        :param permission_type:
        :param restrictions:
        :return:
        """
        ensure_instance('page_id', (str, int))
        ensure_in('permission_type', ('Edit', 'View'))
        ensure_instance('restrictions', list)

        sane_restrictions = self._sanitize_restrictions(
            permission_type=permission_type, restrictions=restrictions
        )

        return (
            self.session()
            .post(
                join_url(
                    self.url,
                    '/rpc/json-rpc/confluenceservice-v2/setContentPermissions',
                ),
                json=[page_id, permission_type, sane_restrictions],
            )
            .text
            == 'true'
        )

    ####################################################################
    # confluence helpers

    def _get(
        self,
        api: str,
        params: Optional[Mapping[str, Union[str, List[str], None]]] = None,
    ) -> requests.Response:
        """Return confluence GET api call results."""
        api_url = join_url(join_url(self.url, 'rest/api'), api)
        return self.session().get(api_url, params=params)

    def _collect_data(
        self,
        api: str,
        params: Optional[Mapping[str, Union[str, List[str], None]]] = None,
    ) -> List[Any]:
        """Return confluence GET api call results, collected."""
        api_url = join_url(join_url(self.url, 'rest/api'), api)
        collected: List[Any] = []
        more = True
        while more:
            response = self.session().get(api_url, params=params)
            if response.status_code // 100 != 2:
                raise ApiError(response.text)
            try:
                workload = response.json()
                collected += workload['results']
            except Exception as exception:
                raise ApiError(exception)
            more = 'next' in workload['_links']
            if more:
                api_url = join_url(
                    workload['_links']['base'], workload['_links']['next']
                )
        return collected

    def _put(
        self, api: str, json: Optional[Mapping[str, Any]] = None
    ) -> requests.Response:
        """Return confluence PUT api call results."""
        api_url = join_url(join_url(self.url, 'rest/api'), api)
        return self.session().put(api_url, json=json)

    def _post(
        self, api: str, json: Union[Mapping[str, Any], List[Mapping[str, Any]]]
    ) -> requests.Response:
        """Return confluence POST api call results."""
        api_url = join_url(join_url(self.url, 'rest/api'), api)
        return self.session().post(api_url, json=json)

    def _sanitize_restrictions(
        self, permission_type: str, restrictions: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Ensure that the _restrictions_ arguments for page restrictions are sanefor usage, see self#set_page_restrictions()
        """
        for restriction in restrictions:
            restriction.setdefault('type', permission_type)
            if restriction['type'] != permission_type:
                raise ValueError(
                    f"field 'type' is inconsistent with 'permission_type'. Got : 'permission_type'={permission_type}, restriction={restriction} "
                )

            has_user = restriction.setdefault('userName', None)
            has_group = restriction.setdefault('groupName', None)
            if has_group == has_user:
                raise ValueError(
                    f"Confluence page restriction must have exactly one of : 'userName', 'groupName'. Got : {restriction} "
                )

        return restrictions
