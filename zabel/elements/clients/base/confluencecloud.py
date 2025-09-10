# Copyright (c) 2019 Martin Lafaix (martin.lafaix@external.engie.com)
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

"""Confluence Cloud .

A class wrapping Confluence Cloud APIs.

There can be as many Confluence Cloud instances as needed.

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
    join_url,
)


########################################################################

OPERATION_KEY_VALUES = [
    'administer',
    'archive',
    'copy',
    'create',
    'delete',
    'export',
    'move',
    'purge',
    'purge_version',
    'read',
    'restore',
    'restrict_content',
    'update',
    'use',
]
OPERATION_TARGET_VALUES = [
    'page',
    'blogpost',
    'comment',
    'attachment',
    'space',
]


class ConfluenceCloud:
    """Confluence Cloud Low-Level Wrapper.

    An interface to Confluence Cloud, including users and groups
    management.

    There can be as many Confluence Cloud instances as needed.

    This class depends on the public **requests** library.  It also
    depends on three **zabel-commons** modules,
    #::zabel.commons.exceptions, #::zabel.commons.sessions,
    and #::zabel.commons.utils.

    ## Reference URLs

    - <https://developer.atlassian.com/cloud/confluence/rest/v2/>
    - <https://developer.atlassian.com/cloud/confluence/rest/v1/>

    ## Implemented features

    - pages
    - search
    - spaces

    What is accessible through the API depends on account rights.

    Whenever applicable, the provided features handle pagination (i.e.,
    they return all relevant elements, not only the first n).

    ## Examples

    ```python
    from zabel.elements.clients import ConfluenceCloud

    url = 'https://your-instance.atlassian.net/wiki/'
    user = '...'
    token = '...'
    confluencecloud = ConfluenceCloud(url, basic_auth=(user, token))
    confluencecloud.list_users()
    ```
    """

    def __init__(self, url: str, basic_auth: Tuple[str, str]) -> None:
        """Create a Confluence Cloud instance object.

        # Required parameters

        - url: a non-empty string
        - basic_auth: a string tuple (user, token)

        # Usage

        `url` must be the URL of the Confluence Cloud instance.  For
        example:

            'https://{instance}.atlassian.net/wiki'

        `basic_auth` is a tuple containing the user name and the API
        token.  The API token can be generated in the Atlassian
        account settings, under "Security" and "API token".
        """
        ensure_nonemptystring('url')
        ensure_instance('basic_auth', tuple)

        self.url = url
        self.basic_auth = basic_auth
        self.session = prepare_session(self.basic_auth)

    def __str__(self) -> str:
        return '{self.__class__.__name__}: {self.url}'

    def __repr__(self) -> str:
        if self.basic_auth:
            rep = self.basic_auth[0]
        return f'<{self.__class__.__name__}: {self.url!r}, {rep!r}>'

    ####################################################################
    # Confluence spaces
    #
    # list_spaces
    # get_space
    # list_space_pages
    # list_space_blogposts
    # create_space

    @api_call
    def list_spaces(
        self,
        description_format: Optional[str] = None,
        favorited_by: Optional[str] = None,
        ids: Optional[List[int]] = None,
        include_icons: bool = False,
        keys: Optional[List[str]] = None,
        labels: Optional[List[str]] = None,
        limit: int = 100,
        not_favorited_by: Optional[str] = None,
        sort: Optional[str] = None,
        status: Optional[str] = None,
        space_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return a list of spaces.

        # Optional parameters

        - description_format: a string
        - favorited_by: a string
        - ids: a list of integers
        - include_icons: a boolean
        - keys: a list of strings
        - labels: a list of strings
        - limit: an integer (default: 100)
        - not_favorited_by: a string
        - sort: a string
        - status: a string
        - space_type: a string

        # Returned value

        A list of _spaces_. Each space is a dictionary with the
        following entries:

        - authorId: a string
        - createdAt: a string
        - currentActiveAlias: a string
        - homepageId: an integer
        - id: a string
        - key: a string
        - name: a string
        - spaceOwnerId: a string
        - status: a string
        - type: a string
        - _links: a dictionary

        Handles pagination (i.e., it returns all spaces, not only the
        first _n_ spaces).
        """
        ensure_noneorinstance('description_format', str)
        ensure_noneorinstance('favorited_by', str)
        ensure_noneorinstance('ids', list)
        ensure_instance('include_icons', bool)
        ensure_noneorinstance('keys', list)
        ensure_noneorinstance('labels', list)
        ensure_noneorinstance('limit', int)
        ensure_noneorinstance('not_favorited_by', str)
        ensure_noneorinstance('sort', str)
        ensure_noneorinstance('status', str)
        ensure_noneorinstance('space_type', str)

        params = {'limit': limit}
        add_if_specified(params, 'description-format', description_format)
        add_if_specified(params, 'favorited-by', favorited_by)
        add_if_specified(params, 'ids', ids)
        add_if_specified(params, 'include-icon', include_icons)
        add_if_specified(params, 'keys', keys)
        add_if_specified(params, 'labels', labels)
        add_if_specified(params, 'not-favorited-by', not_favorited_by)
        add_if_specified(params, 'sort', sort)
        add_if_specified(params, 'status', status)
        add_if_specified(params, 'type', space_type)

        return self._collect_data('spaces', params=params)

    @api_call
    def get_space(
        self,
        space_id: str,
        description_format: Optional[str] = None,
        include_icon: bool = False,
        include_labels: bool = False,
        include_operations: bool = False,
        include_permissions: bool = False,
        include_properties: bool = False,
        include_role_assignments: bool = False,
    ) -> Dict[str, Any]:
        """Return space details.

        # Required parameters

        - space_id: a string

        # Optional parameters

        - description_format: a string or None (None by default)
        - include_icon: a boolean (False by default)
        - include_labels: a boolean (False by default)
        - include_operations: a boolean (False by default)
        - include_permissions: a boolean (False by default)
        - include_properties: a boolean (False by default)
        - include_role_assignments: a boolean (False by default)

        # Returned value

        A dictionary with the following entries:

        - authorId: a string
        - createdAt: a string
        - description: a dictionary
        - homepageId: a string
        - icon: a dictionary
        - key: an integer
        - name: a string
        - status: a string
        - type: a string
        - _links: a dictionary
        """
        ensure_noneorinstance('description_format', str)
        ensure_instance('include_icon', bool)
        ensure_instance('include_labels', bool)
        ensure_instance('include_operations', bool)
        ensure_instance('include_permissions', bool)
        ensure_instance('include_properties', bool)
        ensure_instance('include_role_assignments', bool)

        params = {}
        add_if_specified(params, 'description-format', description_format)
        add_if_specified(params, 'include-icon', include_icon)
        add_if_specified(params, 'include-labels', include_labels)
        add_if_specified(params, 'include-operations', include_operations)
        add_if_specified(params, 'include-permissions', include_permissions)
        add_if_specified(params, 'include-properties', include_properties)
        add_if_specified(
            params, 'include-role-assignments', include_role_assignments
        )
        url = join_url(self.url, f'rest/api/space/{space_id}')
        response = self.session().get(url, params=params)
        return response.json()

    @api_call
    def list_space_pages(
        self,
        space_id: int,
        body_format: Optional[str] = None,
        depth: Optional[str] = None,
        limit: int = 200,
        sort: Optional[str] = None,
        status: Optional[List[str]] = None,
        title: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return a list of pages in a space.

        # Required parameters

        - space_id: an integer

        # Optional parameters

        - body_format: a string
        - depth: a string
        - limit: an integer (default 200)
        - sort: a string
        - status: a list of strings
        - title: a string

        # Returned value

        A list of dictionaries, each representing a page.  Please refer
        to #get_page() for more.
        """
        ensure_instance('space_id', int)
        ensure_noneorinstance('body_format', str)
        ensure_noneorinstance('depth', str)
        ensure_instance('limit', int)
        ensure_noneorinstance('sort', str)
        ensure_noneorinstance('status', list)
        ensure_noneorinstance('title', str)

        params = {'limit': limit}
        add_if_specified(params, 'body-format', body_format)
        add_if_specified(params, 'depth', depth)
        add_if_specified(params, 'sort', sort)
        add_if_specified(params, 'status', status)
        add_if_specified(params, 'title', title)

        return self._collect_data(f'spaces/{space_id}/pages', params=params)

    @api_call
    def list_space_blogposts(
        self,
        space_id: int,
        body_format: Optional[str] = None,
        depth: Optional[str] = None,
        limit: int = 200,
        sort: Optional[str] = None,
        status: Optional[List[str]] = None,
        title: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return a list of blog posts in a space.

        # Required parameters

        - space_id: an integer

        # Optional parameters

        - body_format: a string
        - depth: a string
        - limit: an integer (default `200`)
        - sort: a string
        - status: a list of strings
        - title: a string

        # Returned value

        A list of dictionaries, each representing a blog post.
        """
        ensure_instance('space_id', int)
        ensure_noneorinstance('body_format', str)
        ensure_noneorinstance('depth', str)
        ensure_instance('limit', int)
        ensure_noneorinstance('sort', str)
        ensure_noneorinstance('status', list)
        ensure_noneorinstance('title', str)

        params = {'limit': limit}
        add_if_specified(params, 'body-format', body_format)
        add_if_specified(params, 'depth', depth)
        add_if_specified(params, 'sort', sort)
        add_if_specified(params, 'status', status)
        add_if_specified(params, 'title', title)

        return self._collect_data(
            f'spaces/{space_id}/blogposts', params=params
        )

    @api_call
    def create_space(
        self,
        name: str,
        key: str,
        alias: Optional[str] = None,
        description: Optional[Dict[str, Any]] = None,
        role_assignments: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Create a new space.

        # Required parameters

        - name: a non-empty string
        - key: a non-empty string

        # Optional parameters

        - alias: a string
        - description: a dictionary
        - role_assignments: a list of dictionaries

        # Returned value

        A dictionary representing the created space.  Please refer to
        #get_space() for more.
        """
        ensure_nonemptystring('name')
        ensure_nonemptystring('key')
        ensure_noneorinstance('alias', str)
        ensure_noneorinstance('description', dict)
        ensure_noneorinstance('role_assignments', list)

        data: Dict[str, Any] = {
            'name': name,
            'key': key,
        }
        add_if_specified(data, 'alias', alias)
        add_if_specified(data, 'description', description)
        add_if_specified(data, 'roleAssignments', role_assignments)

        url = join_url(self.url, 'rest/api/space')
        response = self.session().post(url, json=data)
        return response.status_code == 200

    @api_call
    def get_space_properties(
        self, space_id: int, key: Optional[str] = None, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Return properties of a space.

        # Required parameters

        - space_id: an integer

        # Optional parameters

        - key: a string
        - limit: an integer (default `100`)

        # Returned value

        A list of dictionaries, each representing a property of the
        space.  Please refer to #create_space_property() for more.
        """
        ensure_instance('space_id', int)
        ensure_noneorinstance('key', str)
        ensure_instance('limit', int)

        params = {'limit': limit}
        add_if_specified(params, 'key', key)

        return self._collect_data(
            f'spaces/{space_id}/properties', params=params
        )

    @api_call
    def create_space_property(
        self, space_id: int, key: str, value: Any
    ) -> Dict[str, Any]:
        """Create a property for a space.

        # Required parameters

        - space_id: an integer
        - key: a non-empty string
        - value: any value (e.g., string, integer, dict, etc.)

        # Returned value

        A dictionary with the following entries:

        - id: a string
        - key: a string
        - value: any value (e.g., string, integer, dict, etc.)
        - createdBy: a dictionary
        - createdAt: a string
        - _links: a dictionary
        """
        ensure_instance('space_id', int)
        ensure_nonemptystring('key')

        definition = {'key': key, 'value': value}
        return self._post(f'spaces/{space_id}/properties', definition)

    @api_call
    def list_available_space_permissions(
        self, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Return a list of available space permissions.

        # Optional parameters

        - limit: an integer (default 100)

        # Returned value

        A list of dictionaries, each representing a space permission.
        """
        ensure_instance('limit', int)

        params = {'limit': limit}
        return self._collect_data('space-permissions', params=params)

    @api_call
    def list_space_permissions(
        self, space_id: int, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Return permissions for a space.

        # Required parameters

        - space_id: an integer

        # Optional parameters

        - limit: an integer (default `100`)

        # Returned value

        A list of dictionaries, each dictionary with the following entries:

        - id: a string
        - principal: a dictionary
        - operation: a dictionary
        """
        ensure_instance('space_id', int)
        ensure_instance('limit', int)

        params = {'limit': limit}
        return self._collect_data(
            f'spaces/{space_id}/permissions', params=params
        )

    @api_call
    def add_space_permission(
        self,
        space_key: str,
        type: str,
        identifier: str,
        operation_key: str,
        operation_target: str,
    ) -> bool:
        """Add a new permission on a space.

        # Required parameters

        - space_key: a non-empty string
        - type: a string, either `'user'` or `'group'`
        - identifier: a non-empty string
        - operation_key: a string
        - operation_target: a string

        # Returned value

        A boolean indicating whether the operation was successful.
        """
        ensure_nonemptystring('space_key')
        ensure_in('type', ['user', 'group'])
        ensure_nonemptystring('identifier')
        ensure_in('operation_key', OPERATION_KEY_VALUES)
        ensure_in('operation_target', OPERATION_TARGET_VALUES)

        body = {
            "subject": {"type": type, "identifier": identifier},
            "operation": {"key": operation_key, "target": operation_target},
        }

        url = join_url(self.url, f'rest/api/space/{space_key}/permission')
        response = self.session().post(url, json=body)

        return response.status_code == 200

    @api_call
    def remove_space_permission(
        self, space_key: str, permission_id: str
    ) -> bool:
        """Remove a permission from a space.

        # Required parameters

        - space_key: a non-empty string
        - permission_id: a non-empty string

        # Returned value

        A boolean indicating whether the operation was successful.
        """
        ensure_nonemptystring('space_key')
        ensure_nonemptystring('permission_id')

        url = join_url(
            self.url, f'rest/api/space/{space_key}/permission/{permission_id}'
        )
        response = self.session().delete(url)

        return response.status_code == 204

    @api_call
    def add_space_label(
        self, space_key: str, label: str, prefix: str
    ) -> Dict[str, Any]:
        """Add a label to a space.

        # Required parameters

        - space_key: a non-empty string
        - label: a non-empty string
        - prefix: a non-empty string

        # Returned value

        A dictionary with the following entries:

        - prefix: a string
        - name: a string
        - id: a string
        - label: a string
        - start: an integer
        - size: an integer
        - _links: a dictionary
        """
        ensure_nonemptystring('space_key')
        ensure_nonemptystring('label')
        ensure_nonemptystring('prefix')

        definition = [{'prefix': prefix, 'name': label}]
        url = join_url(self.url, f"rest/api/space/{space_key}/label")
        response = self.session().post(url, json=definition)
        return response.status_code == 200

    ####################################################################
    # Confluence pages
    #
    # search_pages
    # get_page
    # create_page
    # delete_page
    # update_page
    # update_page_title
    # list_page_attachments
    # add_page_attachment
    # update_page_attachment_data

    @api_call
    def search_pages(
        self,
        pace_id: int,
        body_format: Optional[str] = None,
        depth: Optional[str] = None,
        limit: int = 100,
        sort: Optional[str] = None,
        status: Optional[List[str]] = None,
        title: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return a list of pages in a space.

        # Required parameters

        - pace_id: an integer

        # Optional parameters

        - body_format: a string
        - depth: a string
        - limit: an integer (default `100`)
        - sort: a string
        - status: a list of strings
        - title: a string

        # Returned value

        A list of dictionaries, each representing a page.
        Please refer to #get_page() for more.
        """
        ensure_instance('pace_id', int)
        ensure_noneorinstance('body_format', str)
        ensure_noneorinstance('depth', str)
        ensure_instance('limit', int)
        ensure_noneorinstance('sort', str)
        ensure_noneorinstance('status', list)
        ensure_noneorinstance('title', str)

        params = {'limit': limit}
        add_if_specified(params, 'body-format', body_format)
        add_if_specified(params, 'depth', depth)
        add_if_specified(params, 'sort', sort)
        add_if_specified(params, 'status', status)
        add_if_specified(params, 'title', title)

        return self._collect_data(f'spaces/{pace_id}/pages', params=params)

    @api_call
    def get_page(
        self,
        page_id: int,
        body_format: Optional[str] = None,
        get_draft: bool = False,
        include_collaborators: bool = False,
        include_direct_children: bool = False,
        include_favorited_by_current_user_status: bool = False,
        include_labels: bool = False,
        include_likes: bool = False,
        include_operations: bool = False,
        include_properties: bool = False,
        include_version: bool = False,
        include_versions: bool = False,
        include_webresources: bool = False,
        status: Optional[List[str]] = None,
        version: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Return details of a page.

        # Required parameters

        - page_id: an integer

        # Optional parameters

        - body_format: a string or None (None by default)
        - get_draft: a boolean (False by default)
        - include_collaborators: a boolean (False by default)
        - include_direct_children: a boolean (False by default)
        - include_favorited_by_current_user_status: a boolean (False by default)
        - include_labels: a boolean (False by default)
        - include_likes: a boolean (False by default)
        - include_operations: a boolean (False by default)
        - include_properties: a boolean (False by default)
        - include_version: a boolean (False by default)
        - include_versions: a boolean (False by default)
        - include_webresources: a boolean (False by default)
        - status: a list of strings or None (None by default)
        - version: an integer

        # Returned value

        A dictionary with the following entries:

        - id: a string
        - status: a string
        - title: a string
        - spaceId: a string
        - parentId: a string
        - position: an integer
        - authorId: a string
        - ownorId: a string
        - lastOwnerId: a string
        - createdAt: a string
        - version: a dictionary
        - body: a dictionary
        - labels: a list of dictionaries
        - properties: a dictionary
        - likes: a dictionary
        - versions: a dictionary
        - isFavoritedByCurrentUser: a boolean
        - _links: a dictionary
        """
        ensure_instance('page_id', int)
        ensure_noneorinstance('body_format', str)
        ensure_instance('get_draft', bool)
        ensure_instance('include_collaborators', bool)
        ensure_instance('include_direct_children', bool)
        ensure_instance('include_favorited_by_current_user_status', bool)
        ensure_instance('include_labels', bool)
        ensure_instance('include_likes', bool)
        ensure_instance('include_operations', bool)
        ensure_instance('include_properties', bool)
        ensure_instance('include_version', bool)
        ensure_instance('include_versions', bool)
        ensure_instance('include_webresources', bool)
        ensure_noneorinstance('status', list)
        ensure_noneorinstance('version', int)

        params = {}
        add_if_specified(params, 'body-format', body_format)
        add_if_specified(params, 'get-draft', get_draft)
        add_if_specified(
            params, 'include-collaborators', include_collaborators
        )
        add_if_specified(
            params, 'include-direct-children', include_direct_children
        )
        add_if_specified(
            params,
            'include-favorited-by-current-user-status',
            include_favorited_by_current_user_status,
        )
        add_if_specified(params, 'include-labels', include_labels)
        add_if_specified(params, 'include-likes', include_likes)
        add_if_specified(params, 'include-operations', include_operations)
        add_if_specified(params, 'include-properties', include_properties)
        add_if_specified(params, 'include-version', include_version)
        add_if_specified(params, 'include-versions', include_versions)
        add_if_specified(params, 'include-webresources', include_webresources)
        add_if_specified(params, 'status', status)
        add_if_specified(params, 'version', version)

        return self._get(f'pages/{page_id}', params=params)

    @api_call
    def list_page_children(
        self, page_id: int, limit: int = 100, sort: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Return a list of children pages for a given page.

        # Required parameters

        - page_id: an integer

        # Optional parameters

        - limit: an integer (default `100`)
        - sort: a string

        # Returned value

        A list of dictionaries, each representing a child page.
        Please refer to #get_page() for more.
        """
        ensure_instance('page_id', int)
        ensure_instance('limit', int)
        ensure_noneorinstance('sort', str)

        params = {'limit': limit}
        add_if_specified(params, 'sort', sort)

        return self._collect_data(
            f'pages/{page_id}/direct-children', params=params
        )

    @api_call
    def create_page(
        self,
        space_id: int,
        body: Optional[Dict[str, Any]] = None,
        embedded: bool = False,
        parent_id: Optional[int] = None,
        private: bool = False,
        root_level: bool = False,
        status: Optional[str] = None,
        subtype: Optional[str] = None,
        title: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new page.

        # Required parameters

        - space_id: an integer

        # Optional parameters

        - body: a dictionary
        - embedded: a boolean (default False)
        - parent_id: an integer
        - private: a boolean (default False)
        - root_level: a boolean (default False)
        - status: a string (`'current'` or `'draft'`)
        - subtype: a string
        - title: a string

        # Returned value

        A dictionary representing the created page.
        Please refer to #get_page() for more.
        """
        ensure_instance('space_id', int)
        ensure_noneorinstance('body', dict)
        ensure_instance('embedded', bool)
        ensure_noneorinstance('parent_id', int)
        ensure_instance('private', bool)
        ensure_instance('root_level', bool)
        ensure_noneorinstance('status', str)
        if isinstance(status, str):
            ensure_in('status', ['current', 'draft'])
        ensure_noneorinstance('subtype', str)
        ensure_noneorinstance('title', str)

        definition = {'spaceId': space_id}
        add_if_specified(definition, 'body', body)
        add_if_specified(definition, 'embedded', embedded)
        add_if_specified(definition, 'parentId', parent_id)
        add_if_specified(definition, 'private', private)
        add_if_specified(definition, 'root-level', root_level)
        add_if_specified(definition, 'status', status)
        add_if_specified(definition, 'subtype', subtype)
        add_if_specified(definition, 'title', title)

        return self._post('pages', definition)

    @api_call
    def delete_page(self, page_id: int) -> bool:
        """Delete a page.

        # Required parameters

        - page_id: an integer

        # Returned value

        A boolean indicating whether the deletion was successful.
        """
        ensure_instance('page_id', int)

        response = self._delete(f'pages/{page_id}')
        return response.status_code == 204

    @api_call
    def update_page(
        self,
        page_id: int,
        body: Dict[str, Any],
        version: Dict[str, Any],
        owner_id: Optional[str] = None,
        parent_id: Optional[int] = None,
        space_key: Optional[str] = None,
        status: str = 'current',
        title: str = '',
    ) -> Dict[str, Any]:
        """Update a page.

        # Required parameters

        - page_id: an integer
        - body: a dictionary
        - version: a dictionary

        # Optional parameters

        - title: a non-empty string
        - status: a string (default `'current'`)
        - owner_id: a string
        - parent_id: an integer
        - space_key: a string

        # Usage

        `body` is a dictionary with the following entries:

        - representation: a string
        - value: a string

        `version` is a dictionary with the following entries:

        - number: an integer
        - message: a string

        # Returned value

        A dictionary representing the updated page.
        Please refer to #get_page() for more.
        """
        ensure_instance('page_id', int)
        ensure_instance('body', dict)
        ensure_in('status', ['current', 'draft'])
        ensure_nonemptystring('title')
        ensure_instance('version', dict)
        ensure_noneorinstance('owner_id', str)
        ensure_noneorinstance('parent_id', int)
        ensure_noneorinstance('space_key', str)

        definition: Dict[str, Any] = {
            'id': page_id,
            'body': body,
            'status': status,
            'title': title,
            'version': version,
        }
        add_if_specified(definition, 'ownerId', owner_id)
        add_if_specified(definition, 'parentId', parent_id)
        add_if_specified(definition, 'spaceId', space_key)

        return self._put(f'pages/{page_id}', definition)

    @api_call
    def update_page_title(
        self, page_id: int, status: str = 'current', title: str = ''
    ) -> Dict[str, Any]:
        """Update the title of a page.

        # Required parameters

        - page_id: an integer
        - title: a non-empty string
        - status: a string (default `'current'`)

        # Returned value

        A dictionary representing the updated page.
        Please refer to #get_page() for more.
        """
        ensure_instance('page_id', int)
        ensure_in('status', ['current', 'draft'])
        ensure_nonemptystring('title')

        definition = {
            'status': status,
            'title': title,
        }

        return self._put(f'pages/{page_id}/title', definition)

    @api_call
    def list_page_attachments(
        self,
        page_id: int,
        filename: Optional[str] = None,
        limit: int = 100,
        media_type: Optional[str] = None,
        sort: Optional[str] = None,
        status: str = 'current',
    ) -> List[Dict[str, Any]]:
        """Return a list of attachments for a page.

        # Required parameters

        - page_id: an integer

        # Optional parameters

        - filename: a string
        - limit: an integer (default `100`)
        - media_type: a string
        - sort: a string
        - status: a string (default `'current'`)

        # Returned value

        A list of dictionaries, each representing an attachment.
        An attachment is a dictionary with the following entries:

        - id: a string
        - status: a string
        - title: a string
        - createdAt: a string
        - pageId: a string
        - blogPostId: a string
        - customContentId: a string
        - mediaType: a string
        - mediaTypeDescription: a string
        - comment: a string
        - fileId: a string
        - filesize: an integer
        - webuiLink: a string
        - downloadLink: a string
        - version: a dictionary
        - _links: a dictionary
        """
        ensure_instance('page_id', int)
        ensure_noneorinstance('filename', str)
        ensure_noneorinstance('media_type', str)
        ensure_noneorinstance('sort', str)
        ensure_in('status', ['current', 'archived', 'trashed'])

        params = {'limit': limit, 'status': status}
        add_if_specified(params, 'filename', filename)
        add_if_specified(params, 'mediaType', media_type)
        add_if_specified(params, 'sort', sort)

        return self._collect_data(
            f'pages/{page_id}/attachments', params=params
        )

    @api_call
    def add_page_attachment(
        self,
        page_id: int,
        filename: str,
        comment: Optional[str] = None,
        minor_edit: str = 'true',
    ) -> Dict[str, Any]:
        """Add an attachment to a page.

        # Required parameters

        - page_id: an integer
        - filename: a non-empty string (file path)

        # Optional parameters

        - comment: a non-empty string
        - minor_edit: a string (default to `'true'`)

        # Returned value

        A dictionary representing the added attachment.
        Please refer to #list_page_attachments() for more.
        """
        ensure_instance('page_id', int)
        ensure_nonemptystring('filename')
        ensure_noneornonemptystring('comment')
        ensure_noneorinstance('minor_edit', str)

        with open(filename, 'rb') as f:
            files = {'file': (filename, f.read())}
        data = {'minorEdit': minor_edit}
        if comment:
            data['comment'] = comment

        url = join_url(
            self.url, f'rest/api/content/{page_id}/child/attachment'
        )
        response = self.session().post(url, data=data, files=files)
        return response

    @api_call
    def update_page_attachment_data(
        self,
        page_id: Union[str, int],
        attachment_id: Union[str, int],
        filename: str,
        comment: Optional[str] = None,
        minor_edit: str = 'true',
    ) -> Dict[str, Any]:
        """Update an attachment on a page.

        # Required parameters

        - page_id: a string or an integer
        - attachment_id: a string or an integer
        - filename: a non-empty string

        # Optional parameters

        - comment: a string
        - minor_edit: a string (default `'true'`)

        # Returned value

        A dictionary representing the updated attachment.
        Please refer to #list_page_attachments() for more.
        """
        ensure_instance('page_id', (str, int))
        ensure_instance('attachment_id', (str, int))
        ensure_nonemptystring('filename')
        ensure_noneornonemptystring('comment')
        ensure_instance('minor_edit', str)

        with open(filename, 'rb') as f:
            files = {'file': (filename, f.read())}

        data = {'minorEdit': minor_edit}
        if comment:
            data['comment'] = comment

        api_url = join_url(
            self.url,
            f'rest/api/content/{page_id}/child/attachment/{attachment_id}/data',
        )

        response = self.session().put(
            api_url,
            files=files,
            data=data,
            headers={'X-Atlassian-Token': 'nocheck'},
        )

        return response.json()

    ####################################################################
    # Confluence users
    #
    # get_user
    # get_current_user
    # get_user_groups

    @api_call
    def search_users(
        self,
        cql: str = 'type=user',
        limit: int = 100,
        start: int = 0,
        expand: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Return a list of users.

        # Optional parameters

        - cql: a string (default `'type=user'`)
        - limit: an integer (default `100`)
        - start: an integer (default `0`)
        - expand: a list of strings

        # Returned value

        A list of dictionaries, each representing a user.
        Please refer to #get_user() for more.
        """
        ensure_instance('cql', str)
        ensure_instance('limit', int)
        ensure_instance('start', int)
        ensure_noneorinstance('expand', list)

        params = {'limit': limit, 'start': start, 'cql': cql}
        add_if_specified(params, 'expand', expand)

        url = join_url(self.url, 'rest/api/search/user')
        return self.session().get(url, params=params)

    @api_call
    def get_user(
        self, account_id: str, expand: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Return details of a user.

        # Required parameters

        - account_id: a non-empty string

        # Optional parameters

        - expand: a list of strings

        # Returned value

        A dictionary representing the user, with entries like:

        - type: a string
        - username: a string
        - accountId: a string
        - accountType: a string
        - email: a string
        - publicName: a string
        - profilePicture: a dictionary
        - displayName: a string
        - timezone: a string
        - external collaborator: a boolean
        - isExternalCollaborator: a boolean
        - isGuest: a boolean
        - operations: a list of dictionaries
        - details: a dictionary
        - personalSpace: a dictionary
        - _expandable: a dictionary
        - _links: a dictionary
        - Additional properties: a dictionary
        """
        ensure_nonemptystring('account_id')
        ensure_noneorinstance('expand', list)

        params = {'accountId': account_id}
        add_if_specified(params, 'expand', expand)

        url = join_url(self.url, 'rest/api/user')
        return self.session().get(url, params=params)

    @api_call
    def get_current_user(
        self, expand: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Return details of the current user.

        # Optional parameters

        - expand: a list of strings

        # Returned value

        A dictionary representing the current user.  Please refer to
        #get_user() for more.
        """
        ensure_noneorinstance('expand', list)

        params = {}
        add_if_specified(params, 'expand', expand)

        url = join_url(self.url, 'rest/api/user/current')
        return self.session().get(url, params=params)

    @api_call
    def get_user_groups(
        self, account_id: str, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Return groups of a user.

        # Required parameters

        - account_id: a non-empty string

        # Optional parameters

        - limit: an integer (default `100`)

        # Returned value

        A list of dictionaries, each representing a group.  Each group
        has entries like:

        - name: a string
        - type: a string
        - id: a string
        - _links: a dictionary
        """
        ensure_nonemptystring('account_id')
        ensure_instance('limit', int)

        params = {'accountId': account_id, 'limit': limit}

        url = join_url(self.url, 'rest/api/user/memberof')
        return self.session().get(url, params=params)

    ####################################################################
    # Confluence cloud groups
    #
    # list_groups
    # get_group
    # create_group
    # delete_group
    # list_group_members
    # add_group_member
    # remove_group_member

    @api_call
    def list_groups(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Return a list of groups.

        # Optional parameters

        - limit: an integer (default `100`)

        # Returned value

        A list of dictionaries, each representing a group.
        Please refer to #get_group() for more.
        """
        ensure_instance('limit', int)

        params = {'limit': limit}
        url = join_url(self.url, 'rest/api/group')
        return self.session().get(url, params=params)

    @api_call
    def get_group(self, name: str) -> Dict[str, Any]:
        """Return details of a group.

        # Required parameters

        - name: a non-empty string

        # Returned value

        A dictionary representing the group, with the following entries:

        - name: a string
        - type: a string
        - id: a string
        - _links: a dictionary
        """
        ensure_nonemptystring('name')

        url = join_url(self.url, f'rest/api/group/{name}')
        return self.session().get(url)

    @api_call
    def create_group(self, name: str) -> Dict[str, Any]:
        """Create a new group.

        # Required parameters

        - name: a non-empty string

        # Returned value

        A dictionary representing the created group.
        Please refer to #get_group() for more.
        """
        ensure_nonemptystring('name')

        data = {'name': name}
        url = join_url(self.url, 'rest/api/group')
        response = self.session().post(url, json=data)
        return response.json()

    @api_call
    def delete_group(self, group_id: str) -> bool:
        """Delete a group.

        # Required parameters

        - group_id: a non-empty string (UUID format)

        # Returned value

        A boolean indicating whether the deletion was successful.
        """
        ensure_nonemptystring('group_id')

        url = join_url(self.url, 'rest/api/group/by-id')
        params = {'id': group_id}
        response = self.session().delete(url, params=params)
        print(f"Response: {response.status_code} - {response.text}")
        return response.status_code == 204

    @api_call
    def list_group_members(
        self,
        group_name: str,
        expand: Optional[List[str]] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Return members of a group.

        # Required parameters

        - group_name: a non-empty string

        # Optional parameters

        - expand: a list of strings
        - limit: an integer (default `100`)

        # Returned value

        A list of dictionaries, each representing a user.
        Please refer to #get_user() for more.
        """
        ensure_nonemptystring('group_name')
        ensure_noneorinstance('expand', list)
        ensure_instance('limit', int)

        params = {'limit': limit}
        add_if_specified(params, 'expand', expand)

        url = join_url(self.url, f'rest/api/group/{group_name}/member')
        response = self.session().get(url, params=params).json()
        return response['results']

    @api_call
    def add_group_member(self, group_id: str, account_id: str) -> bool:
        """Add a user to a group using groupId.

        # Required parameters

        - group_id: a non-empty string (UUID format)
        - account_id: a non-empty string

        # Returned value

        A boolean indicating whether the user was added successfully.
        """
        ensure_nonemptystring('group_id')
        ensure_nonemptystring('account_id')

        url = join_url(self.url, 'rest/api/group/userByGroupId')
        params = {'groupId': group_id}
        body = {'accountId': account_id}

        response = self.session().post(url, params=params, json=body)
        print(f"Response: {response.status_code} - {response.text}")

        return response.status_code == 201

    @api_call
    def remove_group_member(self, group_id: str, account_id: str) -> bool:
        """Remove a user from a group using groupId.

        # Required parameters

        - group_id: a non-empty string (UUID format)
        - account_id: a non-empty string

        # Returned value

        A boolean indicating whether the user was removed successfully.
        """
        ensure_nonemptystring('group_id')
        ensure_nonemptystring('account_id')

        url = join_url(self.url, 'rest/api/group/userByGroupId')
        params = {'groupId': group_id, 'accountId': account_id}

        response = self.session().delete(url, params=params)
        print(f"Response: {response.status_code} - {response.text}")

        return response.status_code == 204

    ####################################################################
    # confluence cloud helpers

    def _get(
        self,
        api: str,
        params: Optional[Mapping[str, Union[str, List[str], None]]] = None,
    ) -> requests.Response:
        """Return confluence cloud GET api call results."""
        api_url = join_url(join_url(self.url, 'api/v2/'), api)
        return self.session().get(api_url, params=params)

    def _post(
        self,
        api: str,
        json: Union[Mapping[str, Any], List[Mapping[str, Any]]],
    ) -> requests.Response:
        """Return confluence cloud POST api call results."""
        api_url = join_url(join_url(self.url, 'api/v2/'), api)
        return self.session().post(api_url, json=json)

    def _put(
        self, api: str, json: Optional[Mapping[str, Any]] = None
    ) -> requests.Response:
        """Return confluence cloud PUT api call results."""
        api_url = join_url(join_url(self.url, 'api/v2/'), api)
        return self.session().put(api_url, json=json)

    def _delete(self, api: str) -> requests.Response:
        """Return confluence cloud DELETE api call results."""
        api_url = join_url(join_url(self.url, 'api/v2/'), api)
        return self.session().delete(api_url)

    def _collect_data(
        self,
        api: str,
        params: Optional[Mapping[str, Union[str, List[str], None]]] = None,
    ) -> List[Any]:
        """Return confluence cloud GET api call results, collected."""
        api_url = join_url(join_url(self.url, 'api/v2/'), api)
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
                params = {}
        return collected
