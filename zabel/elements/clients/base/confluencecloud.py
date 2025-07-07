# Copyright (c) 2019 Martin Lafaix (martin.lafaix@external.engie.com)
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

"""Confluence Cloud .

A class wrapping Confluence Cloud Server APIs.

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
    join_url
)


########################################################################

class ConfluenceCloud:
    """Confluence Cloud  Low-Level Wrapper.

    There can be as many Confluence cloud instances as needed.

    This class depends on the public **requests** library.  It also
    depends on three **zabel-commons** modules,
    #::zabel.commons.exceptions, #::zabel.commons.sessions,
    and #::zabel.commons.utils.

    # Reference URL

    <https://developer.atlassian.com/cloud/confluence/rest/v2/>
    <https://developer.atlassian.com/cloud/confluence/rest/v1/>
   
    - spaces


    What is accessible through the API depends on account rights.

    Whenever applicable, the provided features handle pagination (i.e.,
    they return all relevant elements, not only the first n).

    # Sample use

    ```python
    from zabel.elements.clients import ConfluenceCloud

    url = 'https://{instance}.atlassian.net/wiki/'
    confluencecloud = ConfluenceCloud(url, basic_auth=(user, token))
    confluencecloud.list_users()
    ```
    """

    def __init__(
        self,
        url: str,
        basic_auth: Tuple[str, str]
    ) -> None:
        """Create a Confluence Cloud instance object.

        Please note that the `bearer_auth` support does not give access
        to JSON-RPC methods.

        # Required parameters

        - url: a non-empty string
        - basic_auth: a string tuple (user, token)


        # Usage

        `url` must be the URL of the Confluence Cloud instance, e.g.,
        `https://{instance}.atlassian.net/wiki`.

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
    # confluence helpers

    def _get(
        self,
        api: str,
        params: Optional[Mapping[str, Union[str, List[str], None]]] = None,
    ) -> requests.Response:
        """Return confluence Cloud GET api call results."""
        api_url = join_url(join_url(self.url, 'api/v2/'), api)
        return self.session().get(api_url, params=params)
    
    def _post(
            self,
            api: str,
            json: Union[Mapping[str, Any], List[Mapping[str, Any]]],
    ) -> requests.Response:
        """Return confluence Cloud POST api call results."""
        api_url = join_url(join_url(self.url, 'api/v2/'), api)
        return self.session().post(api_url, json=json)
 

    def _collect_data(
        self,
        api: str,
        params: Optional[Mapping[str, Union[str, List[str], None]]] = None,
    ) -> List[Any]:
        """Return confluence cloud GET api call results, collected."""
        api_url = join_url(join_url(self.url, 'api/v2/'), api)
        print(api_url)
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
        ids: Optional[List[int]] = None,
        keys: Optional[List[str]] = None,
        type: Optional[str] = None,
        status: Optional[str] = None,
        labels: Optional[List[str]] = None,
        favorited_by: Optional[str] = None,
        not_favorited_by: Optional[str] = None,
        sort: Optional[str] = None,
        description_format: Optional[str] = None,
        include_icons: Optional[bool] = False,
        limit: int = 100,
    )  -> List[Dict[str, Any]]:
        """Return a list of spaces.

        # Returned value

        A list of _spaces_.  Each space is a dictionary with the
        following entries:

        - spaceOwnerId: a string
        - createdAt: a string
        - authorId: a string
        - homepageId: an integer
        - status: a string
        - name: a string
        - key: a string
        - id: a string
        - type: a string
        - _links: a dictionary
        - currentActiveAlias: a string

        Handles pagination (i.e., it returns all spaces, not only the
        first _n_ spaces).
        """

        ensure_noneorinstance('ids', list)
        ensure_noneorinstance('keys', list)
        ensure_noneorinstance('type', str)
        ensure_noneorinstance('status', str)
        ensure_noneorinstance('labels', list)
        ensure_noneorinstance('favorited_by', str)
        ensure_noneorinstance('not_favorited_by', str)
        ensure_noneorinstance('sort', str)
        ensure_noneorinstance('description_format', str)
        ensure_noneorinstance('include_icons', bool)

        params = {'limit': limit}

        add_if_specified(params, 'ids', ids)
        add_if_specified(params, 'keys', keys)
        add_if_specified(params, 'type', type)
        add_if_specified(params, 'status', status)
        add_if_specified(params, 'labels', labels)
        add_if_specified(params, 'favorited-by', favorited_by)
        add_if_specified(params, 'not-favorited-by', not_favorited_by)
        add_if_specified(params, 'sort', sort)
        add_if_specified(params, 'description-format', description_format)
        add_if_specified(params, 'include-icon', include_icons)

        return self._collect_data('spaces', params=params)
    

    @api_call
    def get_space(
        self,
        space_key: str,
        description_format: Optional[str] = None,
        include_icon: Optional[bool] = False,
        include_operations: Optional[bool] = False,
        include_properties: Optional[bool] = False,
        include_permissions: Optional[bool] = False,
        include_role_assignments: Optional[bool] = False,
        include_labels: Optional[bool] = False,
    ) -> Dict[str, Any]:
        """Return space details.

        # Required parameters
        - space_key: a non-empty string

        # Optional parameters
        - description_format: a string
        - include_icon: a boolean
        - include_operations: a boolean
        - include_properties: a boolean
        - include_permissions: a boolean
        - include_role_assignments: a boolean
        - include_labels: a boolean

        # Returned value
        A dictionary with the following entries:
        - key: a string
        - name: a string
        - type: a string
        - status: a string
        - authorId: a string
        - createdAt: a string
        - homepageId: a string
        - description: a dictionary
        - icon: a dictionary
        - _links: a dictionary
        """

        ensure_nonemptystring('space_key')
        ensure_noneorinstance('description_format', str)
        ensure_noneorinstance('include_icon', bool)
        ensure_noneorinstance('include_operations', bool)
        ensure_noneorinstance('include_properties', bool)
        ensure_noneorinstance('include_permissions', bool)
        ensure_noneorinstance('include_role_assignments', bool)
        ensure_noneorinstance('include_labels', bool)

        params = {}
        add_if_specified(params, 'description-format', description_format)
        add_if_specified(params, 'include-icon', include_icon)
        add_if_specified(params, 'include-operations', include_operations)
        add_if_specified(params, 'include-properties', include_properties)
        add_if_specified(params, 'include-permissions', include_permissions)
        add_if_specified(
            params, 'include-role-assignments', include_role_assignments
        )
        add_if_specified(params, 'include-labels', include_labels)

        result = self._get(f'spaces/{space_key}', params=params)
        return result
    
    @api_call
    def get_space_pages(
        self,
        space_key: str,
        depth: Optional[str] = None,
        sort: Optional[str] = None,
        status: Optional[list[str]] = None,
        title: Optional[str] = None,
        body_format: Optional[str] = None, 
        limit: int = 200
    ) -> List[Dict[str, Any]]:
        """Return a list of pages in a space.

        # Required parameters
        - space_key: a non-empty string

        # Optional parameters
        - depth: a string
        - sort: a string
        - status: a list of strings
        - title: a string
        - body_format: a string
        - limit: an integer (default 200)

        # Returned value
        A list of dictionaries, each representing a page.
        """
        
        ensure_nonemptystring('space_key')
        ensure_noneorinstance('depth', str)
        ensure_noneorinstance('sort', str)
        ensure_noneorinstance('status', list)
        ensure_noneorinstance('title', str)
        ensure_noneorinstance('body_format', str)

        params = {'limit': limit}
        
        add_if_specified(params, 'depth', depth)
        add_if_specified(params, 'sort', sort)
        add_if_specified(params, 'status', status)
        add_if_specified(params, 'title', title)
        add_if_specified(params, 'body-format', body_format)

        return self._collect_data(f'spaces/{space_key}/pages', params=params)
    

    @api_call
    def list_space_blogposts(
        self,
        space_key: str,
        depth: Optional[str] = None,
        sort: Optional[str] = None,
        status: Optional[List[str]] = None,
        title: Optional[str] = None,
        body_format: Optional[str] = None, 
        limit: int = 200
    ) -> List[Dict[str, Any]]:
        """Return a list of blog posts in a space.

        # Required parameters
        - space_key: a non-empty string

        # Optional parameters
        - depth: a string
        - sort: a string
        - status: a list of strings
        - title: a string
        - body_format: a string
        - limit: an integer (default 200)

        # Returned value
        A list of dictionaries, each representing a blog post.
        """
        
        ensure_nonemptystring('space_key')
        ensure_noneorinstance('depth', str)
        ensure_noneorinstance('sort', str)
        ensure_noneorinstance('status', list)
        ensure_noneorinstance('title', str)
        ensure_noneorinstance('body_format', str)
        
        params = {'limit': limit}
        
        add_if_specified(params, 'depth', depth)
        add_if_specified(params, 'sort', sort)
        add_if_specified(params, 'status', status)
        add_if_specified(params, 'title', title)
        add_if_specified(params, 'body-format', body_format)

        return self._collect_data(f'spaces/{space_key}/blogposts', params=params)
    
    @api_call
    def create_space(
        self,
        name: str,
        key: Optional[str] = None,
        alias: Optional[str] = None,
        description: Optional[Dict[str, Any]] = None,
        roleAssignments: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """Create a new space.

        # Required parameters
        - name: a non-empty string

        # Optional parameters
        - key: a string
        - alias: a string
        - description: a string
        - roleAssignments: a list of dictionaries

        # Returned value
        A dictionary representing the created space.
        """
        
        ensure_nonemptystring('name')
        ensure_noneorinstance('key', str)
        ensure_noneorinstance('alias', str)
        ensure_noneorinstance('description', dict)
        ensure_noneorinstance('roleAssignments', list)

        definition: Dict[str, Any] = {
            'name': name,
        }
        add_if_specified(definition, 'key', key)
        add_if_specified(definition, 'alias', alias)
        add_if_specified(definition, 'description', description)
        add_if_specified(definition, 'roleAssignments', roleAssignments)

        result = self._post('spaces', definition)
        return result
    

    @api_call
    def get_space_properties(
        self,
        space_key: str,
        key: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Return properties of a space.

        # Required parameters
        - space_key: a non-empty string

        # Optional parameters
        - key: a string
        - limit: an integer (default 100)

        # Returned value
        A list of dictionaries, each representing a property of the space.
        """
        
        ensure_nonemptystring('space_key')
        ensure_noneorinstance('key', str)

        params = {'limit': limit}
        
        add_if_specified(params, 'key', key)


        return self._collect_data(f'spaces/{space_key}/properties', params=params)
    
    @api_call
    def create_space_property(
        self,
        space_key: str,
        key: str,
        value: Any
    ) -> Dict[str, Any]:
        """Create a property for a space.

        # Required parameters
        - space_key: a non-empty string
        - key: a non-empty string
        - value: any value (e.g., string, integer, etc.)

        # Returned value
        A dictionary representing the created property.
        """
        
        ensure_nonemptystring('space_key')
        ensure_nonemptystring('key')

        definition = {
            'key': key,
            'value': value
        }

        result = self._post(f'spaces/{space_key}/properties', definition)
        return result

    @api_call
    def list_available_space_permissions(
        self,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Return a list of available space permissions.

        # Optional parameters
        - limit: an integer (default 100)

        # Returned value
        A list of dictionaries, each representing a space permission.
        """

        params = {'limit': limit}

        return self._collect_data('space-permissions', params=params)
    

    @api_call
    def get_space_permission(
        self,
        space_key: str,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Return permissions for a space.

        # Required parameters
        - space_key: a non-empty string

        # Optional parameters
        - limit: an integer (default 100)

        # Returned value
        A list of dictionaries, each representing a permission for the space.
        """
        
        ensure_nonemptystring('space_key')

        params = {'limit': limit}

        return self._collect_data(f'spaces/{space_key}/permissions', params=params)
    
    ####################################################################
    # Confluence pages
    #
    # search_pages
    # get_page
    # create_page
    # delete_page
    # update_page
    # update_page_title
    # list_page_attachements
    # add_page_attachment
    # update_page_attachment_data



    @api_call
    def search_pages(
        self,
        page_ids: Optional[List[int]] = None,
        space_keys: Optional[List[str]] = None,
        sort: Optional[str] = None,
        status: Optional[List[str]] = None,
        title: Optional[str] = None,
        body_format: Optional[str] = None,
        subtype: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Return a list of pages.

        # Optional parameters
        - page_ids: a list of integers
        - space_keys: a list of strings
        - sort: a string
        - status: a list of strings
        - title: a string
        - body_format: a string
        - subtype: a string
        - limit: an integer (default 100)

        # Returned value
        A list of dictionaries, each representing a page.
        """
        
        ensure_noneorinstance('page_ids', list)
        ensure_noneorinstance('space_keys', list)
        ensure_noneorinstance('sort', str)
        ensure_noneorinstance('status', list)
        ensure_noneorinstance('title', str)
        ensure_noneorinstance('body_format', str)
        ensure_noneorinstance('subtype', str)

        params = {'limit': limit}

        add_if_specified(params, 'page-ids', page_ids)
        add_if_specified(params, 'space-keys', space_keys)
        add_if_specified(params, 'sort', sort)
        add_if_specified(params, 'status', status)
        add_if_specified(params, 'title', title)
        add_if_specified(params, 'body-format', body_format)
        add_if_specified(params, 'subtype', subtype)

        return self._collect_data('pages', params=params)

    @api_call
    def get_page(
        self,
        page_id: int,
        body_format: Optional[str] = None,
        get_draft: Optional[bool] = False,
        status: Optional[list[str]] = None,
        version: Optional[int] = None,
        include_labels: Optional[bool] = False,
        include_properties: Optional[bool] = False,
        include_operations: Optional[bool] = False,
        include_likes: Optional[bool] = False,
        include_versions: Optional[bool] = False,
        include_version: Optional[bool] = False,
        include_favorited_by_current_user_status: Optional[bool] = False,
        include_webresources: Optional[bool] = False,
        include_collaborators: Optional[bool] = False,
        include_direct_children: Optional[bool] = False
    ) -> Dict[str, Any]:
        
        """Return details of a page.

        # Required parameters
        - page_id: an integer

        # Optional parameters
        - body_format: a string
        - get_draft: a boolean
        - status: a list of strings
        - version: an integer
        - include_labels: a boolean
        - include_properties: a boolean
        - include_operations: a boolean
        - include_likes: a boolean
        - include_versions: a boolean
        - include_version: a boolean
        - include_favorited_by_current_user_status: a boolean
        - include_webresources: a boolean
        - include_collaborators: a boolean
        - include_direct_children: a boolean

        # Returned value
        A dictionary representing the page.
        """
        
        ensure_instance('page_id', int)
        ensure_noneorinstance('body_format', str)
        ensure_noneorinstance('get_draft', bool)
        ensure_noneorinstance('status', list)
        ensure_noneorinstance('version', int)
        ensure_noneorinstance('include_labels', bool)
        ensure_noneorinstance('include_properties', bool)
        ensure_noneorinstance('include_operations', bool)
        ensure_noneorinstance('include_likes', bool)
        ensure_noneorinstance('include_versions', bool)
        ensure_noneorinstance('include_version', bool)
        ensure_noneorinstance(
            'include_favorited_by_current_user_status', bool
        )
        ensure_noneorinstance('include_webresources', bool)
        ensure_noneorinstance('include_collaborators', bool)
        ensure_noneorinstance('include_direct_children', bool)

        params = {}
        
        add_if_specified(params, 'body-format', body_format)
        add_if_specified(params, 'get-draft', get_draft)
        add_if_specified(params, 'status', status)
        add_if_specified(params, 'version', version)
        add_if_specified(params, 'include-labels', include_labels)
        add_if_specified(params, 'include-properties', include_properties)
        add_if_specified(params, 'include-operations', include_operations)
        add_if_specified(params, 'include-likes', include_likes)
        add_if_specified(params, 'include-versions', include_versions)
        add_if_specified(params, 'include-version', include_version)
        add_if_specified(
            params, 'include-favorited-by-current-user-status', include_favorited_by_current_user_status
        )
        add_if_specified(params, 'include-webresources', include_webresources)
        add_if_specified(params, 'include-collaborators', include_collaborators)
        add_if_specified(params, 'include-direct-children', include_direct_children)
        result = self._get(f'pages/{page_id}', params=params)
        return result

    @api_call
    def create_page(
        self,
        space_key: str,
        title: str,
        status: str = 'current',
        parent_id: Optional[int] = None,
        body: Optional[Dict[str, Any]] = None,
        subtype: Optional[str] = None,
        embedded: Optional[bool] = False,
        private: Optional[bool] = False,
        root_level: Optional[bool] = False

    ) -> Dict[str, Any]:
        """Create a new page.

        # Required parameters
        - space_key: a non-empty string

        # Optional parameters
        - status: a string
        - title: a string
        - parent_id: an integer
        - body: a dictionary
        - subtype: a string
        - embedded: a boolean (default False)
        - private: a boolean (default False)
        - root_level: a boolean (default False)

        # Returned value
        A dictionary representing the created page.
        """
        
        ensure_nonemptystring('space_key')
        ensure_nonemptystring('title')
        
    
        ensure_noneorinstance('parent_id', int)
        ensure_noneorinstance('body', dict)
        ensure_noneorinstance('embedded', bool)
        ensure_noneorinstance('private', bool)
        ensure_noneorinstance('root_level', bool)
        ensure_in('status', ['current','draft'])
    
        definition: Dict[str, Any] = {
            'spaceId': space_key,
            'title': title,
            'status': status
        }
        add_if_specified(definition, 'parentId', parent_id)
        add_if_specified(definition, 'body', body)
        add_if_specified(definition, 'subtype', subtype)
        add_if_specified(definition, 'embedded', embedded)
        add_if_specified(definition, 'private', private)
        add_if_specified(definition, 'rootLevel', root_level)

        result = self._post('pages', definition)
        return result
    

    @api_call
    def delete_page(
        self,
        page_id: int,
        purge: Optional[bool] = False,
        draft: Optional[bool] = False
    ) -> bool:

        """Delete a page.

        # Required parameters
        - page_id: an integer

        # Optional parameters
        - purge: a boolean (default False)
        - draft: a boolean (default False)

        # Returned value
        A boolean indicating whether the deletion was successful.
        """
        
        ensure_instance('page_id', int)
        ensure_noneorinstance('purge', bool)
        ensure_noneorinstance('draft', bool)

        params = {}
        add_if_specified(params, 'purge', purge)
        add_if_specified(params, 'draft', draft)

        response = self.session().delete(f'pages/{page_id}', params=params)
        return response.status_code // 100 == 2
    
    @api_call
    def update_page(
        self,
        page_id: int,
        title: str,
        version: Dict[str, Any],
        body: Dict[str, Any],
        status: str = 'current',
        space_key: Optional[str] = None,
        parent_id: Optional[int] = None,
        owner_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update a page.

        # Required parameters
        - page_id: an integer
        - title: a string
        - status: a string (default 'current')
        - version: a dictionary
        - body: a dictionary

        # Optional parameters
    
        - space_key: a string
        - parent_id: an integer
        - owner_id: a string

        # Returned value
        A dictionary representing the updated page.
        """

        ensure_instance('page_id', int)
        ensure_nonemptystring('title')
        ensure_instance('version', dict)
        ensure_instance('body', dict)
        ensure_in('status', ['current', 'draft'])
        ensure_noneorinstance('space_key', str)
        ensure_noneorinstance('parent_id', int)
        ensure_noneorinstance('owner_id', str)

        definition: Dict[str, Any] = {
            'id': page_id,
            'status': status,
            'title': title,
            'version': version,
            'body': body,
            
        }
        add_if_specified(definition, 'spaceId', space_key)
        add_if_specified(definition, 'parentId', parent_id)
        add_if_specified(definition, 'ownerId', owner_id)

        result = self._post(f'pages/{page_id}', definition)
        return result
    

    @api_call
    def update_page_title(
        self,
        page_id: int,
        title: str,
        status: str = 'current'
    ) -> Dict[str, Any]:
        """Update the title of a page.

        # Required parameters
        - page_id: an integer
        - title: a string
        - status: a string (default 'current')

        # Returned value
        A dictionary representing the updated page.
        """
        
        ensure_instance('page_id', int)
        ensure_nonemptystring('title')
        ensure_in('status', ['current', 'draft'])

        definition = {
            'status': status,
            'title': title
        }

        result = self._post(f'pages/{page_id}/title', definition)
        return result
    
   
    @api_call
    def list_page_attachements(
        self,
        page_id: int,
        limit: int = 100,
        sort: Optional[str] = None,
        status: List[str] = ['current', 'archived'],
        media_type: Optional[str] = None,
        filename: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return a list of attachments for a page.

        # Required parameters
        - page_id: an integer

        # Optional parameters
        - limit: an integer (default 100)
        - sort: a string
        - status: a list of strings
        - media_type: a string
        - filename: a string

        # Returned value
        A list of dictionaries, each representing an attachment.
        """
        
        ensure_instance('page_id', int)
        ensure_in('status', ['current', 'archived', 'trashed'])
        ensure_noneorinstance('sort', str)
        ensure_noneorinstance('mediaType', str)
        ensure_noneorinstance('filename', str)

        params = {'limit': limit, status: status}
        
        add_if_specified(params, 'sort', sort)
        add_if_specified(params, 'media-type', media_type)
        add_if_specified(params, 'filename', filename)

        return self._collect_data(f'pages/{page_id}/attachments', params=params)
    

    @api_call
    def add_page_attachment(
        self,
        page_id: int,
        filename: str,
        minor_edit: str = 'true',
        comment: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Add an attachment to a page.

        # Required parameters
        - page_id: an integer
        - filename: a string (file path)

        # Optional parameters
        - minor_edit: a string (default 'false')
        - comment: a string

        # Returned value
        A dictionary representing the added attachment.
        """
        
        ensure_instance('page_id', int)
        ensure_nonemptystring('filename')
        ensure_noneorinstance('minor_edit', str)
        ensure_noneornonemptystring('comment')

        with open(filename, 'rb') as f:
            files = {'file': (filename, f.read())}
        data = {'minorEdit': minor_edit}
        if comment:
            data['comment'] = comment
       
        api_url = join_url(
            self.url, f'rest/api/content/{page_id}/child/attachment'
        )
        response = self.session().post(
            api_url,
            files=files,
            data=data,
            headers={'X-Atlassian-Token': 'nocheck'},
        )
        return response
    
    @api_call
    def update_page_attachment_data(
        self,
        page_id: Union[str, int],
        attachment_id: Union[str, int],
        filename: str,
        minor_edit: str = 'true',
        comment: Optional[str] = None
    ) -> Dict[str, Any]:
        """Update an attachment on a page.

        # Required parameters
        - page_id: an integer
        - attachment_id: an integer
        - filename: a string 

        # Optional parameters
        - minor_edit: a string (default 'true')
        - comment: a string

        # Returned value
        A dictionary representing the updated attachment.
        """
        
        ensure_instance('page_id', (str, int))
        ensure_instance('attachment_id', (str, int))
        ensure_nonemptystring('filename')
        ensure_instance('minor_edit', str)
        ensure_noneornonemptystring('comment')

        with open(filename, 'rb') as f:
            files = {'file': (filename, f.read())}
        data = {'minorEdit': minor_edit}
        if comment:
            data['comment'] = comment
        
        api_url = join_url(
            self.url, f'rest/api/content/{page_id}/child/attachment/{attachment_id}/data'
        )
        
        response = self.session().put(
            api_url,
            files=files,
            data=data,
            headers={'X-Atlassian-Token': 'nocheck'},
        )
        
        return response.json()
    

    





    





    




    