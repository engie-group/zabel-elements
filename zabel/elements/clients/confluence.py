# Copyright (c) 2019 Martin Lafaix (martin.lafaix@external.engie.com)
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

"""Confluence Server and Data Center.

A class wrapping Confluence Server and Data Center APIs.

There can be as many Confluence instances as needed.

This module depends on the #::.base.confluence module.
"""

from typing import Any, Dict, List, Union, Optional

from zabel.commons.utils import (
    api_call,
    ensure_instance,
    ensure_noneornonemptystring,
)

from .base.confluence import Confluence as Base


class Confluence(Base):
    """Confluence Server and Data Center Low-Level Wrapper.

    An interface to Confluence, including users and groups management.

    There can be as many Confluence instances as needed.

    This class depends on the public **requests** library.  It also
    depends on three **zabel-commons** modules,
    #::zabel.commons.exceptions, #::zabel.commons.sessions,
    and #::zabel.commons.utils.

    ## Reference URLs

    - <https://docs.atlassian.com/ConfluenceServer/rest/latest>
    - <https://docs.atlassian.com/ConfluenceServer/rest/8.5.5/>
    - <https://developer.atlassian.com/confdev/confluence-server-rest-api>
    - <https://developer.atlassian.com/server/confluence/remote-confluence-methods>

    WADLs are also available on a given instance:

    - <https://{instance}/rest/api/application.wadl>
    - <https://{instance}/rest/mobile/1.0/application.wadl>

    ## Implemented features

    - groups&users
    - pages
    - search
    - spaces
    - misc. features (index, long tasks, ...)

    What is accessible through the API depends on account rights.

    Whenever applicable, the provided features handle pagination (i.e.,
    they return all relevant elements, not only the first _n_).

    ## Content types ans statuses

    | Name               | Description
    | ------------------ | -----------
    | `CONTENT_TYPES`    | `'page'`, `'blogpost'`, `'comment'`, `'attachment'`
    | `CONTENT_STATUSES` | `'current'`, `'trashed'`, `'historical'`, `'draft'`

    ## Examples

    ```python
    from zabel.elements.clients import Confluence

    url = 'https://confluence.example.com'
    user = '...'
    token = '...'
    confluence = Confluence(url, basic_auth=(user, token))
    confluence.list_users()
    ```
    """

    @api_call
    def list_users(self) -> List[str]:
        """Return a list of Confluence users.

        # Returned value

        A list of _users_.  Each user is a string (the user's username).

        Users are not properly speaking managed by Confluence.  The
        returned list is the aggregation of group member, with no
        duplication.

        The `'jira-*'` groups are ignored.

        Handles pagination (i.e., it returns all group users, not only
        the first n users).
        """
        return list(
            {
                u['username']
                for g in self.list_groups()
                for u in self.list_group_members(g['name'])
                if not g['name'].startswith('jira-')
            }
        )

    @api_call
    def update_page_content(
        self,
        page_id: Union[str, int],
        content: str,
        title: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Change page content, creating a new version.

        # Required parameters

        - page_id: an integer or a string
        - content: a string

        The new version number is 1 plus the current version number.

        # Optional parameters

        - title: a non-empty string or None (None by default)

        # Returned value

        A dictionary.  Refer to #create_page() for more information.
        """
        ensure_instance('page_id', (str, int))
        ensure_instance('content', str)
        ensure_noneornonemptystring('title')

        page = self.get_page(page_id)
        if title:
            page['title'] = title
        page['body']['storage']['value'] = content
        page['version'] = {'number': page['version']['number'] + 1}

        return self.update_page(page_id, page)
