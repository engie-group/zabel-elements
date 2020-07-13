# Copyright (c) 2019 Martin Lafaix (martin.lafaix@external.engie.com)
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

"""Jira.

A class wrapping Jira APIs.

There can be as many Jira instances as needed.

This module depends on the #::.base.jira module.
"""

from typing import Any, Dict, Iterable, List, Optional, Union

from zabel.commons.exceptions import ApiError
from zabel.commons.utils import (
    api_call,
    ensure_instance,
    ensure_nonemptystring,
)

from .base.jira import Jira as Base


class Jira(Base):
    """JIRA Low-Level Wrapper.

    There can be as many Jira instances as needed.

    This class depends on the public **requests** and **jira.JIRA**
    libraries.  It also depends on two **zabel-commons** modules,
    #::zabel.commons.exceptions and #::zabel.commons.utils.

    # Reference URLs

    - <https://docs.atlassian.com/jira/REST/server/>
    - <https://docs.atlassian.com/software/jira/docs/api/REST/8.7.1/>

    # Agile references

    - <https://docs.atlassian.com/jira-software/REST/8.7.1/>

    # Using the jira.JIRA python library

    <http://jira.readthedocs.io/en/latest/>

    # Other interesting links

    The various WADLS, such as:

    - <https://jira.tools.digital.engie.com/rest/greenhopper/1.0/application.wadl>
    - <https://jira.tools.digital.engie.com/rest/bitbucket/1.0/application.wadl>

    # Implemented features

    - boards
    - groups
    - issues
    - issuetypeschemes
    - issuetypescreenschemes
    - notificationschemes
    - permissionschemes
    - projects
    - screenschemes
    - search
    - sprints
    - users
    - workflowschemes
    - misc. features (reindexing, plugins & server info)

    Works with basic authentication as well as OAuth authentication.

    It is the responsibility of the user to be sure the provided
    authentication has enough rights to perform the requested operation.

    # Expansion

    The Jira REST API uses resource expansion.  This means the API will
    only return parts of the resource when explicitly requested.

    Many query methods have an `expand` parameter, a comma-separated
    list of entities that are to be expanded, identifying each of them
    by name.

    Here are the default values for the main Jira entities:

    | Entity                    | Default value                        |
    | ------------------------- | ------------------------------------ |
    | PERMISSIONSCHEME_EXPAND   | permissions, user, group,
                                  projectRole, field, all              |
    | NOTIFICATIONSCHEME_EXPAND | notificationSchemeEvents,
                                  user, group, projectRole, field, all |
    | PROJECT_EXPAND            | description, lead, url, projectKeys  |
    | USER_EXPAND               | groups, applicationRoles             |

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

    # Sample use

    ```python
    >>> from zabel.elements.clients import Jira
    >>>
    >>> url = 'https://jira.example.com'
    >>> jc = Jira(url, basic_auth=(user, token))
    >>> jc.get_users()
    ```

    !!! note
        Reuse the JIRA library whenever possible, but always returns
        'raw' values (dictionaries, ..., not classes).
    """

    @api_call
    def get_ids_for_users(self, users_names: List[str]) -> Dict[str, Any]:
        """Return a dictionary of ID for users.

        # Required parameters

        - users_names: a list of strings

        # Returned value

        A dictionary.  In the returned dictionary, keys are the items in
        `users_names`, and the values are one of (1) the ID of the
        corresponding user if it exists, (2) None if no users with that
        name exist, or (3) ... (Ellipsis) if more than one user matches.
        """

        def _user_id(
            users: List[Dict[str, Any]], cnt: int
        ) -> Union[str, None, Ellipsis]:
            return users[0]['name'] if cnt == 1 else None if cnt == 0 else ...

        return {
            n: _user_id(us, len(us))
            for n, us in zip(
                users_names, [self.search_users(name) for name in users_names]
            )
        }

    @api_call
    def get_ids_for_projectkeys(
        self, keys: Iterable[str]
    ) -> Dict[str, Optional[str]]:
        """Return a dictionary of project names for keys.

        # Required parameters

        - keys: a list of strings

        # Returned value

        A dictionary.  In the returned dictionary, keys are items in
        `keys`, and the value is either the project name or None, if no
        project with key exist.
        """

        def _project_name(key: str) -> Optional[str]:
            try:
                return self.get_project(key)['name']  # type: ignore
            except ApiError:
                return None

        return {key: _project_name(key) for key in keys}

    @api_call
    def get_ids_for_sprints(
        self, sprints: List[str], project_key: str
    ) -> Dict[str, Optional[int]]:
        """Return a dictionary of sprint ids for projects.

        # Required parameters

        - sprints: a list of strings
        - project_key: a string

        # Returned value

        A dictionary.  In the returned dictionary, keys are items in
        `sprints`, and the value is either the sprint ID or None.
        """

        def _get_sprint_id(
            name: str, sprints: List[Dict[str, Any]]
        ) -> Optional[int]:
            for sprint in sprints:
                if sprint['name'] == name:
                    return sprint['id']  # type: ignore
            return None

        all_sprints: List[Dict[str, Any]] = []
        for board in self.list_project_boards(project_key):
            all_sprints += self.list_board_sprints(board['id'])

        return {s: _get_sprint_id(s, all_sprints) for s in sprints}

    @api_call
    def list_picker_users(
        self,
        servicedesk_id: str,
        query: str,
        field_name: str,
        project_id: str,
        fieldconfig_id: int,
        _: int,
    ) -> List[Dict[str, Any]]:
        """Return list of users matching query hint.

        Simulates /rest/servicedesk/{n}/customer/user-search.

        # Required parameters

        - servicedesk_id: a non-empty string
        - query: a string
        - field_name: a string
        - project_id: a string
        - fieldconfig_id: an integer
        - _: an integer

        # Returned value

        A possibly empty list of _user infos_.  Each user info is a
        dictionary with the following fields:

        - id: a string
        - emailAddress: a string
        - displayName: a string
        - avatar: a string (an URL)
        """

        def _email(html: str) -> str:
            text = html.replace('<strong>', '').replace('</strong>', '')
            return text.split(' - ')[1].split(' ')[0]

        def _avatar(url: str) -> str:
            if 'avatarId=' in url:
                return (
                    f'/rest/servicedesk/{servicedesk_id}/servicedesk/customer/avatar/'
                    + url.split('avatarId=')[1]
                    + '?size=xsmall'
                )
            return url

        ensure_nonemptystring('servicedesk_id')
        ensure_instance('query', str)
        ensure_instance('field_name', str)
        ensure_instance('project_id', str)

        picked = self._get(
            f'/rest/api/2/user/picker?query={query}',
            params={'maxResults': 10, 'showAvatar': True},
        ).json()['users']

        return [
            {
                'id': user['name'],
                'displayName': user['displayName'],
                'emailAddress': _email(user['html']),
                'avatar': _avatar(user['avatarUrl']),
            }
            for user in picked
        ]
