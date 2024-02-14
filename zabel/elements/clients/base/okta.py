# Copyright (c) 2019 Martin Lafaix (martin.lafaix@external.engie.com)
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

"""A base class wrapping OKTA APIs.

There can be as many _OKTA_ instances as needed.

This module depends on the public **asyncio** and **okta.client**
libraries.  It also depend on two **zabel-commons** modules,
#::zabel.commons.exceptions and #::zabel.commons.utils.
"""

from typing import Any, Dict, List

import asyncio

from zabel.commons.exceptions import ApiError
from zabel.commons.utils import ensure_nonemptystring, api_call


class OktaException(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)


class Okta:
    """Okta Base-Level Wrapper.

    # Reference url

    <https://developer.okta.com/docs/reference/api/groups/>
    """

    def __init__(
        self,
        url: str,
        token: str,
    ):
        ensure_nonemptystring('url')
        ensure_nonemptystring('token')

        self.url = url
        self.client = None
        self.token = token

    def _client(self) -> 'okta.OktaClient':
        """singleton instance, only if needed."""

        if self.client is None:
            from okta.client import Client as OktaClient

            self.client = OktaClient({'orgUrl': self.url, 'token': self.token})
        return self.client

    ####################################################################
    # users
    #
    # list_users
    # get_user_info
    # list_groups_by_user_id

    @api_call
    def list_users(
        self, query_params: Dict[str, str] = {}
    ) -> List[Dict[str, Any]]:
        """Return users list.

        # Optional parameters

        - query_params: a dictionary.  Refer to Okta API documentation for
            more information.

        # Returned value

        A list of _users_.  Each user is a dictionary. See
        #get_user_info() for its format.
        """

        async def list_users_async(self, params: Dict[str, str] = {}):
            users, response, error = await self._client().list_users(
                query_params=params
            )
            if error:
                raise ApiError(error)
            collected = users
            while response.has_next():
                users, error = await response.next()
                if error:
                    raise ApiError(error)
                collected += users
            users_dict = [user.as_dict() for user in collected]
            return users_dict

        loop = asyncio.get_event_loop()
        return loop.run_until_complete(list_users_async(self, query_params))

    @api_call
    def get_user_info(self, user: str) -> Dict[str, Any]:
        """Request the Okta user info.

        # Required parameters

        - user: a non-empty string

        # Returned value

        A dictionary with following entries:

        - id: a string
        - status: an enum
        - created: a timestamp
        - activated: a timestamp
        - statusChanged: a timestamp
        - lastLogin: a timestamp
        - lastUpdated: a timestamp
        - passwordChanged: a boolean
        - type: a dictionary
        - profile: a dictionary
        - credentials: a dictionary

        """
        ensure_nonemptystring('user')

        async def get_user_info_async(self, user: str):
            okta_user, resp, err = await self._client().get_user(user)
            if err:
                # TODO : check if err is itself an exception, no time
                # for this for now
                raise OktaException(err)
            if okta_user is not None:
                return okta_user.as_dict()
            else:
                raise OktaException(f"User {user} not found")

        loop = asyncio.get_event_loop()
        return loop.run_until_complete(get_user_info_async(self, user))

    @api_call
    def list_groups_by_user_id(self, userId: str) -> List[Dict[str, Any]]:
        """Return the groups for an user.

        # Required parameters

        - userId: a non-empty string

        # Raised exceptions

        Raises an _ApiError_ exception if error is throw by Okta.

        # Returned value

        Return a list of groups. Refer to #get_group_by_name() for more information.
        """

        ensure_nonemptystring('userId')

        async def list_groups_by_user_id_async(self, userId: str):
            groups, resp, err = await self._client().list_user_groups(userId)
            groups_dict = [group.as_dict() for group in groups]
            return groups_dict

        loop = asyncio.get_event_loop()
        return loop.run_until_complete(
            list_groups_by_user_id_async(self, userId)
        )

    ####################################################################
    # groups
    #
    # get_group_by_name
    # add_user_to_group
    # remove_user_from_group
    # list_users_by_group_id

    @api_call
    def get_group_by_name(self, group_name: str) -> Dict[str, Any]:
        """Requet Okta group by his name.

        # Required parameters

        - group_name: a non-empty string

        # Returned value

        A dictionary with following entries:

        - id: a string
        - created: a timestamp
        - lastUpdated: a timestamp
        - lastMembershipUpdated: a timestamp
        - objectClass: an array
        - type: a string
        - profile: a dictionary
        - _links: a dictionary

        # Raised exceptions

        Raises an _ApiError_ exception if zero or more than one
        group is return by Okta API.
        """
        ensure_nonemptystring('group_name')

        async def find_group_async(self, group_name):
            param = {'q': group_name}
            groups, resp, error = await self._client().list_groups(
                query_params=param
            )
            if len(groups) == 0:
                raise ApiError(f'The group {group_name} is not an Okta group')
            elif len(groups) > 1:
                raise ApiError(
                    f'More than one group with the name: {group_name}'
                )
            return groups[0].as_dict()

        loop = asyncio.get_event_loop()
        return loop.run_until_complete(find_group_async(self, group_name))

    @api_call
    def add_user_to_group(self, group_id: str, user_id: str) -> None:
        """Add user to Okta group.

        # Required parameters

        - group_id: a non-empty string
        - user_id: a non-empty string

        # Raised exceptions

        Raises an _ApiError_ exception if error is throw by Okta during add
        user to group operation.
        """
        ensure_nonemptystring('group_id')
        ensure_nonemptystring('user_id')

        async def add_user_to_group_async(self, group_id, user_id):
            resp, error = await self._client().add_user_to_group(
                userId=user_id, groupId=group_id
            )
            if error:
                raise ApiError(error)

        loop = asyncio.get_event_loop()
        loop.run_until_complete(
            add_user_to_group_async(self, group_id, user_id)
        )

    @api_call
    def remove_user_from_group(self, group_id: str, user_id: str) -> None:
        """Remove user from Okta group.

        # Required parameters

        - group_id: a non-empty string
        - user_id: a non-empty string

        # Raised exceptions

        Raises an _ApiError_ exception if error is throw by Okta during remove
        user from group operation.

        """
        ensure_nonemptystring('group_id')
        ensure_nonemptystring('user_id')

        async def remove_user_from_group_async(self, group_id, user_id):
            resp, error = await self._client().remove_user_from_group(
                userId=user_id, groupId=group_id
            )
            if error:
                raise ApiError(error)

        loop = asyncio.get_event_loop()
        loop.run_until_complete(
            remove_user_from_group_async(self, group_id, user_id)
        )

    @api_call
    def list_users_by_group_id(self, group_id: str) -> List[Dict[str, Any]]:
        """List users in Okta group.

        # Required parameters

        - group_id: a non-empty string

        # Raised exceptions

        Raises an _ApiError_ exception if error is throw by Okta.

        # Returned value

        Return a list of users. Refer to #get_user_info() for more information.
        """
        ensure_nonemptystring('group_id')

        async def list_users_by_group_id_async(self, group_id):
            users, response, error = await self._client().list_group_users(
                group_id
            )

            collected = users
            while response.has_next():
                users, error = await response.next()
                collected += users
            if error:
                raise ApiError(error)
            users_dict = [user.as_dict() for user in collected]
            return users_dict

        loop = asyncio.get_event_loop()
        return loop.run_until_complete(
            list_users_by_group_id_async(self, group_id)
        )
