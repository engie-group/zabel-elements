# Copyright (c) 2019 Martin Lafaix (martin.lafaix@external.engie.com)
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

"""Okta.

A class wrapping Okta APIs.

There can be as many Okta instances as needed.

This module depends on the public **asyncio** and **okta.client**
libraries.  It also depend on two **zabel-commons** modules,
#::zabel.commons.exceptions and #::zabel.commons.utils.
"""

from typing import Iterable, List, Dict, Any

import asyncio

from zabel.commons.exceptions import ApiError

from .base.okta import Okta as Base, OktaException


class Okta(Base):
    """Okta Low-Level Wrapper.

    # Reference url

    <https://developer.okta.com/docs/reference/api/groups/>

    # Implemented features

    - add_users_to_group
    - remove_users_from_group
    - list_group_users
    - list_user_groups

    - get_user_info
    - get_group_by_name
    - add_user_to_group
    - remove_user_from_group

    # Sample use

    (assuming a token api `token`)

    ```python
    from zabel.elements.clients import Okta

    url = 'https://okta.example.com'
    okta = Okta(
        url,
        token,
    )
    user = okta.get_user_info('JP5300')
    ```

    """

    def add_users_to_group(self, group: str, users: Iterable[str]):
        """Add users to Okta group.

        This method retrieve Okta groupId and userIds and after this
        these users are added to group.

        # Required parameters

        - group: a non-empty string
        - users: an list of strings

        """
        okta_group = self.get_group_by_name(group)
        okta_group_id = okta_group['id']

        loop = asyncio.get_event_loop()
        okta_users = loop.run_until_complete(
            asyncio.gather(*[self._client().get_user(u) for u in users])
        )

        loop.run_until_complete(
            asyncio.gather(
                *[
                    self._client().add_user_to_group(
                        userId=u[0].id, groupId=okta_group_id
                    )
                    for u in okta_users
                    if u[0]
                ]
            )
        )

    def remove_users_from_group(self, group: str, users: Iterable[str]):
        """Remove users from Okta group.

        This method retrieve Okta groupId and userIds and after this
        these users are removed from group.

        # Required parameters

        - group: a non-empty string
        - users: an list of strings

        """
        okta_group = self.get_group_by_name(group)
        okta_group_id = okta_group['id']
        for user in users:
            try:
                okta_user = self.get_user_info(user)
            except OktaException as ex:
                print(
                    f'Could not remove user {user} from group {group}, because : {str(ex)}'
                )
                continue

            okta_user_id = okta_user['id']
            try:
                self.remove_user_from_group(okta_group_id, okta_user_id)
            except ApiError:
                print(f'Could not remove user {user} from group {group}')

    def list_group_users(self, group_name) -> List[Dict[str, Any]]:
        """List users in Okta group.

        Retrieve the Okta groupId and collecting users in group.

        # Required parameters

        - group_name: a non-empty string

        # Raised exceptions

        Raises an _ApiError_ exception if error is throw by Okta.

        # Returned value

        Return a list of users. Refer to #get_user_info() for more information.
        """

        okta_group = self.get_group_by_name(group_name)

        return self.list_users_by_group_id(okta_group['id'])

    def list_user_groups(self, user_login: str):
        """List user groups by login

        # Required parameters

        - user_login: a non-empty string

        # Raised exceptions

        Raises an _ApiError_ exception if error is throw by Okta.

        # Returned value

        Return a list of groups. Refer to #get_group_by_name() for more information.
        """
        try:
            user = self.get_user_info(user_login)
            return self.list_users_by_group_id(user['id'])
        except OktaException as ex:
            # just wrap the exception as the contract method
            # says we can expect this.
            raise ApiError(ex)
