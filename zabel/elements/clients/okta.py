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

This module depends on the #:tooling.base.okta module.
"""

from typing import Iterable

from zabel.commons.exceptions import ApiError

from .base.okta import Okta as Base


class Okta(Base):
    """Okta Low-Level Wrapper.

    # Reference url

    <https://developer.okta.com/docs/reference/api/groups/>

    # Implemented features

    - #add_users_to_group
    - #remove_users_from_group

    - #get_user_info
    - #get_group_by_name
    - #add_user_to_group
    - #remove_user_from_group

    # Sample use

    (assuming an `okta` entry in your credentials that contains the
    token api `token`)

    ```
    >>> from zabel.elements.clients import Okta
    >>> url = 'https://okta.example.com/api/requests/v1/'
    >>> okta = Okta(
    >>>     url,
    >>>     token
    >>> )
    >>> user = okta.get_user_info('JP5300')
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
        okta_group_id = okta_group.id
        for user in users:
            okta_user = self.get_user_info(user)
            okta_user_id = okta_user.id
            try:
                self.add_user_to_group(okta_group_id, okta_user_id)
            except ApiError:
                print(f'Could not add user {user} to group {group}')

    def remove_users_from_group(self, group: str, users: Iterable[str]):
        """Remove users from Okta group.

        This method retrieve Okta groupId and userIds and after this
        these users are removed from group.

        # Required parameters

        - group: a non-empty string
        - users: an list of strings

        """
        okta_group = self.get_group_by_name(group)
        okta_group_id = okta_group.id
        for user in users:
            okta_user = self.get_user_info(user)
            okta_user_id = okta_user.id
            try:
                self.remove_user_from_group(okta_group_id, okta_user_id)
            except ApiError:
                print(f'Could not remove user {user} from group {group}')
