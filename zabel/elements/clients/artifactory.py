# Copyright (c) 2019 Martin Lafaix (martin.lafaix@external.engie.com)
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

"""Artifactory.

A class wrapping Artifactory APIs.

There can be as many Artifactory instances as needed.

This module depends on the #::.base.artifactory module.
"""

from typing import Any, Dict, List, Optional

from .base.artifactory import Artifactory as Base


class Artifactory(Base):
    """Artifactory Low-Level Wrapper.

    There can be as many Artifactory instances as needed.

    This class depends on the public **requests** library.  It also
    depends on three **zabel.commons** modules,
    #::zabel.commons.exceptions, #::zabel.commons.sessions,
    and #::zabel.commons.utils.

    # Reference URL

    - <https://www.jfrog.com/confluence/display/RTF/Artifactory+REST+API>

    # Implemented features

    - users
    - groups
    - repositories
    - permission
    - storageinfo
    - token
    - ping

    # Sample use

    ```python
    >>> from zabel.elements.clients import Artifactory
    >>>
    >>> url = 'https://artifactory.example.com/artifactory/api/'
    >>> af = Artifactory(url, user, token)
    >>> af.get_users()
    ```
    """

    def list_users_details(
        self, users: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Return the users list, including details.

        If `users` is not provided, will return the details for all
        users.

        # Optional parameters

        - users: a list of strings (users names) or None (None by
          default)

        # Returned value

        A list of _users_.  Each user is a dictionary with the following
        entries:

        - admin: a boolean
        - disableUIAccess: a boolean
        - email: a string
        - groups: a list of strings
        - lastLoggedInMillis: an integer
        - ?lastLoggedIn: a string representing a date
        - name: a string
        - offlineMode: a boolean
        - profileUpdatable: a boolean
        - realm: a string

        # Raised exceptions

        An _ApiError_ exception is raised if a user does not exist.
        """
        return self._get_batch(
            f'security/users/{u["name"]}'
            for u in [{'name': n} for n in users or []] or self.list_users()
        )

    def list_permissions_details(
        self, permissions: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Return the permission targets list, including details.

        If `permissions` is not provided, will return the details for
        all permission targets.

        # Optional parameters

        - permissions: a list of strings (permissions names) or None
          (None by default)

        # Returned value

        A list of _permission targets_.  A permission target is a
        dictionary with the following entries:

        - name: a string
        - repositories: a list of strings
        - includesPattern: a string
        - excludesPattern: a string
        - principals: a dictionary

        # Raised exceptions

        An _ApiError_ exception is raised if a permission does not
        exist.
        """
        return self._get_batch(
            f'security/permissions/{p["name"]}'
            for p in [{'name': n} for n in permissions or []]
            or self.list_permissions()
        )
