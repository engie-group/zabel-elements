# Copyright (c) 2019 Martin Lafaix (martin.lafaix@external.engie.com)
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

"""
...
"""

from typing import Any, Dict, Union

from zabel.commons.interfaces import Image
from zabel.commons.servers import ApiApp, entrypoint


########################################################################
# Interface


class ManagedServiceApp(ApiApp, Image):
    """Abstract Managed Service API app.

    This class extends #ApiApp and is abstract.  It declares a
    minimal set of features a managed service must provide, in addition
    to the #ApiApp ones:

    - canonical user names management
    - members getters
    - project push and pull

    # Added Methods

    | Method name                | Default implementation? | Endpoint |
    | -------------------------- | ------------------------| -------- |
    | #get_canonical_member_id() | No                      | No       |
    | #get_internal_member_id()  | No                      | No       |
    | #list_members()            | No                      | `GET /v1/members`
    | #get_member()              | No                      | `GET /v1/members/{canonical_id}`
    | #push_managedproject()     | No                      | `PUT /v1/managedprojects/{project_id}`
    | #pull_managedproject()     | No                      | `GET /v1/managedprojects/{project_id}`

    Unimplemented features will raise a _NotImplementedError_
    exception.
    """

    def get_canonical_member_id(self, user: Any) -> str:
        """Return the canonical member ID.

        # Required parameters

        - user: a service-specific user representation

        `user` is the service internal user representation. It may be
        a service-specific object or class.

        # Returned value

        A string.
        """
        raise NotImplementedError

    def get_internal_member_id(self, canonical_id: str) -> Union[str, int]:
        """Return the internal name.

        # Required parameters

        - canonical_id: a string, the canonical member ID

        # Returned value

        A string or an integer, depending on the service internals.
        """
        raise NotImplementedError

    @entrypoint('/v1/members')
    def list_members(self) -> Dict[str, Any]:
        """Return the members on the service.

        # Returned value

        A dictionary.  The keys are the canonical IDs and the values are
        the representations of a user for the service.
        """
        raise NotImplementedError

    @entrypoint('/v1/members/{member_id}')
    def get_member(self, canonical_id: str) -> Any:
        """Return details on user.

        # Required parameters

        - canonical_id: a string, the canonical member ID.

        # Returned value

        The representation of the user for the service, which is
        service-specific.
        """
        raise NotImplementedError

    @entrypoint('/v1/managedprojects/{project_id}', methods=['PUT'])
    def push_managedproject(self, project_id: str) -> None:
        """Push (aka publish) managed project on service.

        # Required parameters

        - project_id: a managed project definition name

        # Raised exceptions

        Raises an exception if the managed project is not successfully
        pushed.
        """
        raise NotImplementedError

    @entrypoint('/v1/managedprojects/{project_id}', methods=['GET'])
    def pull_managedproject(self, project_id: str) -> Any:
        """Pull (aka extract) managed project users on service.

        # Required parameters

        - project_id: a managed project definition name

        # Returned value

        A service-specific result.
        """
        raise NotImplementedError
