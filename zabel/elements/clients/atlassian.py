# Copyright (c) 2019 Martin Lafaix (martin.lafaix@external.engie.com) and others
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

"""Atlassian.

A class wrapping Atlassian APIs.

This module depends on the #::.base.atlassian module.
"""

from .base.atlassian import Atlassian as Base


class Atlassian(Base):
    """Atlassian Low-Level Wrapper.

    This class depends on the public **requests** library.  It also
    depends on three **zabel-commons** modules,
    #::zabel.commons.exceptions, #::zabel.commons.sessions,
    and #::zabel.commons.utils.

    ## Reference URLs

    - <https://developer.atlassian.com/cloud/admin>

    ## Implemented features

    - users

    ## Examples

    ```python
    from zabel.elements.clients import Atlassian

    url = 'https://api.atlassian.com/admin/v1/'
    token = '...'
    atlassian = Atlassian(url, bearer_auth=token)
    attlasian.list_organization_users('your-organization-id')
    ```
    """
