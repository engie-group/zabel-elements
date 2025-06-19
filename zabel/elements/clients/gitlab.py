# Copyright (c) 2019 Martin Lafaix (martin.lafaix@external.engie.com)
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

"""GitHub.

A class wrapping GitHub APIs.

There can be as many GitHub instances as needed.

This module depends on the #::.base.github module.
"""

from .base.gitlab import GitLab as Base


class GitLab(Base):
    """GitLab Low-Level Wrapper.

    There can be as many GitLab instances as needed.

    This class depends on the public **requests** library.  It also
    depends on three **zabel-commons** modules,
    #::zabel.commons.exceptions, #::zabel.commons.sessions,
    and #::zabel.commons.utils.

    # Reference URLs

    - <https://developer.github.com/v3/>
    - <https://developer.github.com/enterprise/2.20/v3>
    - <https://stackoverflow.com/questions/10625190>

    # Implemented features

    - hooks
    - organizations
    - repositories
    - users
    - misc. operations (version, staff reports & stats)

    # Sample use

    ```python
    >>> from zabel.elements.clients import GitHub
    >>>
    >>> # standard use
    >>> url = 'https://github.example.com/api/v3/'
    >>> gh = GitHub(url, user, token)
    >>> gh.get_users()

    >>> # enabling management features
    >>> mngt = 'https://github.example.com/'
    >>> gh = GitHub(url, user, token, mngt)
    >>> gh.create_organization('my_organization', 'admin')
    ```
    """
