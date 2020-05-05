# Copyright (c) 2019 Martin Lafaix (martin.lafaix@external.engie.com)
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

"""SonarQube.

A class wrapping SonarQube APIs.

There can be as many SonarQube instances as needed.

This module depends on the #::.base.sonarqube module.
"""

from .base.sonarqube import SonarQube as Base


class SonarQube(Base):
    """SonarQube Low-Level Wrapper.

    There can be as many SonarQube instances as needed.

    This class depends on the public **requests** library.  It also
    depends on three **zabel-commons** modules,
    #::zabel.commons.exceptions, #::zabel.commons.sessions,
    and #::zabel.commons.utils.

    # Reference URL

    - <https://docs.sonarqube.org/display/DEV/Web+API>

    # Web API URL

    - <https://sonar.example.com/sonar/web_api>

    # Implemented features

    - applications (incomplete)
    - components (incomplete)
    - languages
    - permissions
    - permissionstemplates
    - projectanalyses (incompete)
    - projects (incomplete)
    - qualitygates (incomplete)
    - qualityprofiles (incomplete)
    - tokens
    - usergroups
    - users
    - misc. operations

    Some features may be specific to the Enterprise Edition, but as long
    as they are not used directly, the library can be used with the
    Community edition too.

    Tested on SonarQube v7.9.1.

    # Conventions

    `'_'` are removed from SonarQube entrypoints names, to prevent
    confusion.

    Getters exhaust results (they return all items matching the query,
    there is no need for paging).

    `list_xxx` methods take a possibly optional filter argument and
    return a list of matching items.

    # Sample use

    ```python
    >>> from zabel.elements.clients import SonarQube
    >>>
    >>> url = 'https://sonar.example.com/sonar/api/'
    >>> sq = SonarQube(url, token)
    >>> sq.search_users()
    ```
    """
