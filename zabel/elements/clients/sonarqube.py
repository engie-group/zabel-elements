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

    ## Reference URLs

    - <https://docs.sonarqube.org/display/DEV/Web+API>
    - <https://next.sonarqube.com/sonarqube/web_api_v2>

    ### Web API URL

    - <https://sonar.example.com/sonar/web_api>

    ## Implemented features

    - applications (incomplete)
    - components (incomplete)
    - languages
    - permissions
    - permissionstemplates
    - projectanalyses (incomplete)
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

    When using SonarCloud, the `organization_key` parameter must be
    specified for methods that declare it.

    Tested on SonarQube v9.9 anv v10.4.

    ## Conventions

    `'_'` are removed from SonarQube entrypoints names, to prevent
    confusion.

    Getters exhaust results (they return all items matching the query,
    there is no need for paging).

    `list_xxx` methods take a possibly optional filter argument and
    return a list of matching items.

    ## Permissions, qualifiers and event categories

    | Item                  | Possible values
    | ---                   | -----
    | `EVENT_CATEGORIES`    | `'VERSION'`, `'OTHER'`, `'QUALITY_PROFILE'`,
                              `'QUALITY_GATE'`, `'DEFINITION_CHANGE'`
    | `GLOBAL_PERMISSIONS`  | `'admin'`, `'gateadmin'`, `'profileadmin'`,
                              `'provisioning'`, `'scan'`,
                              `'applicationcreator'`, `'portfoliocreator'`
    | `PROJECT_PERMISSIONS` | `'admin'`, `'codeviewer'`, `'issueadmin'`,
                              `'scan'`, `'user'`, `'securityhotspotadmin'`
    | `QUALIFIERS`          | `'BRC'`, `'DIR'`,` 'FIL'`, `'TRK'`, `'UTS'`

    ## Examples

    Using a private SonarQube instance:

    ```python
    from zabel.elements.clients import SonarQube

    url = 'https://sonar.example.com/sonar/api/'
    token = '...'
    sq = SonarQube(url, token)
    sq.list_projects()
    ```

    Using SonarCloud:

    ```python
    from zabel.elements.clients import SonarQube

    url = 'https://sonarcloud.io/api/'
    token = '...'
    sq = SonarQube(url, token)
    sq.list_projects(organization_key='my_organization')
    ```
    """
