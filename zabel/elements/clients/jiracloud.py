# Copyright (c) 2019 Martin Lafaix (martin.lafaix@external.engie.com)
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

"""Jira Cloud.

A class wrapping Jira Cloud APIs.

There can be as many Jira Cloud instances as needed.

This module depends on the #::.base.jiracloud module.
"""

from .base.jiracloud import JiraCloud as Base


class JiraCloud(Base):
    """Jira Cloud Low-Level Wrapper.

    There can be as many Jira Cloud instances as needed.

    This class depends on the public **requests** library.
    It also depends on two **zabel-commons** modules,
    #::zabel.commons.exceptions and #::zabel.commons.utils.

    ## Reference URLs

    - <https://developer.atlassian.com/cloud/jira/platform/rest/v3>

    ### Agile references

    - <https://developer.atlassian.com/cloud/jira/software/rest/intro/>
    - <https://support.atlassian.com/jira/kb/how-to-update-board-administrators-through-rest-api/>

    ## Implemented features

    - boards
    - filters
    - groups
    - projects
    - users

    Works with basic authentication.

    It is the responsibility of the user to be sure the provided
    authentication has enough rights to perform the requested operation.

    ## Expansion

    The Jira REST API uses resource expansion.  This means the API will
    only return parts of the resource when explicitly requested.

    Many query methods have an `expand` parameter, a comma-separated
    list of entities that are to be expanded, identifying each of them
    by name.

    Here are the default values for the main Jira entities:

    | Entity            | Default value
    | ----------------- | -------------
    | `PROJECTS_EXPAND` | description, lead, url, projectKeys,
                          issueTypes
    | `PROJECT_EXPAND`  | description, lead, projectKeys, issueTypes,
                          issueTypeHierarchy

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

    ## Examples

    ```python
    from zabel.elements.clients.jiracloud import JiraCloud

    url = 'https://your-domain.atlassian.net'
    user = '...'
    token = '...'
    jc = JiraCloud(url, basic_auth=(user, token))
    jc.list_projects()
    ```
    """
