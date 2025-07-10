# Copyright (c) 2019 Martin Lafaix (martin.lafaix@external.engie.com)
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

"""Jira Cloud.

A class wrapping Jira Cloud APIs.

There can be as many Jira instances as needed.

This module depends on the #::.base.jiracloud module.
"""

from .base.jiracloud import JiraCloud as Base


class JiraCloud(Base):
    """JIRA Cloud Low-Level Wrapper.

    There can be as many Jira instances as needed.

    This class depends on the public **requests** library.
    It also depends on two **zabel-commons** modules,
    #::zabel.commons.exceptions and #::zabel.commons.utils.

    # Reference URLs

    - <https://developer.atlassian.com/cloud/jira/platform/rest/v3>

    # Agile references

    - <https://developer.atlassian.com/cloud/jira/software/rest/intro/>
    - <https://support.atlassian.com/jira/kb/how-to-update-board-administrators-through-rest-api/>

    # Implemented features

    - boards
    - filters
    - groups
    - projects
    - users

    Works with basic authentication.

    It is the responsibility of the user to be sure the provided
    authentication has enough rights to perform the requested operation.

    # Sample usage

    ```python
    from zabel.elements.clients.jiracloud import JiraCloud

    url = 'https://your-domain.atlassian.net'
    jc = JiraCloud(
        url,
        basic_auth=(user, token),
    )
    jc.list_projects()
    ```
    """
