# Copyright (c) 2019 Martin Lafaix (martin.lafaix@external.engie.com)
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

"""Jira Server and Data Center.

A class wrapping Jira Server and Data Center APIs.

There can be as many Jira instances as needed.

This module depends on the #::.base.jira module.
"""

from typing import Any, Dict, Iterable, List, Optional, Union

from zabel.commons.exceptions import ApiError
from zabel.commons.utils import (
    api_call,
    ensure_instance,
    ensure_nonemptystring,
)

from .base.jiracloud import JiraCloud as Base


class JiraCloud(Base):
    """JIRA Cloud Low-Level Wrapper.

    There can be as many Jira instances as needed.

    This class depends on the public **requests** and **jira.JIRA**
    libraries.  It also depends on two **zabel-commons** modules,
    #::zabel.commons.exceptions and #::zabel.commons.utils.

    !!! note
        This class reuses the JIRA library whenever possible, but always
        returns 'raw' values (dictionaries, ..., not classes).

    # Reference URLs

    - <https://developer.atlassian.com/cloud/jira/platform/rest/v3>
    - <https://developer.atlassian.com/cloud/jira/service-desk/rest>

    # Using the jira.JIRA python library

    - <http://jira.readthedocs.io/en/latest/>
    """
