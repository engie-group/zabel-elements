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

This module depends on the #::tooling.base.github module.
"""

from typing import List

import csv
import time

from zabel.commons.exceptions import ApiError
from zabel.commons.utils import api_call, ensure_nonemptystring, join_url

from .base.github import GitHub as Base


class GitHub(Base):
    """GitHub Low-Level Wrapper.

    There can be as many GitHub instances as needed.

    This class depends on the public **requests** library.  It also
    depends on three **commons** modules, #::commons.exceptions,
    #::commons.sessions, and #::commons.utils.

    # Reference URLs

    - <https://developer.github.com/v3/>
    - <https://developer.github.com/enterprise/2.16/v3>
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

    ####################################################################
    # GitHub misc. operations
    #
    # get_staff_report

    @api_call
    def get_staff_report(self, report: str) -> List[List[str]]:
        """Return staff report.

        # Required parameters

        - report: a non-empty string

        # Returned value

        A list of lists, one entry per line in the report. All items in
        the sublists are strings.
        """
        ensure_nonemptystring('report')
        if self.management_url is None:
            raise ApiError('Management URL is not defined')

        retry = True
        while retry:
            rep = self.session().get(join_url(self.management_url, report))
            retry = rep.status_code == 202
            if retry:
                print('Sleeping...')
                time.sleep(5)

        what = list(csv.reader(rep.text.split('\n')[1:], delimiter=','))
        if not what[-1]:
            what = what[:-1]
        return what
