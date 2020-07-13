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

from typing import Any, Dict, List, Optional

import base64
import csv
import time

from zabel.commons.exceptions import ApiError
from zabel.commons.utils import (
    api_call,
    ensure_instance,
    ensure_nonemptystring,
    ensure_noneorinstance,
    ensure_noneornonemptystring,
    join_url,
)

from .base.github import GitHub as Base


class GitHub(Base):
    """GitHub Low-Level Wrapper.

    There can be as many GitHub instances as needed.

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

    ####################################################################
    # GitHub repository contents
    #
    # get_repository_textfile
    # create_repository_textfile
    # update_repository_textfile

    def get_repository_textfile(
        self,
        organization_name: str,
        repository_name: str,
        path: str,
        ref: Optional[str] = None,
    ) -> Any:
        """Return the text file content.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string
        - path: a string

        # Optional parameters

        - ref: a non-empty string or None (None by default)

        # Returned value

        A dictionary with the following entries:

        - name: a string
        - path: a string
        - sha: a string
        - size: an integer
        - content: a string
        - url, html_url, git_url, download_url: strings
        - _links: a dictionnary
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')
        ensure_instance('path', str)
        ensure_noneornonemptystring('ref')

        result = self.get_repository_content(
            organization_name, repository_name, path, ref
        )
        if result.get('encoding') != 'base64':
            raise ApiError('Content not in base64')
        if result.get('type') != 'file':
            raise ApiError('Content is not a file')
        result['content'] = str(base64.b64decode(result['content']), 'utf-8')
        del result['encoding']
        return result

    def create_repository_textfile(
        self,
        organization_name: str,
        repository_name: str,
        path: str,
        message: str,
        content: str,
        branch: Optional[str] = None,
        committer: Optional[Dict[str, str]] = None,
        author: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Create a new repository text file.

        The created text file must not already exist.  `content` is
        expected to be an utf-8-encoded string.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string
        - path: a string
        - message: a string
        - content: a string

        # Optional parameters

        - branch: a string or None (None by default)
        - commiter: a dictionary or None (None by default)
        - author: a dictionary or None (None by default)

        # Returned value

        A dictionary.
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')
        ensure_instance('path', str)
        ensure_instance('message', str)
        ensure_instance('content', str)
        ensure_noneornonemptystring('branch')
        ensure_noneorinstance('committer', dict)
        ensure_noneorinstance('author', dict)

        return self.create_repository_file(
            organization_name,
            repository_name,
            path,
            message,
            str(base64.b64encode(bytes(content, encoding='utf-8')), 'utf-8'),
            branch,
            committer,
            author,
        )

    def update_repository_textfile(
        self,
        organization_name: str,
        repository_name: str,
        path: str,
        message: str,
        content: str,
        sha: str,
        branch: Optional[str] = None,
        committer: Optional[Dict[str, str]] = None,
        author: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Update a repository text file.

        The file must already exist on the repository.  `encoded` is
        expected to be an utf-8-encoded string.

        # Required parameters

        - organization_name: a non-empty string
        - repository_name: a non-empty string
        - path: a string
        - message: a string
        - content: a string
        - sha: a non-empty string

        # Optional parameters

        - branch: a string or None (None by default)
        - commiter: a dictionary or None (None by default)
        - author: a dictionary or None (None by default)

        # Returned value

        A dictionary.
        """
        ensure_nonemptystring('organization_name')
        ensure_nonemptystring('repository_name')
        ensure_instance('path', str)
        ensure_instance('message', str)
        ensure_instance('content', str)
        ensure_nonemptystring('sha')
        ensure_noneornonemptystring('branch')
        ensure_noneorinstance('committer', dict)
        ensure_noneorinstance('author', dict)

        return self.update_repository_file(
            organization_name,
            repository_name,
            path,
            message,
            str(base64.b64encode(bytes(content, encoding='utf-8')), 'utf-8'),
            sha,
            branch,
            committer,
            author,
        )
