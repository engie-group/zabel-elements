# Copyright (c) 2019 Martin Lafaix (martin.lafaix@external.engie.com) and others
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

"""Vault.

A class wrapping Vault APIs.

There can be as many Vault instances as needed.

This module depends on the #::.base.Vault module.
"""

from .base.vault import Vault as Base


class Vault(Base):
    """Vault Low-Level Wrapper.

    There can be as many Vault instances as needed.

    This class depends on the public **requests** library.  It also
    depends on three **zabel-commons** modules,
    #::zabel.commons.exceptions, #::zabel.commons.sessions,
    and #::zabel.commons.utils.

    # Reference URLs

    - <https://www.squashtest.org/fr/actualites/faq-squash-tm/fonctionnalites/api-squash-tm-documentation>
    - <https://squash-tm.tools.digital.engie.com/squash/api/rest/latest/docs/api-documentation.html>

    # Implemented features

    - campaigns (read-only)
    - executions (read-only)
    - iterations (read-only)
    - projects
    - requirements (read-only)
    - teams
    - testcasefolders (read-only)
    - testcases (read-only)
    - teststeps (read-only)
    - testsuites (read-only)
    - users

    # Sample use

    ```python
    >>> from zabel.elements.clients import Vault
    >>>
    >>> url = 'https://squash-tm.example.com/squash/api/rest/latest/'
    >>> tm = Vault(url, user, token)
    >>> tm.get_projects()
    ```
    """
