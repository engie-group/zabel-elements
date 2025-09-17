# Copyright (c) 2025 Martin Lafaix (mlafaix@henix.com)
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

"""Sonatype Nexus Repository Manager.

A class wrapping Sonatype Nexus APIs.

There can be as many Sonatype Nexus instances as needed.

This module depends on the #::.base.sonatypenexus module.

!!! note
    Does not use the **nexus_api_client** library, as it fails on
    components and assets validation on some supported versions
    (PRO 3.70.4-02)

This module depends on the **requests** public library.  It also depends
on three **zabel-commons** modules, #::zabel.commons.exceptions,
#::zabel.commons.sessions, and #::zabel.commons.utils.
"""

from .base.sonatypenexus import SonatypeNexus as Base


class SonatypeNexus(Base):
    """Sonatype Nexus Low-Level Wrapper.

    ## Reference URLs

    - <https://help.sonatype.com/en/api-reference.html>
    - <https://pypi.org/project/nexus_api_client/>

    !!! note
        Does not use the **nexus_api_client** library, as it fails on
        components and assets validation on some supported versions
        (PRO 3.70.4-02)

    ## Implemented features

    - repositories
    - tags
    - users
    - roles
    - privileges
    - misc. features (sources, metrics, ...)

    ## Examples

    ```python
    # standard use
    from zabel.elements.clients import SonatypeNexus

    url = 'https://nexus.example.com/nexus/service/rest'
    token = '...'
    nx = SonatypeNexus(url, bearer_token=token)
    nx.list_repositories()
    ```
    """
