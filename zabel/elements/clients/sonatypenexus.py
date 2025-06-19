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

This module depends on the #::.base.github module.
"""

from .base.sonatypenexus import SonatypeNexus as Base


class SonatypeNexus(Base):
    """Sonatype Nexus Low-Level Wrapper.

    # Reference URL

    - <https://help.sonatype.com/en/api-reference.html>
    - <https://pypi.org/project/nexus_api_client/>

    # Implemented features

    - ...

    # Sample use

    ```python
    # standard use
    from zabel.elements.clients import SonatypeNexus

    url = 'https://nexus.example.com/nexus/service/rest'
    nx = SonatypeNexus(url, access_token=access_token)
    nx.list_project_protectedbranches()
    ```

    !!! note
        Reuse the nexus_api_client library whenever possible, but always
        returns 'raw' values (dictionaries, ..., not classes).
    """
