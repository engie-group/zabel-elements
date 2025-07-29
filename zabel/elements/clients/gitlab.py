# Copyright (c) 2025 Martin Lafaix (mlafaix@henix.com)
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

"""GitLab.

A class wrapping GitLab APIs.

There can be as many GitLab instances as needed.

This module depends on the **python-gitlab** public library.  It also
depends on three **zabel-commons** modules, #::zabel.commons.exceptions,
#::zabel.commons.sessions, and #::zabel.commons.utils.
"""

from typing import Any, Dict, List, Union


from zabel.commons.utils import ensure_instance, ensure_nonemptystring

from .base.gitlab import GitLab as Base


class GitLab(Base):
    """GitLab Low-Level Wrapper.

    !!! note
        Reuse the **python-gitlab** library whenever possible, but
        always returns 'raw' values (dictionaries, ..., not classes).

    ## Reference URLs

    - <https://docs.gitlab.com/api/rest/>
    - <https://docs.gitlab.com/api/api_resources/>
    - <https://python-gitlab.readthedocs.io/en/stable/>

    ## Implemented features

    - namespaces
    - groups
    - projects
    - members

    ## Examples

    Standard use on gitlab.com:

    ```python
    from zabel.elements.clients import GitLab

    url = 'https://gitlab.com/'
    token = '...'
    gl = GitLab(url, private_token=token)
    gl.list_project_protectedbranches()
    ```
    """

    def list_namespace_projects(
        self, group_name_or_id: Union[str, int]
    ) -> List[Dict[str, Any]]:
        """List all namespace projects.

        # Required parameters

        - group_name_or_id: a non-empty string or an integer

        # Returned value

        A list of _projects_.  Each project is a dictionary.
        """
        if isinstance(group_name_or_id, str):
            ensure_nonemptystring('group_name_or_id')
        else:
            ensure_instance('group_name_or_id', int)

        all_projects = self.list_group_projects(group_name_or_id)
        for grp in self.list_group_subgroups(group_name_or_id):
            all_projects.extend(self.list_namespace_projects(grp['id']))

        return all_projects
