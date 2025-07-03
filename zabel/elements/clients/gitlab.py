# Copyright (c) 2019 Martin Lafaix (martin.lafaix@external.engie.com)
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

"""GitLab.

A class wrapping GitLab APIs.

There can be as many GitLab instances as needed.

This module depends on the #::.base.gitlab module.
"""

from typing import Any, Dict, List, Optional


from zabel.commons.utils import (
    add_if_specified,
    api_call,
    ensure_in,
    ensure_instance,
    ensure_nonemptystring,
    ensure_noneorinstance,
    ensure_noneornonemptystring,
    ensure_onlyone,
)

from .base.gitlab import GitLab as Base


class GitLab(Base):
    """GitLab Low-Level Wrapper.

    # Reference URL

    - <https://docs.gitlab.com/api/rest/>
    - <https://docs.gitlab.com/api/api_resources/>
    - <https://python-gitlab.readthedocs.io/en/stable/>

    # Implemented features

    - namespaces
    - groups
    - projects
    - members

    # Sample use

    ```python
    # standard use
    from zabel.elements.clients import GitLab

    url = 'https://gitlab.com/'
    gl = GitLab(url, private_token)
    gl.list_project_protectedbranches()
    ```

    !!! note
        Reuse the **python-gitlab** library whenever possible, but
        always returns 'raw' values (dictionaries, ..., not classes).
    """

    def list_namespace_projects(
        self,
        *,
        group_name: Optional[str] = None,
        group_id: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """List all namespace projects."""
        ensure_noneornonemptystring('group_name')
        ensure_noneorinstance('group_id', int)
        ensure_onlyone('group_name', 'group_id')

        all_projects = self.list_group_projects(
            group_name=group_name, group_id=group_id
        )
        print(len(all_projects))
        for grp in self.list_group_subgroups(
            group_name=group_name,
            group_id=group_id,
        ):
            print(grp)
            all_projects.extend(
                self.list_namespace_projects(group_id=grp['id'])
            )

        return all_projects
