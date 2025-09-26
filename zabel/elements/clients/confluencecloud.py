"""
ConfluenceCloud client module providing access to Confluence Cloud API.
"""

from typing import Any, Dict, List, Optional
from .base.confluencecloud import ConfluenceCloud as Base
from zabel.commons.utils import (
    api_call,
    ensure_nonemptystring,
    ensure_noneorinstance,
)

from zabel.commons.exceptions import ApiError


class ConfluenceCloud(Base):
    """Confluence Cloud Low-Level Wrapper.

    An interface to Confluence, including users and groups management.

    There can be as many Confluence Cloud instances as needed.

    This class depends on the public **requests** library.  It also
    depends on three **zabel-commons** modules,
    #::zabel.commons.exceptions, #::zabel.commons.sessions,
    and #::zabel.commons.utils.

    ## Reference URLs

    - <https://developer.atlassian.com/cloud/confluence/rest/v2/>
    - <https://developer.atlassian.com/cloud/confluence/rest/v1/>

    ## Implemented features

    - pages
    - search
    - spaces

    What is accessible through the API depends on account rights.

    Whenever applicable, the provided features handle pagination (i.e.,
    they return all relevant elements, not only the first n).

    ## Examples

    ```python
    from zabel.elements.clients import ConfluenceCloud

    url = 'https://your-instance.atlassian.net/wiki/'
    user = '...'
    token = '...'
    confluencecloud = ConfluenceCloud(url, basic_auth=(user, token))
    confluencecloud.list_users()
    ```
    """

    # Inherits all methods from Base class
    # No additional methods or properties are defined here
    @api_call
    def list_group_members(
        self, group_name: str, expand: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Return members of a group.

        # Required parameters

        - group_name: a non-empty string

        # Optional parameters

        - expand: a comma-separated string of fields to expand.
        Possible values are: `operations`, `personalSpace`

        # Returned value

        A list of dictionaries, each representing a user.
        Please refer to #get_user() for more.
        """
        ensure_nonemptystring('group_name')
        ensure_noneorinstance('expand', list)

        grp = self.get_group(group_name)
        if not grp or not grp.get('id'):
            raise ApiError(f"Group '{group_name}' not found")
        group_id = grp['id']

        return self.list_group_members_by_id(
            group_id, limit=200, expand=expand
        )
