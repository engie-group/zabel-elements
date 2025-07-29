"""
ConfluenceCloud client module providing access to Confluence Cloud API.
"""

from .base.confluencecloud import ConfluenceCloud as Base


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
