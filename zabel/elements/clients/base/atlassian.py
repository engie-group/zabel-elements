"""Atlassian.

A base class wrapping Atlassian cloud APIs.

This module depends on the public **requests** library.  It also depends
on three **zabel-commons** modules, #::zabel.commons.exceptions,
#::zabel.commons.sessions, and #::zabel.commons.utils.

A base class wrapper only implements 'simple' API requests.  It handles
pagination if appropriate, but does not process the results or compose
API requests.
"""

from typing import (
    Any,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Union,
)

import requests
from zabel.commons.sessions import prepare_session
from zabel.commons.utils import (
    api_call,
    ensure_nonemptystring,
    join_url,
    BearerAuth,
)

########################################################################
########################################################################


# Atlassian Cloud low-level api


class Atlassian:
    """Atlassian Base-Level Wrapper.

    ## Reference URLs

    - <https://developer.atlassian.com/cloud/admin>

    ## Implemented features

    - users

    ## Examples

    ```python
    from zabel.elements.clients import Atlassian

    url = 'https://api.atlassian.com/admin'
    token = '...'
    atlassian = Atlassian(url, bearer_auth=token)
    atlassian.list_organization_users('your-organization-id')
    ```
    """

    def __init__(
        self,
        url: str,
        bearer_auth: str,
    ) -> None:
        """Create an Atlassian instance object.

        # Required parameters

        - url: a non-empty string
        - bearer_auth: a string

        # Usage

        `url` is the top-level API endpoint.  For example:

            'https://api.atlassian.com/admin/v1/'
        """
        ensure_nonemptystring('url')
        ensure_nonemptystring('bearer_auth')

        self.url = url
        self.bearer_auth = BearerAuth(bearer_auth)
        self.session = prepare_session(self.bearer_auth)

    def __str__(self) -> str:
        return f'{self.__class__.__name__}: {self.url}'

    def __repr__(self) -> str:
        auth = self.bearer_auth.pat[:10] + '...' + self.bearer_auth.pat[-10:]
        return f'<{self.__class__.__name__}: {self.url!r}, {auth!r}>'

    ####################################################################
    # atlassian users
    #
    # list_organization_users

    @api_call
    def list_organization_users(self, org_id: str) -> List[Dict[str, Any]]:
        """List organization users.

        # Required parameters

        - org_id: a string

        # Returned value

        A list of _users_.  Each user is a dictionary with the
        following entries:

        - `account_id`: a string
        - `account_type`: a string
        - `account_status`: a string
        - `name`: a string
        - `email`: a string
        - `access_billable`: a boolean
        - `product_access`: a list of strings
        - `links`: a dictionary
        """
        ensure_nonemptystring('org_id')

        return self._get(f'orgs/{org_id}/users')

    ####################################################################
    # atlassian sites

    @api_call
    def list_site_users(self, site_url: str) -> List[Dict[str, Any]]:
        """List site users.

        # Required parameters

        - site_url: a non-empty string (of the form `https://...`)

        # Returned value

        A list of _users_.  Each user is a dictionary with the
        following entries:

        - `accountId`: a string
        - `accountType`: a string
        - `emailAddress`: a string
        - `avatarUrls`: a dictionary
        - `displayName`: a string
        - `active`: a boolean
        - `locale`: a string
        """
        ensure_nonemptystring('site_url')

        api_url = join_url(site_url, 'rest/api/3/users/search')
        return self.session().get(api_url)

    ####################################################################
    # atlassian private helpers

    def _get(
        self,
        api: str,
        params: Optional[
            Mapping[str, Union[str, Iterable[str], int, bool]]
        ] = None,
    ) -> requests.Response:
        """Return atlassian api call results, as Response."""
        api_url = join_url(self.url, api)
        return self.session().get(api_url, params=params)
