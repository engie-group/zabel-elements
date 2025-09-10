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
    Tuple,
    Union,
)

import requests

from zabel.commons.sessions import prepare_session
from zabel.commons.utils import (
    api_call,
    ensure_nonemptystring,
    ensure_noneorinstance,
    ensure_noneornonemptystring,
    ensure_onlyone,
    join_url,
    BearerAuth,
)


########################################################################
########################################################################

# Atlassian Cloud low-level api


class Atlassian:
    """Atlassian Low-Level Wrapper.

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
        *,
        basic_auth: Optional[Tuple[str, str]] = None,
        bearer_auth: Optional[str] = None,
    ) -> None:
        """Create an Atlassian instance object.

        You can specify either `basic_auth` or `bearer_auth`.

        # Required parameters

        - url: a non-empty string
        - basic_auth: a strings tuple (user, token)
        - bearer_auth: a string

        # Usage

        `url` is the top-level API endpoint.  For example:

            'https://api.atlassian.com/admin/v1/'
        """
        ensure_nonemptystring('url')
        ensure_onlyone('bearer_auth', 'basic_auth')
        ensure_noneornonemptystring('bearer_auth')
        ensure_noneorinstance('basic_auth', tuple)

        self.url = url
        self.basic_auth = basic_auth
        self.bearer_auth = bearer_auth

        if basic_auth is not None:
            self.auth = basic_auth
        if bearer_auth is not None:
            self.auth = BearerAuth(bearer_auth)
        self.session = prepare_session(self.auth)

    def __str__(self) -> str:
        return f'{self.__class__.__name__}: {self.url}'

    def __repr__(self) -> str:
        if self.basic_auth:
            rep = self.basic_auth[0]
        elif self.bearer_auth:
            rep = f'***{self.bearer_auth[-6:]}'
        return f'<{self.__class__.__name__}: {self.url!r}, {rep!r}>'

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

        return self._get(f'orgs/{org_id}/users')  # type: ignore

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

    @api_call
    def search_site_user(self, site_url: str, query: str) -> Dict[str, Any]:
        """Search for site user details.

        # Required parameters

        - site_url: a non-empty string
        - query: a non-empty string

        # Returned value

        A _user_.  See #list_site_users() for details on its structure.
        """
        ensure_nonemptystring('site_url')
        ensure_nonemptystring('query')
        params = {'query': query}

        api_url = join_url(site_url, 'rest/api/3/user/search')
        return self.session().get(api_url, params=params)

    get_user = search_site_user

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
