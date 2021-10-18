# Copyright (c) 2019 Martin Lafaix (martin.lafaix@external.engie.com)
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

"""Jira.

A class wrapping Jira APIs.

There can be as many Jira instances as needed.

This module depends on the public **requests** and **jira.JIRA**
libraries.  It also depends on two **zabel-commons** modules,
#::zabel.commons.exceptions and #::zabel.commons.utils.
"""

from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, Union

import json
import re

from urllib.parse import urlencode

import requests

from zabel.commons.exceptions import ApiError
from zabel.commons.utils import (
    add_if_specified,
    api_call,
    ensure_in,
    ensure_instance,
    ensure_nonemptystring,
    ensure_noneorinstance,
    ensure_onlyone,
    join_url,
)


########################################################################
########################################################################

REINDEX_KINDS = [
    'FOREGROUND',
    'BACKGROUND',
    'BACKGROUND_PREFFERED',
    'BACKGROUND_PREFERRED',
]

PERMISSIONSCHEME_EXPAND = 'permissions,user,group,projectRole,field,all'
NOTIFICATIONSCHEME_EXPAND = (
    'notificationSchemeEvents,user,group,projectRole,field,all'
)
PROJECT_EXPAND = 'description,lead,url,projectKeys'
USER_EXPAND = 'groups,applicationRoles'


# Helpers


def _get_atl_token(html: str) -> str:
    atl_token = html[html.find('"atl_token"') :]
    atl_token = atl_token[atl_token.find('value="') + 7 :]
    return atl_token[: atl_token.find('"')]


def _get_scheme_id(
    name_or_id: Union[int, str], schemes: Iterable[Mapping[str, Any]]
) -> str:
    if isinstance(name_or_id, str):
        matches = [s['id'] for s in schemes if s['name'] == name_or_id]
        if len(matches) != 1:
            raise ApiError('Scheme %s not found.' % name_or_id)
        return str(matches.pop())
    if not any(str(s['id']) == str(name_or_id) for s in schemes):
        raise ApiError('Scheme ID %s not found.' % str(name_or_id))
    return str(name_or_id)


class BearerAuth(requests.auth.AuthBase):
    """A Bearer handler class for requests."""

    def __init__(self, pat: str):
        self.pat = pat

    def __eq__(self, other):
        return self.pat == getattr(other, 'pat', None)

    def __ne__(self, other):
        return not self == other

    def __call__(self, r):
        r.headers['Authorization'] = f'Bearer {self.pat}'
        return r


# JIRA low-level api


class Jira:
    """JIRA Low-Level Wrapper.

    Reference URL:

    <https://docs.atlassian.com/jira/REST/server/>
    <https://docs.atlassian.com/software/jira/docs/api/REST/8.7.1>
    <https://docs.atlassian.com/jira-servicedesk/REST/4.9.0/>

    Agile reference:

    <https://docs.atlassian.com/jira-software/REST/8.7.1/>

    Using the python library:

    <http://jira.readthedocs.io/en/latest/>

    Plus the various WADLS, such as:

    <https://jira.example.com/rest/greenhopper/1.0/application.wadl>
    <https://jira.example.com/rest/bitbucket/1.0/application.wadl>

    Implemented features:

    - search
    - groups
    - permissionschemes
    - projects
    - users
    - boards
    - sprints
    - issues
    - servicedesk
    - misc. features (reindexing, plugins, xray, & server info)

    Works with basic authentication as well as OAuth authentication.

    It is the responsibility of the user to be sure the provided
    authentication has enough rights to perform the requested operation.

    # Sample use

    ```python
    >>> from zabel.elements.clients import Jira
    >>>
    >>> url = 'https://jira.example.com'
    >>> jc = Jira(url, basic_auth=(user, token))
    >>> jc.list_users()
    ```

    !!! note
        Reuse the JIRA library whenever possible, but always returns
        'raw' values (dictionaries, ..., not classes).
    """

    def __init__(
        self,
        url: str,
        basic_auth: Optional[Tuple[str, str]] = None,
        oauth: Optional[Dict[str, str]] = None,
        bearer_auth: Optional[str] = None,
        verify: bool = True,
    ) -> None:
        """Create a Jira instance object.

        You can only specify either `basic_auth`, `oauth`, or 'bearer_auth`.

        # Required parameters

        - url: a string
        - basic_auth: a strings tuple (user, token)
        - oauth: a dictionary
        - bearer_auth: a string

        The `oauth` dictionary is expected to have the following
        entries:

        - access_token: a string
        - access_token_secret: a string
        - consumer_key: a string
        - key_cert: a string

        # Optional parameters

        - verify: a boolean (True by default)

        `verify` can be set to False if disabling certificate checks for
        Jira communication is required.  Tons of warnings will occur if
        this is set to False.
        """
        ensure_nonemptystring('url')
        ensure_onlyone('basic_auth', 'oauth', 'bearer_auth')
        ensure_noneorinstance('basic_auth', tuple)
        ensure_noneorinstance('oauth', dict)
        ensure_noneorinstance('bearer_auth', str)
        ensure_instance('verify', bool)

        self.url = url
        self.basic_auth = basic_auth
        self.oauth = oauth
        self.bearer_auth = bearer_auth

        if basic_auth is not None:
            self.auth = basic_auth
        if oauth is not None:
            from requests_oauthlib import OAuth1
            from oauthlib.oauth1 import SIGNATURE_RSA

            self.auth = OAuth1(
                oauth['consumer_key'],
                'dont_care',
                oauth['access_token'],
                oauth['access_token_secret'],
                signature_method=SIGNATURE_RSA,
                rsa_key=oauth['key_cert'],
                signature_type='auth_header',
            )
        if bearer_auth is not None:
            self.auth = BearerAuth(bearer_auth)

        self.client = None
        self.verify = verify
        self.UPM_BASE_URL = join_url(url, 'rest/plugins/1.0/')
        self.AGILE_BASE_URL = join_url(url, 'rest/agile/1.0/')
        self.GREENHOPPER_BASE_URL = join_url(url, 'rest/greenhopper/1.0/')
        self.SERVICEDESK_BASE_URL = join_url(url, 'rest/servicedeskapi/')
        self.SDBUNDLE_BASE_URL = join_url(url, 'rest/jsdbundled/1.0')
        self.XRAY_BASE_URL = join_url(url, 'rest/raven/1.0')

    def __str__(self) -> str:
        return f'{self.__class__.__name__}: {self.url}'

    def __repr__(self) -> str:
        if self.basic_auth:
            rep = self.basic_auth[0]
        elif self.oauth:
            rep = self.oauth['consumer_key']  # type: ignore
        else:
            rep = f'Bearer {self.bearer_auth[:5]}...{self.bearer_auth[-2:]}'
        return f'<{self.__class__.__name__}: {self.url!r}, {rep!r}>'

    def _client(self) -> 'jira.JIRA':
        """singleton instance, only if needed."""
        if self.client is None:
            from jira import JIRA

            options = {
                'server': self.url,
                'agile_rest_path': 'agile',
                'verify': self.verify,
            }
            if self.bearer_auth:
                options['headers'] = {
                    'Authorization': f'Bearer {self.bearer_auth}'
                }
            self.client = JIRA(
                options=options,
                basic_auth=self.basic_auth,
                oauth=self.oauth,
            )
        return self.client

    ####################################################################
    # JIRA search
    #
    # search

    @api_call
    def search(
        self,
        jql: str,
        start_at: Optional[int] = None,
        max_results: Optional[int] = None,
        validate_query: bool = True,
        fields: Optional[List[str]] = None,
        expand: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return the result of a query.

        # Required parameters

        - jql: a string

        # Optional parameters

        - start_at: an integer or None (None by default)
        - max_results: an integer or None (None by default)
        - validate_query: a boolean (True by default)
        - fields: a list of strings or None (None by default)
        - expand: a string or None (None by default)

        `max_results` is limited by the `jira.search.views.default.max`
        property, and hence requesting a high number of results may
        result in fewer returned results.

        # Returned value

        A dictionary with the following entries:

        - expand: a string
        - startAt: an integer
        - maxResults: an integer
        - total: an integer
        - issues: a list of dictionaries

        The entries in `issues` items depends on what was specified for
        `expand`.

        Assuming the default `expand` value, items in `issues` contain
        the following entries:

        - id: an integer
        - expand: a string
        - self: a string
        - key: a string
        - fields: a dictionary

        The entries in `fields` depends on the issue type.
        """
        ensure_instance('jql', str)
        ensure_noneorinstance('start_at', int)
        ensure_noneorinstance('max_results', int)
        ensure_instance('validate_query', bool)
        ensure_noneorinstance('fields', list)
        ensure_noneorinstance('expand', str)

        params = {'jql': jql, 'validateQuery': validate_query}
        add_if_specified(params, 'startAt', start_at)
        add_if_specified(params, 'maxResults', max_results)
        add_if_specified(params, 'fields', fields)
        add_if_specified(
            params, 'expand', expand.split(',') if expand is not None else None
        )

        result = self._post('search', json=params)
        return result  # type: ignore

    ####################################################################
    # JIRA groups
    #
    # list_groups
    # delete_group
    # create_group
    # add_group_user
    # list_group_users
    # remove_group_user

    @api_call
    def list_groups(self) -> List[str]:
        """Return the list of groups.

        # Returned value

        A list of strings, each string being a group name.
        """
        return self._client().groups()

    @api_call
    def create_group(self, group_name: str) -> bool:
        """Create a new group.

        # Required parameters

        - group_name: a non-empty string

        # Returned value

        A boolean.  True if successful, False otherwise.
        """
        ensure_nonemptystring('group_name')

        return self._client().add_group(group_name)

    @api_call
    def delete_group(self, group_name: str) -> bool:
        """Delete group.

        # Required parameters

        - group_name: a non-empty string

        # Returned value

        A boolean.  True if successful, False otherwise.
        """
        ensure_nonemptystring('group_name')

        return self._client().remove_group(group_name)

    @api_call
    def add_group_user(
        self, group_name: str, user_name: str
    ) -> Union[bool, Dict[str, Any]]:
        """Add user to group.

        # Required parameters

        - group_name: a non-empty string
        - user_name: a non-empty string

        # Returned value

        False if the operation failed, a dictionary otherwise.
        """
        ensure_nonemptystring('group_name')
        ensure_nonemptystring('user_name')

        return self._client().add_user_to_group(user_name, group_name)

    @api_call
    def remove_group_user(self, group_name: str, user_name: str) -> bool:
        """Remove user from group.

        # Required parameters

        - group_name: a non-empty string
        - username: a non-empty string

        # Returned value

        A boolean, True.
        """
        ensure_nonemptystring('group_name')
        ensure_nonemptystring('user_name')

        return self._client().remove_user_from_group(user_name, group_name)

    @api_call
    def list_group_users(self, group_name: str) -> Dict[str, Any]:
        """Return the group users.

        # Required parameters

        - group_name: a non-empty string

        # Returned value

        A dictionary.  Keys are the user names, and values are
        dictionaries with the following entries:

        - active: a boolean
        - fullname: a string
        - email: a string
        """
        ensure_nonemptystring('group_name')

        return self._client().group_members(group_name)

    ####################################################################
    # JIRA permission scheme
    #
    # list_permissionschemes
    # get_permissionscheme
    # create_permissionscheme
    # update_permissionscheme
    # delete_permissionscheme
    # list_permissionscheme_grants

    @api_call
    def list_permissionschemes(
        self, expand: str = PERMISSIONSCHEME_EXPAND
    ) -> List[Dict[str, Any]]:
        """Return the list of permissionschemes.

        # Optional parameters

        - expand: a string (`PERMISSIONSCHEME_EXPAND` by default)

        # Returned value

        A list of _permissionschemes_.  Each permissionscheme is a
        dictionary with the following entries (assuming the default for
        `expand`):

        - id: an integer
        - expand: a string
        - name: a string
        - self: a string
        - description: a string
        - permissions: a list of dictionaries

        Each `permissions` dictionary has the following entries:

        - permission: a string
        - id: an integer
        - holder: a dictionary
        - self: a string

        The `holder` dictionary has the following entries

        - type: a string
        - group: a dictionary
        - expand: a string
        - parameter: a string

        The `group` dictionary has the following entries

        - self: a string
        - name: a string
        """
        ensure_instance('expand', str)

        result = self._get_json('permissionscheme', params={'expand': expand})
        return result['permissionSchemes']  # type: ignore

    @api_call
    def get_permissionscheme(
        self, scheme_id: int, expand: str = PERMISSIONSCHEME_EXPAND
    ) -> Dict[str, Any]:
        """Return permission scheme details.

        # Required parameters

        - scheme_id: an integer

        # Optional parameters

        - expand: a string (`PERMISSIONSCHEME_EXPAND` by default)

        # Returned value

        A dictionary.  See #get_permissionschemes() for details
        on its structure.
        """
        ensure_instance('scheme_id', int)

        result = self._get_json(
            f'permissionscheme/{scheme_id}', params={'expand': expand}
        )
        return result  # type: ignore

    @api_call
    def create_permissionscheme(
        self,
        name: str,
        description: Optional[str] = None,
        permissions: List[Dict[str, Any]] = [],
    ) -> Dict[str, Any]:
        """Create new permission scheme.

        # Required parameters

        - name: a non-empty string

        # Optional parameters

        - description: a string or None (None by default)
        - permissions: a possibly empty list of dictionaries (`[]` by
          default)

        # Returned value

        If successful, returns a dictionary containing:

        - name
        - id
        - expand
        - self

        # Raised exceptions

        Raises an _ApiError_ in case of problem (duplicate permission
        scheme, invalid permissions, ...).
        """
        ensure_nonemptystring('name')
        ensure_noneorinstance('description', str)
        ensure_instance('permissions', list)

        scheme = {'name': name, 'permissions': permissions}
        add_if_specified(scheme, 'description', description)

        result = self.session().post(
            self._get_url('permissionscheme'), data=json.dumps(scheme)
        )
        return result  # type: ignore

    @api_call
    def update_permissionscheme(
        self, scheme_id: int, scheme: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update permission scheme scheme_id.

        # Required parameters

        - scheme_id: an integer
        - scheme: a dictionary

        # Returned value

        A dictionary.  See #get_permissionschemes() for details on its
        structure.
        """
        ensure_instance('scheme_id', int)
        ensure_instance('scheme', dict)

        result = self.session().put(
            self._get_url(f'permissionscheme/{scheme_id}'),
            data=json.dumps(scheme),
        )
        return result  # type: ignore

    @api_call
    def delete_permissionscheme(self, scheme_id: int) -> Dict[str, Any]:
        """Delete permission scheme scheme_id.

        # Required parameters

        - scheme_id: an integer

        # Returned value

        An empty dictionary if successful.
        """
        ensure_instance('scheme_id', int)

        result = self.session().delete(
            self._get_url(f'permissionscheme/{scheme_id}')
        )
        return result  # type: ignore

    @api_call
    def list_permissionscheme_grants(
        self, scheme_id: int
    ) -> List[Dict[str, Any]]:
        """Return list of permission grants.

        # Required parameters

        - scheme_id: an integer

        # Returned value

        A list of _permission grants_.  Each permission grant is a
        dictionary with the following entries:

        - id: an integer
        - holder: a dictionary
        - permission: a string

        `holder` contains the following entries:

        - parameter: a string
        - type: a string
        """
        ensure_instance('scheme_id', int)

        result = self._get_json(f'permissionscheme/{scheme_id}/permission')
        return result['permissions']  # type: ignore

    ####################################################################
    # JIRA misc. schemes
    #
    # getters suffixed with a '+' add a `active` entry in their returned
    # values.
    #
    # list_issuetypeschemes+
    # delete_issuetypescheme (for pre-8 JIRA versions)
    # list_issuetypescreenschemes+
    # delete_issuetypescreenscheme
    # list_notificationschemes
    # list_inactivenotificationschemes
    # delete_notificationscheme
    # list_priorityschemes+
    # delete_priorityscheme
    # list_fieldconfigurationschemes+
    # delete_fieldconfigurationscheme
    # list_fieldconfigurations+
    # delete_fieldconfiguration
    # list_workflows
    # delete_workflow
    # list_workflowschemes+
    # delete_workflowscheme
    # list_screens+
    # delete_screen
    # list_screenschemes+
    # delete_screenscheme

    # issuetypeschemes

    @api_call
    def list_issuetypeschemes(self) -> List[Dict[str, Any]]:
        """Return the list of issue type schemes.

        # Returned value

        A list of _issuetypeschemes_.  Each issuetypeschemes is a
        dictionary with the following entries:

        - name: a string
        - id: an integer or a string
        - active: a boolean
        """
        uri = 'secure/admin/ManageIssueTypeSchemes!default.jspa'
        pat_name = r'data-scheme-field="name">([^<]+)<'
        pat_id = r'&schemeId=(\d+)">Edit</a>'
        pat_inactive = (
            r'<span class="errorText">No projects</span>\s+'
            r'</td>\s+<td class="cell-type-collapsed">\s+'
            r'<ul class="operations-list">\s+<li><a id="edit_%s"'
        )
        return self._parse_data(uri, pat_name, pat_id, pat_inactive)

    @api_call
    def delete_issuetypescheme(
        self, scheme_id_or_name: Union[int, str]
    ) -> None:
        """Delete issuetypescheme.

        # Required parameters

        - scheme_id_or_name: a integer or a non-empty string

        # Returned value

        None.

        # Raised exceptions

        _ApiError_ if `scheme_id_or_name` is invalid or something wrong
        occured.
        """
        ensure_instance('scheme_id_or_name', (int, str))

        scheme_id = _get_scheme_id(
            scheme_id_or_name, self.list_issuetypeschemes()
        )

        uri = (
            'secure/admin/DeleteOptionScheme!default.jspa?fieldId=&schemeId=%s'
        )
        form = self._get(uri % scheme_id)
        self._do_form_step(
            'secure/admin/DeleteOptionScheme.jspa',
            data={
                'atl_token': _get_atl_token(form.text),
                'schemeId': scheme_id,
            },
            cookies=form.cookies,
        )

    # issuetypescreenschemes

    @api_call
    def list_issuetypescreenschemes(self) -> List[Dict[str, Any]]:
        """Return the list of issuetypescreenschemes.

        # Returned value

        A list of _issuetypescreenschemes_.  Each issuetypescreenscheme
        is a dictionary with the following entries:

        - id: an integer or a string
        - name: a string
        - active: a boolean

        `active` is true if the scheme is associated with at least one
        project.
        """
        uri = 'secure/admin/ViewIssueTypeScreenSchemes.jspa'
        pat_name = r'<strong\s+data-scheme-field="name">([^<]+)<'
        pat_id = r'id=(\d+)[^<]*>\s*<strong\s+data-scheme-field'
        pat_inactive = (
            r'ViewDeleteIssueTypeScreenScheme.jspa\?[^>]+&amp;id=%s"'
        )
        return self._parse_data(uri, pat_name, pat_id, pat_inactive)

    @api_call
    def delete_issuetypescreenscheme(
        self, scheme_id_or_name: Union[int, str]
    ) -> None:
        """Delete issuetypescreenscheme.

        # Required parameters

        - scheme_id_or_name: an integer or a string

        # Returned value

        None.

        # Raised exceptions

        _ApiError_ if `scheme_id_or_name` is invalid or the scheme is
        active.
        """
        ensure_instance('scheme_id_or_name', (int, str))

        scheme_id = _get_scheme_id(
            scheme_id_or_name, self.list_issuetypescreenschemes()
        )

        uri = 'secure/admin/ViewIssueTypeScreenSchemes.jspa'
        page = self._get(uri)
        atl_token = re.search(
            r'ViewDeleteIssueTypeScreenScheme.jspa\?atl_token=([^&]+)&amp;id=%s"'
            % scheme_id,
            page.text,
        )

        if not atl_token:
            raise ApiError('Scheme %s is active.' % str(scheme_id_or_name))

        self._do_form_step(
            'secure/admin/DeleteIssueTypeScreenScheme.jspa',
            data={
                'id': scheme_id,
                'confirm': 'true',
                'atl_token': atl_token.group(1),
            },
            cookies=page.cookies,
        )

    # screens

    @api_call
    def list_screens(self) -> List[Dict[str, Any]]:
        """Return the list of screens.

        # Returned value

        A list of _screens_.  Each screen is a dictionary with the
        following entries:

        - id: an integer or a string
        - name: a string
        - active: a boolean

        `active` is true if the screen is not part of a Screen Scheme
        and is not used in any workflow.
        """
        uri = 'secure/admin/ViewFieldScreens.jspa'
        pat_name = r'<td>\s*<strong\s+class="field-screen-name">([^<]+)<'
        pat_id = r'data-field-screen-id="(\d+)">\s*<td>\s*<strong'
        pat_inactive = r'ViewDeleteFieldScreen.jspa\?id=%s"'
        return self._parse_data(uri, pat_name, pat_id, pat_inactive)

    @api_call
    def delete_screen(self, screen_id_or_name: Union[int, str]) -> None:
        """Delete screen.

        # Required parameters

        - scheme_id_or_name: a non-empty string

        # Returned value

        None.
        """
        ensure_instance('screen_id_or_name', (int, str))

        scheme_id = _get_scheme_id(screen_id_or_name, self.list_screens())

        uri = 'secure/admin/ViewDeleteFieldScreen.jspa?id=%s'
        form = self._get(uri % scheme_id)
        self._do_form_step(
            'secure/admin/DeleteFieldScreen.jspa',
            data={
                'id': scheme_id,
                'confirm': 'true',
                'atl_token': _get_atl_token(form.text),
            },
            cookies=form.cookies,
        )

    # screenschemes

    @api_call
    def list_screenschemes(self) -> List[Dict[str, Any]]:
        """Return the list of screenschemes.

        # Returned value

        A list of _screenschemes_.  Each screenscheme is a dictionary
        with the following entries:

        - id: an integer or a string
        - name: a string
        - active: a boolean

        `active` is true if the screen scheme is used in an Issue Type
        Screen Scheme.
        """
        uri = 'secure/admin/ViewFieldScreenSchemes.jspa'
        pat_name = r'class="field-screen-scheme-name">([^<]+)</strong>'
        pat_id = r'ConfigureFieldScreenScheme.jspa\?id=(\d+)"'
        pat_inactive = r'ViewDeleteFieldScreenScheme.jspa\?id=%s"'
        return self._parse_data(uri, pat_name, pat_id, pat_inactive)

    @api_call
    def delete_screenscheme(self, scheme_id_or_name: Union[int, str]) -> None:
        """Delete screenscheme.

        # Required parameters

        - scheme_id_or_name: a non-empty string

        # Returned value

        None.
        """
        ensure_instance('scheme_id_or_name', (int, str))

        scheme_id = _get_scheme_id(
            scheme_id_or_name, self.list_screenschemes()
        )

        uri = 'secure/admin/ViewDeleteFieldScreenScheme.jspa?id=%s'
        form = self._get(uri % scheme_id)
        self._do_form_step(
            'secure/admin/DeleteFieldScreenScheme.jspa',
            data={
                'id': scheme_id,
                'confirm': 'true',
                'atl_token': _get_atl_token(form.text),
            },
            cookies=form.cookies,
        )

    # notificationschemes

    @api_call
    def list_notificationschemes(
        self, expand: str = NOTIFICATIONSCHEME_EXPAND
    ) -> List[Dict[str, Any]]:
        """Return the list of notificationschemes.

        # Optional parameters

        - expand: a string (`NOTIFICATIONSCHEME_EXPAND` by default)

        # Returned value

        A list of _notificationschemes_.  Each notificationscheme is a
        dictionary with the following entries (assuming the default for
        `expand`):

        - id: an integer
        - expand: a string
        - name: a string
        - self: a string
        - description: a string
        - notificationSchemeEvents: a list of dictionaries

        Each `notificationSchemeEvents` dictionary has the following
        entries:

        - event: a dictionary
        - notifications: a list of dictionaries

        The `event` dictionaries have the following entries:

        - id: an integer
        - name: a string
        - description: a string

        The `notifications` dictionaries have the following entries:

        - id: an integer
        - notificationType: a string

        They may have other entries depending on their
        `notificationType`.
        """
        ensure_instance('expand', str)

        return self._collect_data(
            'notificationscheme', params={'expand': expand}
        )

    @api_call
    def list_inactivenotificationschemes(self) -> List[Dict[str, Any]]:
        """Returns the id of inactive notification schemes.

        A notification scheme is said to be inactive if it is not used
        by any project.

        # Returned value

        A list of inactive _notificationschemes_.  Each
        notificationschemes is a dictionary with the following entries:

        - id: an integer
        - name: a string
        """
        uri = 'secure/admin/ViewNotificationSchemes.jspa'
        pat_name = r'<a href="EditNotifications!default.jspa.*?&amp;schemeId=\d+">([^<]+)<'
        pat_id = (
            r'<a href="EditNotifications!default.jspa.*?&amp;schemeId=(\d+)">'
        )
        pat_inactive = (
            r'&nbsp;\s+</td>\s+<td>\s+'
            r'<ul class="operations-list">\s+<li><a id="%s_'
        )
        return [
            {'id': scheme['id'], 'name': scheme['name']}
            for scheme in self._parse_data(uri, pat_name, pat_id, pat_inactive)
            if not scheme['active']
        ]

    @api_call
    def delete_notificationscheme(self, scheme_id: Union[int, str]) -> None:
        """Delete notification scheme.

        # Required parameters

        - scheme_id: either an integer or a string

        # Returned value

        None.

        # Raised exceptions

        _ApiError_ if the scheme does not exist.
        """
        scheme_id = str(scheme_id)
        ensure_nonemptystring('scheme_id')

        uri = 'secure/admin/ViewNotificationSchemes.jspa'
        page = self._get(uri)
        atl_token = re.search(
            r'<a href="EditNotifications!default.jspa\?atl_token=([^&]+)&amp;schemeId=%s">'
            % scheme_id,
            page.text,
        )

        if not atl_token:
            raise ApiError(
                'Notification Scheme %s could not be found.' % scheme_id
            )

        self._do_form_step(
            'secure/admin/DeleteNotificationScheme.jspa',
            data={
                'schemeId': scheme_id,
                'Delete': 'Delete',
                'confirmed': 'true',
                'atl_token': atl_token.group(1),
            },
            cookies=page.cookies,
        )

    # priority schemes

    @api_call
    def list_priorityschemes(self) -> List[Dict[str, Any]]:
        """Return the list of priorityschemes.

        # Returned value

        A list of _priorityschemes_.  Each priorityscheme is a
        dictionary with the following entries:

        - id: an integer
        - name: a string
        - active: a boolean

        `active` is true if the priority scheme is used in any project.
        """
        uri = 'secure/admin/ViewPrioritySchemes.jspa'
        pat_name = r'<strong data-scheme-field="name">([^<]+)</strong>'
        pat_id = r'<tr data-id="(\d+)"'
        pat_inactive = (
            r'<span class="errorText">No projects</span>'
            r'</td><td class="cell-type-collapsed">'
            r'<ul class="operations-list"><li><a id="\w+_%s"'
        )

        return self._parse_data(uri, pat_name, pat_id, pat_inactive)

    @api_call
    def delete_priorityscheme(self, scheme_id: Union[int, str]) -> None:
        """Delete priority scheme.

        # Required parameters

        - scheme_id: either an integer or a string

        # Returned value

        None.

        # Raised exceptions

        _ApiError_ if the scheme does not exist.
        """
        scheme_id = str(scheme_id)
        ensure_nonemptystring('scheme_id')

        uri = 'secure/admin/ViewPrioritySchemes.jspa'
        page = self._get(uri)
        atl_token = re.search(r'/logout\?atl_token=([^"]+)"', page.text)

        if not atl_token:
            raise ApiError(
                'Priority Scheme %s could not be found.' % scheme_id
            )

        self._do_form_step(
            'secure/admin/DeletePriorityScheme.jspa',
            data={
                'schemeId': scheme_id,
                'decorator': 'dialog',
                'inline': 'true',
                'atl_token': atl_token.group(1),
            },
            cookies=page.cookies,
        )

    # field configuration fields

    @api_call
    def list_fieldconfigurationschemes(self) -> List[Dict[str, Any]]:
        """Return the list of field configuration schemes.

        # Returned value

        A list of _fieldconfigurationschemes_.  Each
        fieldconfigurationschemes is a dictionary with the following
        entries:

        - id: an integer
        - name: a string
        - active: a boolean

        `active` is true if the field configuration scheme is used in
        any project.
        """
        uri = 'secure/admin/ViewFieldLayoutSchemes.jspa'
        pat_name = r'<strong data-scheme-field="name">([^<]+)</strong>'
        pat_id = r'<a id="configure_(\d+)" data-operation="configure"'
        pat_inactive = (
            r'&nbsp;\s+</td>\s+<td>\s+'
            r'<ul class="operations-list">\s+<li><a id="\w+_%s"'
        )

        return self._parse_data(uri, pat_name, pat_id, pat_inactive)

    @api_call
    def delete_fieldconfigurationscheme(
        self, scheme_id: Union[int, str]
    ) -> None:
        """Delete field configuration scheme.

        # Required parameters

        - scheme_id: either an integer or a string

        # Returned value

        None.

        # Raised exceptions

        _ApiError_ if the scheme does not exist.
        """
        scheme_id = str(scheme_id)
        ensure_nonemptystring('scheme_id')

        uri = 'secure/admin/ViewFieldLayoutSchemes.jspa'
        page = self._get(uri)
        atl_token = re.search(
            r'atl_token=([^&]+)&amp;id=%s" title="Delete this scheme">'
            % scheme_id,
            page.text,
        )

        if not atl_token:
            raise ApiError(
                'Field Configuration Scheme %s could not be found.' % scheme_id
            )

        self._do_form_step(
            'secure/admin/DeleteFieldLayoutScheme.jspa',
            data={
                'id': scheme_id,
                'confirm': 'true',
                'Delete': 'Delete',
                'atl_token': atl_token.group(1),
            },
            cookies=page.cookies,
        )

    # field configurations

    @api_call
    def list_fieldconfigurations(self) -> List[Dict[str, Any]]:
        """Return the list of field configurations.

        # Returned value

        A list of _fieldconfigurations_.  Each fieldconfigurations is a
        dictionary with the following entries:

        - id: an integer
        - name: a string
        - active: a boolean

        `active` is true if the field configuration scheme is used in
        any project.
        """
        uri = 'secure/admin/ViewFieldLayouts.jspa'
        pat_name = r'<span data-scheme-field="name" class="field-name">\s+.*?title="Edit field properties">([^<]+)'
        pat_id = r';id=(\d+)" title="Create a copy of '
        pat_inactive = (
            r'<td>\s+</td>\s+<td>\s+<ul class="operations-list">'
            r'\s+<li><a[^>]+?;id=%s"'
        )

        return self._parse_data(uri, pat_name, pat_id, pat_inactive)

    @api_call
    def delete_fieldconfiguration(self, conf_id: Union[int, str]) -> None:
        """Delete field configuration.

        # Required parameters

        - conf_id: either an integer or a string

        # Returned value

        None.

        # Raised exceptions

        _ApiError_ if the field configuration does not exist.
        """
        conf_id = str(conf_id)
        ensure_nonemptystring('conf_id')

        uri = 'secure/admin/ViewFieldLayouts.jspa'
        page = self._get(uri)
        atl_token = re.search(
            r'atl_token=([^&]+)&amp;id=%s" title="Create a copy ' % conf_id,
            page.text,
        )

        if not atl_token:
            raise ApiError(
                'Field Configuration %s could not be found.' % conf_id
            )

        self._do_form_step(
            'secure/admin/DeleteFieldLayout.jspa',
            data={
                'id': conf_id,
                'confirm': 'true',
                'Delete': 'Delete',
                'atl_token': atl_token.group(1),
            },
            cookies=page.cookies,
        )

    # workflows

    @api_call
    def list_workflows(self) -> List[Dict[str, Any]]:
        """Return the list of workflows.

        # Returned value

        A list of _workflows_.  Each workflow is a dictionary with the
        following entries:

        - name: a string
        - description: a string
        - lastModifiedDate: a string (local format)
        - lastModifiedUser: a string (display name)
        - steps: an integer
        - default: a boolean
        """
        return self._get_json('workflow')  # type: ignore

    @api_call
    def list_inactiveworkflows(self) -> List[str]:
        """Return the list of inactive workflows.

        # Returned value

        A list of _workflow names_.
        """
        page = self._get('secure/admin/workflows/ListWorkflows.jspa')
        inactives = page.text.split('<table id="inactive-workflows-table"')
        if len(inactives) == 1:
            return []
        return re.findall(r'<tr data-workflow-name="([^"]+)">', inactives[1])

    @api_call
    def delete_workflow(self, workflow_name: str) -> None:
        """Delete worflow.

        # Required parameters

        - workflow_name: a non-empty string

        # Returned value

        None.

        # Raised exceptions

        _ApiError_ if the workflow does not exist or is attached to a
        project.
        """
        ensure_nonemptystring('workflow_name')

        what = urlencode({'workflowName': workflow_name}).replace('+', r'\+')
        uri = 'secure/admin/workflows/ListWorkflows.jspa'
        page = self._get(uri)
        atl_token = re.search(
            r'DeleteWorkflow.jspa\?atl_token=([^&]+)&amp;[^&]+&amp;%s"' % what,
            page.text,
        )

        if not atl_token:
            raise ApiError(
                'Workflow %s not found or attached to project(s).'
                % workflow_name
            )

        self._do_form_step(
            'secure/admin/workflows/DeleteWorkflow.jspa',
            data={
                'workflowName': workflow_name,
                'workflowMode': 'live',
                'confirmedDelete': 'true',
                'atl_token': atl_token.group(1),
            },
            cookies=page.cookies,
        )

    # workflowschemes

    @api_call
    def list_workflowschemes(self) -> List[Dict[str, Any]]:
        """Return list of workflow schemes.

        # Returned value

        A list of _workflowschemes_.  Each workflowscheme is a
        dictionary with the following entries:

        - name: a string
        - id: an integer
        - active: a boolean
        """
        uri = 'secure/admin/ViewWorkflowSchemes.jspa'
        pat_name = r'class="workflow-scheme-name[^<]+<strong>([^<]+)</strong>'
        pat_id = r'EditWorkflowScheme.jspa\?schemeId=(\d+)"'
        pat_inactive = r'DeleteWorkflowScheme!default.jspa\?schemeId=%s"'
        return self._parse_data(uri, pat_name, pat_id, pat_inactive)

    @api_call
    def delete_workflowscheme(
        self, scheme_id_or_name: Union[int, str]
    ) -> None:
        """Delete workflowscheme.

        # Required parameters

        - scheme_id_or_name: an integer or a non-empty string

        # Returned value

        None.

        # Raised exceptions

        _ApiError_ if `scheme_id_or_name` is invalid or something wrong
        occurred.
        """
        ensure_instance('scheme_id_or_name', (int, str))

        if not isinstance(scheme_id_or_name, int):
            scheme_id = _get_scheme_id(
                scheme_id_or_name, self.list_workflowschemes()
            )
            scheme = self._get_json(f'workflowscheme/{scheme_id}')
            if scheme['name'] != scheme_id_or_name:
                raise ApiError('Scheme %s not found.' % scheme_id_or_name)
        else:
            scheme_id = str(scheme_id_or_name)

        requests.delete(
            self._get_url(f'workflowscheme/{scheme_id}'),
            auth=self.auth,
            verify=self.verify,
        )

    ####################################################################
    # JIRA project
    #
    # list_projects
    # get_project
    # create_project
    # delete_project
    # update_project
    # list_project_boards
    #
    # get_project_issuetypescheme
    # set_project_issuetypescheme
    # get_project_issuetypescreenscheme
    # set_project_issuetypescreenscheme
    # get_project_notificationscheme
    # set_project_notificationscheme
    # get_project_permissionscheme
    # set_project_permissionscheme
    # get_project_priorityscheme
    # set_project_priorityscheme
    # get_project_workflowscheme
    # set_project_workflowscheme
    #
    # list_project_shortcuts
    # add_project_shortcut
    # create_project_board
    #
    # list_project_roles
    # get_project_role
    # add_project_role_actors
    # remove_project_role_actor

    @api_call
    def list_projects(
        self, expand: str = PROJECT_EXPAND
    ) -> List[Dict[str, Any]]:
        """Return list of expanded projects.

        # Optional parameters

        - expand: a string (`PROJECT_EXPAND` by default)

        # Returned value

        A list of _projects_.  Each project is a dictionary with the
        following entries (assuming the default for `expand`):

        - projectKeys: a list of string
        - id: a string
        - projectTypeKey: a string
        - name: a string
        - expand: a string
        - avatarUrls: a dictionary
        - self: a string
        - description: a string
        - lead: a dictionary
        - key: a string

        The `avatarUrls` dictionary has string keys (of the form 'nnxnn'
        for each avatar size) and string values (an URL referring the
        avatar image).

        The `lead` dictionary represents a user and has the following
        entries:

        - avatarUrls: a dictionary as described above
        - name: a string
        - active: a boolean
        - self: a string
        - displayName: a string
        - key: a string
        """
        ensure_instance('expand', str)

        result = self._get_json('project', params={'expand': expand})
        return result  # type: ignore

    @api_call
    def list_projectoverviews(self):
        """Return list of project overviews.

        # Returned value

        A list of _project overviews_.  Each project overview is a
        dictionary with the following entries:

        - admin: a boolean
        - hasDefaultAvatar: a boolean
        - id: an integer
        - issueCount: an integer or None
        - key: a string
        - lastUpdatedTimestamp: an integer (a timestamp) or None
        - lead: a string
        - leadProfileLink: a string
        - name: a string
        - projectAdmin: a boolean
        - projectCategoryId: ... or None
        - projectTypeKey: a string
        - projectTypeName: a string
        - recent: a boolean
        - url: a string or None
        """
        result = requests.get(
            join_url(self.url, '/secure/project/BrowseProjects.jspa'),
            auth=self.auth,
            verify=self.verify,
        )
        upd = result.text.split(
            'WRM._unparsedData["com.atlassian.jira.project.browse:projects"]="'
        )[1].split('\n')[0][:-2]
        return json.loads(
            upd.replace('\\"', '"').replace('\\\\', '\\').replace("\\\'", "'")
        )

    @api_call
    def get_project(
        self, project_id_or_key: Union[int, str], expand: str = PROJECT_EXPAND
    ) -> Dict[str, Any]:
        """Returned expanded project details.

        # Required parameters

        - project_id_or_key: an integer or a non-empty string

        # Optional parameters

        - expand: a string (`PROJECT_EXPAND` by default)

        # Returned value

        A dictionary.  See #list_projects() for details on its
        structure.
        """
        ensure_instance('project_id_or_key', (str, int))
        ensure_instance('expand', str)

        result = self._get_json(
            f'project/{project_id_or_key}', params={'expand': expand}
        )
        return result  # type: ignore

    @api_call
    def create_project(
        self,
        key: str,
        project_type: str,
        lead: str,
        name: Optional[str] = None,
        project_template: Optional[str] = None,
        description: Optional[str] = None,
        url: Optional[str] = None,
        assignee_type: Optional[str] = None,
        avatar_id: Optional[int] = None,
        issue_security_scheme: Optional[int] = None,
        permission_scheme: Optional[int] = None,
        notification_scheme: Optional[int] = None,
        category_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Create new project.

        # Required parameters

        - key: a string
        - project_type: a string
        - lead: a string

        # Optional parameters

        - name: a string or None (None by default)
        - project_template: a string or None (None by default)
        - description: a string or None (None by default)
        - url: a string or None (None by default)
        - assignee_type: one of `'PROJECT_LEAD'`, `'UNASSIGNED'`
        - avatar_id: an integer or None (None by default)
        - issue_security_scheme: an integer or None (None by default)
        - permission_scheme: an integer or None (None by default)
        - notification_scheme: an integer or None (None by default)
        - category_id: an integer or None (None by default)

        # Returned value

        A dictionary describing the project if successful.

        # Raised exceptions

        Raises an _ApiError_ if not successful.
        """
        ensure_noneorinstance('avatar_id', int)
        ensure_noneorinstance('issue_security_scheme', int)
        ensure_noneorinstance('permission_scheme', int)
        ensure_noneorinstance('notification_scheme', int)
        ensure_noneorinstance('category_id', int)

        project = {'key': key}
        add_if_specified(project, 'name', name)
        add_if_specified(project, 'projectTypeKey', project_type)
        add_if_specified(project, 'projectTemplateKey', project_template)
        add_if_specified(project, 'description', description)
        add_if_specified(project, 'lead', lead)
        add_if_specified(project, 'url', url)
        add_if_specified(project, 'assigneeType', assignee_type)
        add_if_specified(project, 'avatarId', avatar_id)
        add_if_specified(project, 'issueSecurityScheme', issue_security_scheme)
        add_if_specified(project, 'permissionScheme', permission_scheme)
        add_if_specified(project, 'notificationScheme', notification_scheme)
        add_if_specified(project, 'categoryId', category_id)

        result = self.session().post(
            self._get_url('project'), data=json.dumps(project)
        )
        return result  # type: ignore

    @api_call
    def update_project(
        self, project_id_or_key: Union[int, str], project: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update project project.

        # Required parameters

        - project_id_or_key: an integer or a non-empty string
        - project: a dictionary

        `project` is dictionary with the following optional entries:

        - name
        - projectTypeKey
        - projectTemplateKey
        - description
        - lead
        - url
        - assigneeType
        - avatarId
        - issueSecurityScheme
        - permissionScheme
        - notificationScheme
        - categoryId

        This dictionary respects the format returned by
        #list_projects().

        If an entry is not specified or is None, its corresponding
        value in the project will remain unchanged.

        # Returned value

        A dictionary.  See #list_projects() for details on its
        structure.
        """
        ensure_instance('project_id_or_key', (str, int))

        result = self.session().put(
            self._get_url(f'project/{project_id_or_key}'),
            data=json.dumps(project),
        )
        return result  # type: ignore

    @api_call
    def delete_project(
        self, project_id_or_key: Union[int, str]
    ) -> Dict[str, Any]:
        """Delete project project.

        # Required parameters

        - project_id_or_key: an integer or a string

        # Returned value

        An empty dictionary if the deletion is successful.

        # Raised exceptions

        Raises an _ApiError_ if not successful.
        """
        ensure_instance('project_id_or_key', (str, int))

        result = self.session().delete(
            self._get_url(f'project/{project_id_or_key}')
        )
        return result  # type: ignore

    @api_call
    def list_project_boards(
        self, project_id_or_key: Union[int, str]
    ) -> List[Dict[str, Any]]:
        """Returns the list of boards attached to project.

        # Required parameters

        - project_id_or_key: an integer or a string

        # Returned value

        A list of _boards_.  Each board is a dictionary with the
        following entries:

        - type: a string
        - id: an integer
        - name: a string
        - self: a string

        # Raised exceptions

        Browse project permission required (will raise an _ApiError_
        otherwise).
        """
        ensure_instance('project_id_or_key', (str, int))

        return self.list_boards(params={'projectKeyOrId': project_id_or_key})

    @api_call
    def get_project_notificationscheme(
        self, project_id_or_key: Union[int, str]
    ) -> Optional[Dict[str, Any]]:
        """Get notificationscheme assigned to project.

        # Required parameters

        - project_id_or_key: an integer or a string

        # Returned value

        A dictionary with the following entries:

        - id: an integer
        - self: a string
        - name: a string
        - description: a string
        - notificationSchemeEvents: a list of dictionaries

        Returns None if no notificationscheme assigned.
        """
        ensure_instance('project_id_or_key', (str, int))

        try:
            return self._get_json(
                f'project/{project_id_or_key}/notificationscheme'
            )
        except:
            return None

    @api_call
    def set_project_notificationscheme(
        self,
        project_id_or_key: Union[int, str],
        scheme_id_or_name: Union[int, str],
    ) -> Dict[str, Any]:
        """Set notificationscheme associated to project.

        # Required parameters

        - project_id_or_key: an integer or a string
        - scheme_id_or_name! an integer or a string

        `scheme_id_or_name` is either the scheme ID or the scheme name.

        # Returned value.

        A dictionary.  See #list_projects() for details on its
        structure.
        """
        ensure_instance('project_id_or_key', (str, int))
        ensure_instance('scheme_id_or_name', (str, int))

        if isinstance(scheme_id_or_name, int):
            scheme_id = scheme_id_or_name
        else:
            nss = [
                ns['id']
                for ns in self.list_notificationschemes()
                if ns['name'] == scheme_id_or_name
            ]
            if len(nss) > 1:
                raise ApiError(
                    'More than one notificationscheme with name %s.'
                    % scheme_id_or_name
                )
            if not nss:
                raise ApiError(
                    'No notificationscheme with name %s.' % scheme_id_or_name
                )
            scheme_id = nss[0]

        return self.update_project(
            project_id_or_key, {'notificationScheme': scheme_id}
        )

    @api_call
    def get_project_permissionscheme(
        self, project_id_or_key: Union[int, str]
    ) -> Dict[str, Any]:
        """Get permissionscheme assigned to project.

        # Required parameters

        - project_id_or_key: an integer or a string

        # Returned value

        A dictionary with the following entries:

        - id: an integer
        - self: a string
        - name: a string
        - description: a string
        """
        ensure_instance('project_id_or_key', (str, int))

        result = self._get_json(
            f'project/{project_id_or_key}/permissionscheme'
        )
        return result  # type: ignore

    @api_call
    def set_project_permissionscheme(
        self,
        project_id_or_key: Union[int, str],
        scheme_id_or_name: Union[int, str],
    ) -> Dict[str, Any]:
        """Set permissionscheme associated to project.

        # Required parameters

        - project_id_or_key: an integer or a string
        - scheme_id_or_name: an integer or a string

        `scheme_id_or_name` is either the scheme ID or the scheme name.

        # Returned value

        A dictionary with the following entries:

        - id: an integer
        - self: a string
        - name: a string
        - description: a string

        # Raised exceptions

        Raises an _ApiError_ if `scheme_id_or_name` is not known or
        ambiguous.
        """
        ensure_instance('project_id_or_key', (str, int))
        ensure_instance('scheme_id_or_name', (str, int))

        if isinstance(scheme_id_or_name, int):
            data = {'id': scheme_id_or_name}
        else:
            pss = [
                ps['id']
                for ps in self.list_permissionschemes()
                if ps['name'] == scheme_id_or_name
            ]
            if len(pss) > 1:
                raise ApiError(
                    'More than one permissionscheme with name %s.'
                    % scheme_id_or_name
                )
            if not pss:
                raise ApiError(
                    'No permissionscheme with name %s.' % scheme_id_or_name
                )
            data = {'id': pss[0]}

        result = self.session().put(
            self._get_url(f'project/{project_id_or_key}/permissionscheme'),
            data=json.dumps(data),
        )
        return result  # type: ignore

    @api_call
    def get_project_priorityscheme(
        self, project_id_or_key: Union[int, str]
    ) -> Dict[str, Any]:
        """Get priorityscheme associated to project.

        # Required parameters

        - project_id_or_key: an integer or a string

        # Returned value

        A dictionary with the following entries:

        - id: an integer
        - self: a string
        - name: a string
        - description: a string
        - ...
        """
        ensure_instance('project_id_or_key', (str, int))

        result = self._get_json(f'project/{project_id_or_key}/priorityscheme')
        return result  # type: ignore

    @api_call
    def set_project_priorityscheme(
        self,
        project_id_or_key: Union[int, str],
        scheme_id_or_name: Union[int, str],
    ) -> Dict[str, Any]:
        """Set priorityscheme associated to project.

        # Required parameters

        - project_id_or_key: an integer or a string
        - scheme_id_or_name: an integer or a string

        `scheme_id_or_name` is either the scheme ID or the scheme name.

        # Returned value

        A dictionary with the following entries:

        - expand: a string
        - self: a string
        - id: an integer
        - name: a string
        - description: a string
        - defaultOptionId: a string
        - optionIds: a list of strings
        - defaultScheme: a boolean
        - projectKeys: a list of strings

        # Raised exceptions

        Raises an _ApiError_ if `scheme_id_or_name` is not known or
        ambiguous.
        """
        ensure_instance('project_id_or_key', (str, int))
        ensure_instance('scheme_id_or_name', (str, int))

        if isinstance(scheme_id_or_name, int):
            data = {'id': scheme_id_or_name}
        else:
            pss = [
                ps['id']
                for ps in requests.get(
                    self._get_url('priorityschemes'),
                    auth=self.auth,
                    verify=self.verify,
                ).json()['schemes']
                if ps['name'] == scheme_id_or_name
            ]
            if len(pss) > 1:
                raise ApiError(
                    'More than one priorityscheme with name %s.'
                    % scheme_id_or_name
                )
            if not pss:
                raise ApiError(
                    'No priorityscheme with name %s.' % scheme_id_or_name
                )
            data = {'id': pss[0]}

        result = self.session().put(
            self._get_url(f'project/{project_id_or_key}/priorityscheme'),
            data=json.dumps(data),
        )
        return result  # type: ignore

    @api_call
    def get_project_workflowscheme(
        self, project_id_or_key: Union[int, str]
    ) -> Dict[str, Any]:
        """Get workflowscheme assigned to project.

        # Required parameters

        - project_id_or_key: an integer or a string

        # Returned value

        A dictionary with the following entries:

        - name: a string
        - description: a string
        - id: an integer
        - shared: a dictionary
        - ...
        """
        ensure_instance('project_id_or_key', (str, int))

        # projectconfig requires a project key
        project = self.get_project(project_id_or_key)
        api_uri = f'rest/projectconfig/1/workflowscheme/{project["key"]}'
        return self._get(api_uri)  # type: ignore

    @api_call
    def set_project_workflowscheme(
        self, project_id_or_key: Union[int, str], workflowscheme: str
    ) -> None:
        """Set project workflowscheme.

        # Required parameters

        - project_id_or_key: an integer or a string
        - workflowscheme: a non-empty string

        # Returned value

        None.
        """
        # No API for that, using forms...
        #
        # !!! note
        #     The last request returns a 401 error, but it
        #     works.  No idea why (and skipping it does NOT work).
        #     Maybe due to a redirect?
        ensure_instance('project_id_or_key', (str, int))
        ensure_nonemptystring('workflowscheme')

        project = self.get_project(project_id_or_key)
        form, workflowscheme_id = self._get_projectconfig_option(
            'secure/project/SelectProjectWorkflowScheme!default.jspa',
            project['id'],
            workflowscheme,
        )
        atl_token = _get_atl_token(form.text)

        step1 = self._do_form_step(
            'secure/project/SelectProjectWorkflowSchemeStep2!default.jspa',
            data={
                'Associate': 'Associate',
                'atl_token': atl_token,
                'projectId': project['id'],
                'schemeId': workflowscheme_id,
            },
            cookies=form.cookies,
        )
        self._do_form_step(
            'secure/project/SelectProjectWorkflowSchemeStep2.jspa',
            data={
                'Associate': 'Associate',
                'atl_token': atl_token,
                'projectId': project['id'],
                'schemeId': workflowscheme_id,
                'draftMigration': False,
                'projectIdsParameter': project['id'],
            },
            cookies=step1.cookies,
        )

    @api_call
    def get_project_issuetypescheme(
        self, project_id_or_key: Union[int, str]
    ) -> Dict[str, str]:
        """Return the current issuetypescheme name.

        # Required parameters

        - project_id_or_key: an integer or a string

        # Returned value

        A dictionary with the following entry:

        - name: a string

        # Raised exceptions

        Raises an _ApiError_ if the project does not exist.
        """
        return {
            'name': self._get_projectconfig_scheme(
                project_id_or_key, 'issuetypes'
            )
        }

    @api_call
    def set_project_issuetypescheme(
        self, project_id_or_key: Union[int, str], scheme: str
    ) -> None:
        """Set project issuetypescheme.

        # Required parameters

        - project_id_or_key: an integer or a string
        - scheme: a non-empty string

        # Returned value

        None.

        # Raised exceptions

        Raises an _ApiError_ if the scheme does not exist.
        """
        ensure_instance('project_id_or_key', (str, int))
        ensure_nonemptystring('scheme')

        project = self.get_project(project_id_or_key)
        page, option = self._get_projectconfig_option(
            'secure/admin/SelectIssueTypeSchemeForProject!default.jspa',
            project['id'],
            scheme,
        )
        self._do_form_step(
            'secure/admin/SelectIssueTypeSchemeForProject.jspa',
            data={
                'OK': 'OK',
                'atl_token': _get_atl_token(page.text),
                'projectId': project['id'],
                'schemeId': option,
                'createType': 'chooseScheme',
            },
            cookies=page.cookies,
        )

    @api_call
    def get_project_issuetypescreenscheme(
        self, project_id_or_key: Union[int, str]
    ) -> Dict[str, str]:
        """Return the current issuetypescreenscheme name.

        # Required parameters

        - project_id_or_key: an integer or a string

        # Returned value

        A dictionary with the following entry:

        - name: a string

        # Raised exceptions

        If the project does not exist, raises an _ApiError_.
        """
        return {
            'name': self._get_projectconfig_scheme(
                project_id_or_key, 'screens'
            )
        }

    @api_call
    def set_project_issuetypescreenscheme(
        self, project_id_or_key: Union[int, str], scheme: str
    ) -> None:
        """Set project issuetypescreenscheme.

        # Required parameters

        - project_id_or_key: an integer or a string
        - scheme: a non-empty string

        # Returned value

        None.

        # Raised exceptions

        Raises an _ApiError_ if the scheme does not exist.
        """
        ensure_instance('project_id_or_key', (str, int))
        ensure_nonemptystring('scheme')

        project = self.get_project(project_id_or_key)
        page, option = self._get_projectconfig_option(
            'secure/project/SelectIssueTypeScreenScheme!default.jspa',
            project['id'],
            scheme,
        )
        self._do_form_step(
            'secure/project/SelectIssueTypeScreenScheme.jspa',
            data={
                'Associate': 'Associate',
                'atl_token': _get_atl_token(page.text),
                'projectId': project['id'],
                'schemeId': option,
            },
            cookies=page.cookies,
        )

    @api_call
    def list_project_shortcuts(
        self, project_id_or_key: Union[int, str]
    ) -> List[Dict[str, str]]:
        """Return the list of project shortcuts.

        # Required parameters

        - project_id_or_key: an integer or a string

        # Returned value

        A list of project _shortcuts_.  Each shortcut is a dictionary
        with the following entries:

        - name: a string
        - url: a string
        - id: a string
        - icon: a string

        The list may be empty.
        """
        ensure_instance('project_id_or_key', (str, int))

        api_uri = f'rest/projects/1.0/project/{project_id_or_key}/shortcut'
        return self._get(api_uri)  # type: ignore

    @api_call
    def add_project_shortcut(
        self, project_id_or_key: Union[int, str], url: str, description: str
    ) -> Dict[str, str]:
        """Add a shortcut to project.

        !!! note
            It is not an error to create identical shortcuts.

        # Required parameters

        - project_id_or_key: an integer or a string
        - url: a non-empty string
        - description: a non-empty string

        # Returned value

        A dictionary with the following entries:

        - icon: a string
        - id: a string
        - name: a string
        - url: a string
        """
        ensure_instance('project_id_or_key', (str, int))
        ensure_nonemptystring('url')
        ensure_nonemptystring('description')

        project = self.get_project(project_id_or_key)

        result = requests.post(
            join_url(
                self.url,
                f'rest/projects/1.0/project/{project["key"]}/shortcut',
            ),
            json={'url': url, 'name': description, 'icon': ''},
            auth=self.auth,
            verify=self.verify,
        )
        return result  # type: ignore

    @api_call
    def create_project_board(
        self, project_id_or_key: Union[int, str], name: str, preset: str
    ) -> Dict[str, Any]:
        """Create a new board associated to project.

        # Required parameters

        - project_id_or_key: a non-empty string
        - name: a non-empty string
        - preset: one of 'kanban', 'scrum'

        # Returned value

        A dictionary with the following entries:

        - id: an integer
        - name: a string

        KLUDGE we shouldn't switch to greenhopper
        """
        ensure_nonemptystring('project_id_or_key')
        ensure_nonemptystring('name')
        ensure_in('preset', ['kanban', 'scrum'])

        self._client()._options['agile_rest_path'] = 'greenhopper'
        result = self._client().create_board(name, project_id_or_key, preset)
        self._client()._options['agile_rest_path'] = 'agile'
        return result.raw

    @api_call
    def list_project_roles(
        self, project_id_or_key: Union[int, str]
    ) -> Dict[str, Any]:
        """Return the project roles.

        # Required parameters

        - project_id_or_key: an integer or a string

        # Returned value

        A dictionary.  Keys are role names, and values are URIs
        containing details for the role.
        """
        ensure_instance('project_id_or_key', (str, int))

        result = self._get_json(f'project/{project_id_or_key}/role')
        return result  # type: ignore

    @api_call
    def get_project_role(
        self, project_id_or_key: Union[int, str], role_id: Union[int, str]
    ) -> Dict[str, Any]:
        """Return the project role details.

        # Required parameters

        - project_id_or_key: an integer or a string
        - role_id: an integer or a string

        # Returned value

        A dictionary with the following entries:

        - self: a string (an URL)
        - name: a string
        - id: an integer
        - actors: a list of dictionaries

        `actors` entries have the following entries:

        - id: an integer
        - displayName: a string
        - type: a string
        - name: a string
        - avatarUrl: a string
        """
        ensure_instance('project_id_or_key', (str, int))
        ensure_instance('role_id', (str, int))

        result = self._get_json(f'project/{project_id_or_key}/role/{role_id}')
        return result  # type: ignore

    @api_call
    def add_project_role_actors(
        self,
        project_id_or_key: Union[int, str],
        role_id: Union[int, str],
        groups: Optional[List[str]] = None,
        users: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Add an actor (group or user) to a project role.

        You can only specify either `groups` or `users`.

        # Required parameters

        - project_id_or_key: an integer or a string
        - role_id: an integer or a string
        - groups: a list of strings
        - users: a list of strings

        # Returned value

        A project role.  Refer to #get_project_role() for details.
        """
        ensure_instance('project_id_or_key', (str, int))
        ensure_instance('role_id', (str, int))
        ensure_onlyone('groups', 'users')
        ensure_noneorinstance('groups', list)
        ensure_noneorinstance('users', list)

        if groups is not None:
            data = {'group': groups}
        else:
            data = {'user': users}  # type: ignore
        result = self.session().post(
            self._get_url(f'project/{project_id_or_key}/role/{role_id}'),
            data=json.dumps(data),
        )
        return result  # type: ignore

    @api_call
    def remove_project_role_actor(
        self,
        project_id_or_key: Union[int, str],
        role_id: Union[int, str],
        group: Optional[str] = None,
        user: Optional[str] = None,
    ) -> None:
        """Remove an actor from project role.

        You can only specify either `group` or `user`.

        # Required parameters

        - project_id_or_key: an integer or a string
        - role_id: an integer or a string
        - group: a string
        - user: a string
        """
        ensure_instance('project_id_or_key', (str, int))
        ensure_instance('role_id', (str, int))
        ensure_onlyone('group', 'user')
        ensure_noneorinstance('group', str)
        ensure_noneorinstance('user', str)

        if group is not None:
            params = {'group': group}
        else:
            params = {'user': user}  # type: ignore
        self.session().delete(
            self._get_url(f'project/{project_id_or_key}/role/{role_id}'),
            params=params,
        )

    ####################################################################
    # JIRA roles
    #
    # list_roles

    @api_call
    def list_roles(self) -> List[Dict[str, Any]]:
        """Return list of roles available in JIRA.

        # Returned value

        A list of _roles_.  Each role is a dictionary  with the
        following entries:

        - self: a string (an URL)
        - name: a string
        - id: an integer
        - actors: a list of dictionaries

        `actors` entries have the following entries:

        - id: an integer
        - displayName: a string
        - type: a string
        - name: a string
        - avatarUrl: a string

        The `actors` entry may be missing.
        """
        return self._get_json('role')  # type: ignore

    ####################################################################
    # JIRA users
    #
    # list_users
    # get_user
    # get_currentuser
    # create_user
    # update_user
    # delete_user
    # search_user

    @api_call
    def list_users(self) -> List[str]:
        """Return users list.

        # Returned value

        A list of _users_.  Each user is a string (the user 'name').

        All known users are returned, including inactive ones.
        """
        users = {}
        for letter in 'abcdefghijklmnopqrstuvwxyz':
            exhausted = False
            start = 0
            while not exhausted:
                results = self._client().search_users(
                    letter,
                    includeInactive=True,
                    maxResults=1000,
                    startAt=start,
                )
                for user in results:
                    users[user.name] = True
                if len(results) == 1000:
                    start += 1000
                else:
                    exhausted = True

        return list(users.keys())

    @api_call
    def get_user(
        self, user_name: str, expand: Optional[str] = None
    ) -> Dict[str, Any]:
        """Return user details.

        # Required parameters

        - user_name: a non-empty string

        # Optional parameters

        - expand: a string

        If not specified, `expand` defaults to
        `'groups,applicationRoles'` and lists what to return for each
        user.

        # Returned value

        A dictionary with the followin entries (assuming the default for
        `expand`):

        - active: a boolean
        - applicationRoles: a dictionary
        - avatarUrls: a dictionary
        - displayName: a string
        - emailAddress: a string
        - expand: a string
        - groups: a dictionary
        - key: a string
        - locale: a string
        - name: a string
        - self: a string
        - timeZone: a string

        The `applicationRoles` has two entries, `size` and `items`.
        `size` is the number of entries in item, `items` is a list of
        dictionaries.

        Each entry (if any) in the items list has the following entries:

        - key: a string
        - name: a string

        # Raised exceptions

        If `user_name` does not exist, an _ApiError_ is raised.
        """
        ensure_nonemptystring('user_name')
        ensure_noneorinstance('expand', str)

        if expand is None:
            expand = USER_EXPAND

        result = self._get_json(
            'user', params={'username': user_name, 'expand': expand}
        )
        return result  # type: ignore

    @api_call
    def get_currentuser(self, expand: Optional[str] = None) -> Dict[str, Any]:
        """Return currently logged user details.

        # Optional parameters

        - expand: a string

        # Returned value

        A dictionary.  Refer to #get_user() for details.
        """
        ensure_noneorinstance('expand', str)

        if expand:
            params = {'expand': expand}
        else:
            params = {}

        return self._get_json('myself', params=params)  # type: ignore

    @api_call
    def search_users(self, name: str) -> List[Dict[str, Any]]:
        """Return list of user details for users matching name.

        Return at most 1000 entries.

        # Required parameters

        - name: a non-empty string

        `name` will be searched in `name` and `displayName` fields, and
        is case-insensitive.

        # Returned value

        A list of _user details_.  Each user details is a dictionary.
        Refer to #get_user() for its structure.
        """
        ensure_nonemptystring('name')

        return [
            self.get_user(u.name)
            for u in self._client().search_users(
                name, includeInactive=True, maxResults=1000
            )
        ]

    @api_call
    def create_user(
        self,
        name: str,
        password: Optional[str],
        email_address: str,
        display_name: str,
    ) -> bool:
        """Create a new user.

        # Required parameters

        - name: a non-empty string
        - email_address: a non-empty string
        - password: a non-empty string or None
        - display_name: a string

        # Returned value

        True if successful.
        """
        ensure_nonemptystring('name')
        ensure_nonemptystring('email_address')
        ensure_noneorinstance('password', str)
        ensure_instance('display_name', str)

        return self._client().add_user(
            name, email_address, password=password, fullname=display_name
        )

    @api_call
    def update_user(
        self, user_name: str, user: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update user.

        !!! note
            JSON support only.

        # Required parameters

        - user_name: a non-empty string
        - user: a dictionary

        # Returned value

        The updated _user details_.  Refer to #get_user() for more
        information.
        """
        ensure_nonemptystring('user_name')
        ensure_instance('user', dict)

        result = self.session().put(
            self._get_url('user'),
            params={'username': user_name},
            data=json.dumps(user),
        )
        return result  # type: ignore

    @api_call
    def delete_user(self, user_name: str) -> bool:
        """Delete user.

        # Required parameters

        - user_name: a non-empty string

        # Returned value

        True if successful, False otherwise.
        """
        ensure_nonemptystring('user_name')

        return self._client().delete_user(user_name)

    ####################################################################
    # JIRA agile
    #
    # list_boards
    # get_board
    # get_board_configuration
    # list_board_sprints
    # list_board_projects
    # list_board_epics
    # create_board
    # delete_board
    # get_board_editmodel
    # set_board_admins
    # set_board_columns
    # set_board_daysincolumn

    @api_call
    def list_boards(
        self, params: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Return the list of boards.

        # Optional parameters

        - params: a dictionary or None (None by default)

        `params`, if provided, is a dictionary with at least one of the
        following entries:

        - expand: a string
        - includePrivate: a boolean
        - maxResults: an integer
        - name: a string
        - orderBy: a string
        - projectKeyOrId: a string
        - projectLocation: a string
        - startAt: an integer
        - type: a string
        - userkeyLocation: a string
        - usernameLocation: a string

        # Returned value

        A list of _boards_.  Each board is a dictionary with the
        following entries:

        - name: a string
        - type: a string (`'scrum'` or `'kanban'`)
        - id: an integer
        - self: a string (URL)
        """
        ensure_noneorinstance('params', dict)

        return self._collect_agile_data('board', params=params)

    @api_call
    def get_board(self, board_id: int) -> Dict[str, Any]:
        """Return board details.

        # Required parameters

        - board_id: an integer

        # Returned value

        A dictionary with the following entries:

        - id: an integer
        - type: a string
        - name: a string
        - self: a string
        """
        ensure_instance('board_id', int)

        result = self._client()._get_json(
            f'board/{board_id}', base=self._client().AGILE_BASE_URL
        )
        return result  # type: ignore

    @api_call
    def get_board_configuration(self, board_id: int) -> Dict[str, Any]:
        """Return board configuration details.

        # Required parameters

        - board_id: an integer

        # Returned value

        A dictionary with the following entries:

        - filter: a dictionary
        - ranking: a dictionary
        - columnConfig: a dictionary
        - name: a string
        - subQuery: a dictionary
        - self: a string (an URL)
        - type: a string
        - id: an integer
        """
        ensure_instance('board_id', int)

        result = self._client()._get_json(
            f'board/{board_id}/configuration',
            base=self._client().AGILE_BASE_URL,
        )
        return result  # type: ignore

    @api_call
    def list_board_sprints(self, board_id: int) -> List[Dict[str, Any]]:
        """Return the list of sprints attached to board.

        Sprints will be ordered first by state (i.e. closed, active,
        future) then by their position in the backlog.

        # Required parameters

        - board_id: an integer

        # Returned value

        A list of _sprints_.  Each sprint is a dictionary with the
        following entries:

        - id: an integer
        - self: a string
        - state: a string
        - name: a string
        - startDate: a string (an ISO8601 timestamp)
        - endDate: a string (an ISO8601 timestamp)
        - originBoardId: an integer
        - goal: a string

        Depending on the sprint state, some entries may be missing.
        """
        ensure_instance('board_id', int)

        return self._collect_agile_data(f'board/{board_id}/sprint')

    @api_call
    def list_board_projects(self, board_id: int) -> List[Dict[str, Any]]:
        """Return the list of projects attached to board.

        # Required parameters

        - board_id: an integer

        # Returned value

        A list of _projects_.  Each project is a dictionary with the
        following entries:

        - key: a string
        - id: a string (or an int)
        - avatarUrls: a dictionary
        - name: a string
        - self: a string
        """
        ensure_instance('board_id', int)

        return self._collect_agile_data(f'board/{board_id}/project')

    @api_call
    def list_board_epics(self, board_id: int) -> List[Dict[str, Any]]:
        """Return the list of epics attached to board.

        # Required parameters

        - board_id: an integer

        # Returned value

        A list of _epics_.  Each epic is a dictionary with the following
        entries:

        - id: an integer
        - self: a string
        - name: a string
        - summary: a string
        - color: a dictionary
        - done: a boolean

        The `color` dictionary has one key, `'key'`, with its value
        being a string (the epic color, for example `'color_1'`).
        """
        ensure_instance('board_id', int)

        return self._collect_agile_data(f'board/{board_id}/epic')

    @api_call
    def create_board(
        self, board_name: str, board_type: str, filter_id: int
    ) -> Dict[str, Any]:
        """Create board.

        # Required parameters

        - board_name: a non-empty string
        - board_type: a non-empty string, either `'scrum'` or `'kanban'`
        - filter_id: an integer

        # Returned value

        A dictionary with the following entries:

        - id: an integer
        - self: a string (an URL)
        - name: a string
        - type: a string
        """
        ensure_nonemptystring('board_name')
        ensure_in('board_type', ['scrum', 'kanban'])
        ensure_instance('filter_id', int)

        data = {'name': board_name, 'type': board_type, 'filterId': filter_id}
        result = requests.post(
            join_url(self.AGILE_BASE_URL, 'board'),
            json=data,
            auth=self.auth,
            verify=self.verify,
        )
        return result  # type: ignore

    @api_call
    def delete_board(self, board_id: int) -> None:
        """Delete board.

        # Required parameters

        - board_id: an integer

        # Returned value

        None if successful.

        # Raised exceptions

        An _ApiError_ is raised if the board does not exist or if
        the deletion was not successful.
        """
        ensure_instance('board_id', int)

        result = requests.delete(
            join_url(self.AGILE_BASE_URL, f'board/{board_id}'),
            auth=self.auth,
            verify=self.verify,
        )
        return result  # type: ignore

    @api_call
    def get_board_editmodel(self, board_id: int) -> Dict[str, Any]:
        """Return board editmodel.

        # Required parameters

        - board_id: an integer

        # Returned value

        A dictionary with the following entries:

        - boardAdmins: a dictionary
        - canEdit: a boolean
        - canUseBoardAdminsPicker: a boolean
        - cardColorConfig: a dictionary
        - cardLayoutConfig: a dictionary
        - detailViewFieldConfig: a dictionary
        - estimationStatisticConfig: a dictionary
        - filterConfig: a dictionary
        - globalConfig: a dictionary
        - id: an integer
        - isKanPlanEnabled: a boolean
        - isOldDoneIssuesCutoffConfigurable: a boolean
        - isSprintSupportEnabled: a boolean
        - JQLAutoComplete: a dictionary
        - name: a string
        - oldDoneIssuesCutoff: a string
        - oldDoneIssuesCutoffOptions: a list of dictionaries
        - quickFilterConfig: a dictionary
        - rapidListConfig: a dictionary
        - showDaysInColumn: a boolean
        - showEpicAsPanel: a boolean
        - subqueryConfig: a dictionary
        - swimlanesConfig: a dictionary
        - warnBeforeEditingOwner: a boolean
        - workingDaysConfig: a dictionary
        """
        ensure_instance('board_id', int)

        result = requests.get(
            join_url(self.GREENHOPPER_BASE_URL, 'rapidviewconfig/editmodel'),
            params={'rapidViewId': board_id},
            auth=self.auth,
            verify=self.verify,
        )
        return result  # type: ignore

    @api_call
    def set_board_admins(
        self, board_id: int, board_admins: Dict[str, List[str]]
    ) -> Dict[str, List[Dict[str, str]]]:
        """Set the board administrators.

        # Required parameters

        - board_id: an integer
        - board_admins: a dictionary

        The `board_admins` dictionary has the following two entries:

        - groupKeys: a list of strings
        - userKeys: a list of strings

        The lists can be empty.  Their items must be valid group keys
        or user keys, respectively.

        # Returned value

        A dictionary with the following entries:

        - groupKeys: a list of dictionaries
        - userKeys: a list of dictionaries

        The list items are dictionaries with the following two entries:

        - key: a string
        - displayName: a string

        This returned value has the same format as the `boardAdmins`
        entry in #get_board_editmodel().

        # Raised exceptions

        Raises an _ApiError_ if a provided key is invalid.
        """
        ensure_instance('board_id', int)
        ensure_instance('board_admins', dict)

        result = requests.put(
            join_url(self.GREENHOPPER_BASE_URL, 'rapidviewconfig/boardadmins'),
            json={'id': board_id, 'boardAdmins': board_admins},
            auth=self.auth,
            verify=self.verify,
        )
        return result  # type: ignore

    @api_call
    def set_board_columns(
        self,
        board_id: int,
        columns_template: List[Dict[str, Any]],
        statistics_field: str = 'none_',
    ) -> Dict[str, Any]:
        """Set the board columns.

        # Required parameters

        - board_id: an integer
        - columns_template: a list of dictionaries

        Each item in the `columns_template` list has the following
        entries:

        - name: a non-empty string
        - mappedStatuses: a list of string (possibly empty)
        - isKanPlanColumn: a boolean
        - min: a string,
        - max: a string,
        - id: an integer or None

        `mappedStatuses` entries must be names of existing statuses in
        the associated project(s) workflow(s).  A given status cannot
        be mapped to more than one column (but it's fine to have a
        status not mapped to a column).

        If `id` is None, a new column is created.  If it is not None,
        the column must already exist, and will be updated if needed.

        # Optional parameters

        - statistics_field: a non-empty string (`'_none'` by default)

        If `statistics_field` is specified, it must be the ID of a
        valid statistic field.

        # Returned value

        A dictionary.

        # Raised exceptions

        Raises an _ApiError_ if the provided columns definition is
        invalid.
        """
        ensure_instance('board_id', int)
        ensure_instance('columns_template', list)
        ensure_nonemptystring('statistics_field')

        model = self.get_board_editmodel(board_id)
        if statistics_field not in [
            sf['id'] for sf in model['rapidListConfig']['statisticsFields']
        ]:
            raise ApiError('Unknown statistics_field %s.' % statistics_field)

        # collecting known statuses
        statuses = list(model['rapidListConfig']['unmappedStatuses'])
        for col in model['rapidListConfig']['mappedColumns']:
            statuses += col['mappedStatuses']
        statuses_names = {status['name']: status['id'] for status in statuses}

        mapped_names: List[str] = []
        columns_definitions = []
        for col in columns_template:
            col_statuses = []
            for name in col['mappedStatuses']:
                if name in mapped_names:
                    raise ApiError('Status %s mapped more than once.' % name)
                if name not in statuses_names:
                    raise ApiError('Unknown status %s.' % name)
                mapped_names.append(name)
                col_statuses.append(name)
            column_definition = col.copy()
            column_definition['mappedStatuses'] = [
                {'id': statuses_names[n]} for n in col_statuses
            ]
            columns_definitions.append(column_definition)

        result = requests.put(
            join_url(self.GREENHOPPER_BASE_URL, 'rapidviewconfig/columns'),
            json={
                'currentStatisticsField': {'id': statistics_field},
                'rapidViewId': board_id,
                'mappedColumns': columns_definitions,
            },
            auth=self.auth,
            verify=self.verify,
        )
        return result  # type: ignore

    @api_call
    def set_board_daysincolumn(
        self, board_id: int, days_in_column: bool
    ) -> None:
        """Enable or disable the time spent indicator on cards.

        # Required parameters

        - board_id: an integer
        - days_in_column: a boolean

        # Returned value

        None if successful.

        # Raised exceptions

        An _ApiError_ is raised if something went wrong while setting
        the time spent indicator.
        """
        ensure_instance('board_id', int)
        ensure_instance('days_in_column', bool)

        result = requests.put(
            join_url(
                self.GREENHOPPER_BASE_URL, 'rapidviewconfig/showDaysInColumn'
            ),
            json={'rapidViewId': board_id, 'showDaysInColumn': days_in_column},
            auth=self.auth,
            verify=self.verify,
        )
        return result  # type: ignore

    ####################################################################
    # JIRA issues
    #
    # get_issue
    # list_issue_transitions
    # list_issue_comments
    # add_issue_comment
    # add_issue_link
    # transition_issue
    # get_issue_fields
    # create_issue
    # create_issues
    # TODO delete_issue
    # update_issue
    # assign_issue
    # TEST add_issue_attachment

    @api_call
    def get_issue(
        self, issue_id_or_key: str, expand: Optional[str] = None
    ) -> Dict[str, Any]:
        """Return issue details.

        # Required parameters

        - issue_id_or_key: a non-empty string

        # Optional parameters

        - expand: a string or None (None by default)

        # Returned value

        A dictionary with the following entries:

        - fields: a dictionary
        - self: a string
        - id: a string
        - key: a string
        - expand: a string

        `fields` contains one entry per field associated with the issue.
        The key is the field name (`resolution`, `customfield_11038`,
        ...).  The value is field-dependent (it may be None, a list,
        a string, a dictionary, ...).
        """
        ensure_nonemptystring('issue_id_or_key')
        ensure_noneorinstance('expand', str)

        return (
            self._client()
            .issue(
                issue_id_or_key,
                expand=expand.split(',') if expand is not None else expand,
            )
            .raw
        )

    @api_call
    def list_issue_comments(
        self, issue_id_or_key: str
    ) -> List[Dict[str, Any]]:
        """Return the available comments for issue.

        # Required parameters

        - issue_id_or_key: a non-empty string

        # Returned value

        A list of _comments_.  Each comment is a dictionary with the
        following entries:

        - self: a string (an URL)
        - id: a string
        - author: a dictionary
        - body: a string
        - updateAuthor
        - created: a string (a timestamp)
        - updated: a string (a timestamp)
        """
        return [c.raw for c in self._client().comments(issue_id_or_key)]

    @api_call
    def add_issue_comment(
        self, issue_id_or_key: str, fields: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a comment.

        # Required parameters

        - issue_id_or_key: a non-empty string
        - fields: a dictionary

        # Returned value

        A _comment_.  Comments are dictionaries.  Refer to
        #list_issue_comments() for more information.
        """
        url = self._get_url(f'issue/{issue_id_or_key}/comment')
        result = self.session().post(url, data=json.dumps(fields))
        return result  # type: ignore

    @api_call
    def add_issue_link(
        self,
        inward_issue_id_or_key: str,
        type_: str,
        outward_issue_id_or_key: str,
    ) -> Dict[str, Any]:
        """Add an issue link between two issues.

        The `type_` value must be a valid _issue link type_ name.  Refer
        to #list_issuelinktypes() for details.

        # Required parameters
        - inward_issue_id_or_key: a non-empty string
        - type: a non-empty string
        - outward_issue_id_or_key: a non-empty string

        # Returned value


        """
        url = self._get_url('issueLink')
        data = {
            'type': {'name': type_},
            'inwardIssue': {'key': inward_issue_id_or_key},
            'outwardIssue': {'key': outward_issue_id_or_key},
        }
        result = self.session().post(url, data=json.dumps(data))
        return result  # type: ignore

    @api_call
    def list_issue_transitions(
        self, issue_id_or_key: str
    ) -> List[Dict[str, Any]]:
        """Return the available transitions for issue.

        # Required parameters

        - issue_id_or_key: a non-empty string

        # Returned value

        A list of _transitions_.  Each transition is a dictionary with
        the following entries:

        - to: a dictionary
        - id: a string
        - name: a string

        It returns the available transitions, depending on issue current
        state.
        """
        ensure_nonemptystring('issue_id_or_key')

        return self._client().transitions(
            self._client().issue(issue_id_or_key)
        )

    @api_call
    def transition_issue(self, issue_id_or_key: str, path: List[str]) -> None:
        """Transition an issue to a new state, following provided path.

        # Required parameters

        - issue_id_or_key: a non-empty string
        - path: a list of strings

        # Returned value

        None.
        """
        ensure_nonemptystring('issue_id_or_key')
        ensure_instance('path', list)

        for name in path:
            transitions = [
                t['id']
                for t in self.list_issue_transitions(issue_id_or_key)
                if t['name'] == name
            ]
            if len(transitions) != 1:
                raise ApiError(
                    'Got %d transitions to %s, was expecting one.'
                    % (len(transitions), name)
                )
            self._client().transition_issue(issue_id_or_key, transitions[0])

    @api_call
    def get_issue_fields(self, issue_id_or_key: str) -> Dict[str, Any]:
        """Return the available fields for issue.

        # Required parameters

        - issue_id_or_key: a non-empty string

        # Returned value

        A dictionary of _fields_.  Keys are fields internal names
        and values are dictionaries describing the corresponding fields.
        """
        ensure_nonemptystring('issue_id_or_key')

        result = self._get_json(
            f'issue/{issue_id_or_key}/editmeta', params=None
        )
        return result['fields']  # type: ignore

    @api_call
    def create_issue(self, fields: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new issue.

        # Required parameters

        - fields: a dictionary

        `fields` is a dictionary with at least the following entries:

        - project: a dictionary
        - summary: a string
        - description: a string
        - issuetype: a dictionary

        `project` is a dictionary with either an `id` entry or a `key`
        entry.

        `issuetype` is a dictionary with a `name` entry.

        # Returned value

        A dictionary representing the issue.  Refer to #get_issue() for
        more details on its content.
        """
        return self._client().create_issue(fields=fields).raw

    @api_call
    def create_issues(
        self, issue_list: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Create multiple issues.

        # Required parameters

        - issue_list: a list of dictionaries

        # Returned value

        A list of _issues_.  Each issue is a dictionary with the
        following entries:

        - status: a string (`'Success'` or `'Error'`)
        - error: a string or None (in case of success)
        - issue: a dictionary or None
        - input_fields: a dictionary, the corresponding entry in
          `issue_list`
        """
        ensure_instance('issue_list', list)

        return self._client().create_issues(field_list=issue_list)

    @api_call
    def assign_issue(self, issue_id_or_key: str, assignee: str) -> bool:
        """Assign or reassign an issue.

        !!! important
            Requires issue assign permission, which is different from
            issue editing permission.

        # Required parameter

        - issue_id_or_key: a non-empty string
        - assignee: a non-empty string

        # Returned value

        True if successful.
        """
        ensure_nonemptystring('issue_id_or_key')
        ensure_nonemptystring('assignee')

        return self._client().assign_issue(issue_id_or_key, assignee)

    @api_call
    def update_issue(
        self, issue_id_or_key: str, fields: Dict[str, Any]
    ) -> None:
        """Update issue.

        # Required parameters

        - issue_id_or_key: a non-empty string
        - fields: a dictionary

        `fields` is a dictionary with one entry per issue field to
        update.  The key is the field name, and the value is the new
        field value.

        # Returned value

        None.
        """
        ensure_nonemptystring('issue_id_or_key')
        ensure_instance('fields', dict)

        return self._client().issue(issue_id_or_key).update(fields)

    @api_call
    def add_issue_attachment(
        self,
        issue_id_or_key: str,
        filename: str,
        rename_to: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Add attachment to issue.

        !!! note
            If rename_to contains non-ASCII symbols, this may
            fail with an HTTP error (code 500).  Some (?) Jira versions
            fail to handle that properly.

        # Required parameters

        - issue_id_or_key: a non-empty string
        - filename: a non-empty string

        # Optional parameters

        - rename_to: a non-empty string or None (None by default)

        # Returned value

        A dictionary.
        """
        ensure_nonemptystring('issue_id_or_key')
        ensure_nonemptystring('filename')
        ensure_noneorinstance('rename_to', str)

        return (
            self._client()
            .add_attachment(
                issue=issue_id_or_key, attachment=filename, filename=rename_to
            )
            .raw
        )

    ####################################################################
    # JIRA issue linktypes
    #
    # list_issuelinktypes

    @api_call
    def list_issuelinktypes(self) -> List[Dict[str, str]]:
        """List issue link types.

        # Returned value

        A list of _issuelinktypes_.  Each issuelinktype is a dictionary
        with the following entries:

        - id: a string
        - name: a string
        - inward: a string
        - outward: a string
        - self: a string (an URL)

        The `name` entry can be used to create a link between two
        issues.
        """
        return self._get_json('issueLinkType')['issueLinkTypes']

    ####################################################################
    # JIRA sprints
    #
    # create_sprint
    # TODO delete_sprint
    # update_sprint
    # TODO get_sprint
    # add_sprint_issues
    # TODO get_sprint_issues

    @api_call
    def create_sprint(
        self,
        name: str,
        board_id: int,
        start_date: Optional[Any] = None,
        end_date: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Create a new sprint.

        # Required parameters

        - name: a string
        - board_id: an integer

        # Optional parameters

        - start_date
        - end_date

        # Returned value

        A dictionary.
        """
        return (
            self._client()
            .create_sprint(name, board_id, start_date, end_date)
            .raw
        )

    @api_call
    def update_sprint(
        self,
        sprint_id: int,
        name: Optional[str] = None,
        state: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        complete_date: Optional[str] = None,
        origin_board_id: Optional[int] = None,
        goal: Optional[str] = None,
    ) -> None:
        """Update existing sprint.

        # Required parameters

        - sprint_id: an integer

        # Optional parameters

        - name
        - state
        - start_date
        - end_date
        - complete_date
        - origin_board_id
        - goal

        # Returned value

        None.
        """
        ensure_instance('sprint_id', int)
        ensure_noneorinstance('name', str)
        ensure_noneorinstance('state', str)
        ensure_noneorinstance('start_date', str)
        ensure_noneorinstance('end_date', str)
        ensure_noneorinstance('complete_date', str)
        ensure_noneorinstance('origin_board_id', int)
        ensure_noneorinstance('goal', str)

        scheme = {'id': sprint_id}
        add_if_specified(scheme, 'name', name)
        add_if_specified(scheme, 'state', state)
        add_if_specified(scheme, 'startDate', start_date)
        add_if_specified(scheme, 'endDate', end_date)
        add_if_specified(scheme, 'completeDate', complete_date)
        add_if_specified(scheme, 'originBoardId', origin_board_id)
        add_if_specified(scheme, 'goal', goal)

        self.session().post(
            join_url(self.AGILE_BASE_URL, f'sprint/{sprint_id}'), json=scheme
        )

    @api_call
    def add_sprint_issues(self, sprint_id: int, issue_keys: List[str]) -> None:
        """Add issues to sprint.

        # Required parameters

        - sprint_id: an integer
        - issue_keys: a list of strings

        # Returned value

        None.
        """
        return self._client().add_issues_to_sprint(sprint_id, issue_keys)

    ####################################################################
    # Xray for JIRA
    #
    # list_xray_projects

    @api_call
    def list_xray_projects(self) -> List[Dict[str, Any]]:
        """Return the requirement projects.

        A _requirement_ project is a project on which Xray is enabled.

        # Returned value

        A list of dictionary with the following entries:

        - icon: a string
        - name: a string (the project name)
        - alias: a string (the project key)
        - pid: an integer
        - avatarId: an integer
        - type: a string (the project type)

        TODO: support more than 100 projects.
        """
        params = {'iDisplayStart': 0, 'iDisplayLength': 100}

        result = requests.get(
            join_url(self.XRAY_BASE_URL, 'preferences/requirementProjects'),
            params=params,
            auth=self.auth,
        ).json()

        return result['entries']

    ####################################################################
    # JIRA Service Desk
    #
    # create_request
    # get_request
    # add_request_comment
    # get_bundledfield_definition
    # list_queues
    # list_queue_issues
    # list_requesttypes

    @api_call
    def create_request(
        self,
        servicedesk_id: str,
        requesttype_id: str,
        fields: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Create a new customer request on specified service desk.

        # Required parameters:

        - servicedesk_id: a non-empty string
        - requesttype_id: a non-empty string
        - fields: a dictionary

        The `fields` dictionary content depends on the request type (as
        specified by `requesttype_id`).  It typically has at least the
        following two entries:

        - summary: a string
        - description: a string

        # Returned value

        The created _request_ details.  Please refer to #get_request()
        for more information.
        """
        ensure_nonemptystring('servicedesk_id')
        ensure_nonemptystring('requesttype_id')
        # ensure_instance('fields', list)

        result = requests.post(
            join_url(self.SERVICEDESK_BASE_URL, 'request'),
            json={
                'serviceDeskId': servicedesk_id,
                'requestTypeId': requesttype_id,
                'requestFieldValues': fields,
            },
            auth=self.auth,
            verify=self.verify,
        )
        return result  # type: ignore

    @api_call
    def get_request(
        self, request_id_or_key: str, expand: Optional['str'] = None
    ) -> Dict[str, Any]:
        """Return request details.

        # Required parameters:

        - request_id_or_key: a non-empty string

        # Optional parameters

        - expand: a string or None (None by default)

        # Returned value:

        The _request_ details, a dictionary, with the following entries:

        - issueId: a string
        - issueKey: a string
        - requestTypeId: a string
        - serviceDeskId: a string
        - createDate: a dictionary
        - reporter: a dictionary
        - active: a boolean
        - timeZone: a string
        - currentStatus: a dictionary
        - requestFieldValues: a dictionary

        There may be additional fields depending on the specified
        `expand` parameter.
        """
        ensure_nonemptystring('request_id_or_key')
        ensure_noneorinstance('expand', str)

        if expand is not None:
            params: Optional[Dict[str, str]] = {'expand': expand}
        else:
            params = None
        response = requests.get(
            join_url(
                self.SERVICEDESK_BASE_URL, f'request/{request_id_or_key}'
            ),
            params=params,
            auth=self.auth,
            verify=self.verify,
        )
        return response  # type: ignore

    @api_call
    def add_request_comment(
        self, request_id_or_key: str, body: str, public: bool = False
    ) -> Dict[str, Any]:
        """Create a public or private comment on request.

        # Required parameters

        - request_id_or_key: a non-empty string
        - body: a string

        # Optional parameters

        - public: a boolean (False by default)

        # Returned value

        A dictionary with the following entries:

        - id: a string
        - body: a string
        - public: a boolean
        - author: a dictionary
        - created: a dictionary
        - _links: a dictionary

        The `author` dictionary has the following entries:

        - name: a string
        - key: a string
        - emailAddress: a string
        - displayName: a string
        - active: a boolean
        - timeZone: a string
        - _links: a dictionary

        The `created` dictionary has the following entries:

        - iso8601: a string (an ISO8601 timestamp)
        - jira: a string (an ISO8601 timestamp)
        - friendly: a string
        - epochMillis: an integer
        """
        ensure_nonemptystring('request_id_or_key')
        ensure_instance('body', str)
        ensure_instance('public', bool)

        result = requests.post(
            join_url(
                self.SERVICEDESK_BASE_URL,
                f'request/{request_id_or_key}/comment',
            ),
            json={'body': body, 'public': public},
            auth=self.auth,
            verify=self.verify,
        )
        return result  # type: ignore

    @api_call
    def get_bundledfield_definition(
        self, context_id: str, customfield_id: str
    ) -> Dict[str, Any]:
        """Return a bundled field definition.

        # Required parameters

        - context_id: a string
        - customfield_id: a string

        # Returned value

        A dictionary.
        """
        ensure_nonemptystring('context_id')
        ensure_nonemptystring('customfield_id')

        result = requests.get(
            join_url(self.SDBUNDLE_BASE_URL, 'jsdbundled/getBundledFields'),
            params={'contextId': context_id, 'customFieldId': customfield_id},
            auth=self.auth,
        )
        return result  # type: ignore

    @api_call
    def list_queues(self, servicedesk_id: str) -> List[Dict[str, Any]]:
        """Return a list of queues for a given service desk.

        # Required parameters

        - servicedesk_id: a non-empty string

        # Returned value

        A list of dictionaries.
        """
        ensure_nonemptystring('servicedesk_id')

        return self._collect_sd_data(
            f'servicedesk/{servicedesk_id}/queue',
            headers={'X-ExperimentalApi': 'opt-in'},
        )

    @api_call
    def list_queue_issues(
        self, servicedesk_id: str, queue_id: str
    ) -> List[Dict[str, Any]]:
        """Return a list of issues that are in a given queue.

        # Required parameters

        - servicedesk_id: a non-empty string
        - queue_id: a non-empty string

        # Returned value

        A list of dictionaries.
        """
        ensure_nonemptystring('servicedesk_id')
        ensure_nonemptystring('queue_id')

        return self._collect_sd_data(
            f'servicedesk/{servicedesk_id}/queue/{queue_id}/issue',
            headers={'X-ExperimentalApi': 'opt-in'},
        )

    @api_call
    def list_requesttypes(self, servicedesk_id: str) -> List[Dict[str, Any]]:
        """Return a list of service desk request types.

        # Required parameters

        - servicedesk_id: a non-empty string

        # Returned value

        A list of dictionaries.
        """
        ensure_nonemptystring('servicedesk_id')

        return self._collect_sd_data(
            f'servicedesk/{servicedesk_id}/requesttype'
        )

    @api_call
    ####################################################################
    # JIRA misc. operation
    #
    # list_plugins
    # get_server_info
    # reindex

    @api_call
    def list_plugins(self) -> List[Dict[str, Any]]:
        """Return a list of installed plugins.

        # Returned value

        A list of _plugins_.  A plugin is represented by a dictionary
        with the following entries:

        - applicationKey: a string
        - applicationPluginType: a string (one of `'APPLICATION'`,
            `'PRIMARY'`, `'UTILITY'`)
        - description: a string
        - enabled: a boolean
        - key: a string
        - links: a dictionary
        - name: a string
        - optional: a boolean
        - remotable: a boolean
        - static: a boolean
        - unloadable: a boolean
        - userInstalled: a boolean
        - usesLicensing: a boolean
        - vendor: a dictionary
        - version: a string

        The `links` dictionary may contain the following entries:

        - manage: a string
        - modify: a string
        - plugin-icon: a string
        - plugin-logo: a string
        - plugin-summary: a string
        - self: a string

        The `vendor` dictionary may contain the following entries:

        - link: a string
        - marketplaceLink: a string
        - name: a string

        Not all entries are present for all plugins.
        """
        return requests.get(
            self.UPM_BASE_URL, auth=self.auth, verify=self.verify
        ).json()['plugins']

    @api_call
    def get_server_info(self, do_health_check: bool = False) -> Dict[str, Any]:
        """Return server info.

        # Optional parameters

        - do_health_check: a boolean (False by default)

        # Returned value

        A dictionary with the following entries:

        - versionNumbers: a list of integers
        - serverTitle: a string
        - buildNumber: an integer
        - deploymentType: a string
        - version: a string
        - baseUrl: a string
        - scmInfo: a string
        - buildDate: a datetime as a string
        - serverTime: a datetime as a string

        For example:

        ```python
        {
            'versionNumbers': [7, 3, 8],
            'serverTitle': 'JIRA Dev',
            'buildNumber': 73019,
            'deploymentType': 'Server',
            'version': '7.3.8',
            'baseUrl': 'https://jira.example.com',
            'scmInfo': '94e8771b8094eef96c119ec22b8e8868d286fa88',
            'buildDate': '2017-06-12T00:00:00.000+0000',
            'serverTime': '2018-01-15T11:07:40.690+0000'
        }
        ```
        """
        ensure_instance('do_health_check', bool)

        result = self._get_json(
            'serverInfo', params={'doHealthCheck': str(do_health_check)}
        )
        return result  # type: ignore

    @api_call
    def reindex(
        self,
        kind: str,
        index_comments: bool = False,
        index_change_history: bool = False,
        index_worklogs: bool = False,
    ) -> Dict[str, Any]:
        """Kicks off a reindex.

        !!! note
            Not using the Python API `reindex` method, which does not
            use the API but simulate a page click.

        Foreground reindexing rebuild all indexes (hence the irrelevancy
        of the three optional parameters in that case).

        # Required parameters

        - kind: one of 'FOREGROUND', 'BACKGROUND',
          'BACKGROUND_PREFFERED', or 'BACKGROUND_PREFERRED'.

        # Optional parameters

        - index_comments: a boolean (False by default for background
          reindexing, irrelevant for foreground reindexing)
        - index_change_history: a boolean (False by default for
          background reindexing, irrelevant for foreground reindexing)
        - index_worklogs: a boolean (False by default for background
          reindexing, irrelevant for foreground reindexing)

        # Returned value

        A dictionary with the following entries:

        - progressUrl: a string
        - currentProgress: an integer
        - currentSubTask: a string
        - submittedTime: a string (an ISO timestamp)
        - startTime: a string (an ISO timestamp)
        - finishTime: a string (an ISO timestamp)
        - success: a boolean
        """
        ensure_instance('index_comments', bool)
        ensure_instance('index_change_history', bool)
        ensure_instance('index_worklogs', bool)
        ensure_in('kind', REINDEX_KINDS)

        result = self._post(
            'reindex',
            json={
                'type': kind,
                'indexComments': index_comments,
                'indexChangeHistory': index_change_history,
                'indexWorklogs': index_worklogs,
            },
        )
        return result  # type: ignore

    ####################################################################
    # JIRA helpers

    def session(self) -> requests.Session:
        """Return current session."""
        return self._client()._session

    def _get(
        self,
        uri: str,
        params: Optional[
            Mapping[str, Union[str, Iterable[str], int, bool]]
        ] = None,
    ) -> requests.Response:
        return requests.get(
            join_url(self.url, uri),
            params=params,
            auth=self.auth,
            verify=self.verify,
        )

    def _post(
        self, api: str, json: Optional[Mapping[str, Any]] = None
    ) -> requests.Response:
        api_url = self._get_url(api)
        return requests.post(
            api_url, json=json, auth=self.auth, verify=self.verify
        )

    def _collect_data(
        self,
        api: str,
        params: Optional[Mapping[str, Union[str, List[str], None]]] = None,
        base: Optional[str] = None,
        headers: Optional[Mapping[str, str]] = None,
        start_at: str = 'startAt',
        is_last: str = 'isLast',
    ) -> List[Any]:
        api_url = self._get_url(api) if base is None else join_url(base, api)
        collected: List[Any] = []
        _params = dict(params or {})
        more = True
        with requests.Session() as session:
            session.auth = self.auth
            session.headers = headers  # type: ignore
            session.verify = self.verify
            while more:
                response = session.get(api_url, params=_params)
                if response.status_code // 100 != 2:
                    raise ApiError(response.text)
                try:
                    workload = response.json()
                    values = workload['values']
                    collected += values
                except Exception as exception:
                    raise ApiError(exception)
                more = not workload[is_last]
                if more:
                    _params[start_at] = workload[start_at] + len(values)

        return collected

    def _collect_sd_data(
        self,
        api: str,
        params: Optional[Mapping[str, Union[str, List[str], None]]] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> List[Any]:
        return self._collect_data(
            api,
            params=params,
            base=self.SERVICEDESK_BASE_URL,
            headers=headers,
            start_at='start',
            is_last='isLastPage',
        )

    def _collect_agile_data(
        self,
        api: str,
        params: Optional[Mapping[str, Union[str, List[str], None]]] = None,
    ) -> List[Any]:
        return self._collect_data(api, params=params, base=self.AGILE_BASE_URL)

    def _get_url(self, api: str) -> str:
        return self._client()._get_url(api)  # type: ignore

    def _get_json(
        self,
        api: str,
        params: Optional[Mapping[str, Union[str, List[str], None]]] = None,
    ) -> Any:
        return self._client()._get_json(api, params=params)

    # forms helpers

    def _parse_data(
        self, uri: str, pat_name: str, pat_id: str, pat_inactive: str
    ) -> List[Dict[str, Any]]:
        page = self._get(uri)
        return [
            {
                'name': name,
                'id': int(sid),
                'active': not re.search(pat_inactive % sid, page.text),
            }
            for name, sid in zip(
                re.findall(pat_name, page.text), re.findall(pat_id, page.text)
            )
        ]

    def _do_form_step(
        self, api: str, data: Dict[str, Any], cookies
    ) -> requests.Response:
        """Perform a project-config step."""
        return requests.post(
            join_url(self.url, api),
            data=data,
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-Atlassian-Token': 'no-check',
            },
            cookies=cookies,
            auth=self.auth,
            verify=self.verify,
        )

    def _get_projectconfig_scheme(
        self, project_id_or_key: Union[str, int], scheme: str
    ) -> str:
        """Return scheme name."""
        ensure_instance('project_id_or_key', (str, int))

        project = self.get_project(project_id_or_key)
        page = self._get(
            f'plugins/servlet/project-config/{project["key"]}/{scheme}'
        )
        match = re.search(
            r'class="project-config-scheme-name"[^>]+>([^<]+)<', page.text
        )
        if match is None:
            raise ApiError('Scheme %s not found' % scheme)
        return match.group(1)

    def _get_projectconfig_option(
        self, api: str, project_id: str, scheme: str
    ) -> Tuple[requests.Response, str]:
        page = self._get(f'{api}?projectId={project_id}')
        option = re.search(
            r'<option value="(\d+)"[^>]*>\s*%s\s*</option>' % scheme, page.text
        )
        if option is None:
            raise ApiError('Scheme %s not found.' % scheme)
        return page, option.group(1)
