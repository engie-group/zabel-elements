# Copyright (c) 2019-2020 Martin Lafaix (martin.lafaix@external.engie.com)
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

"""
The **zabel.elements.images** base classes library.

It provides wrappers for the built-in low-level clients classes (those
defined in the **zabel.elements.clients** module).

Those abstract service wrappers implement an `__init__` constructor with
no parameter.

Managed services also implement at least the `list_members()` method of
the #::ManagedService interface.  They may provide `get_member()` if a
fast implementation is available.

Concrete classes deriving those abstract managed services wrappers
should provide a `get_canonical_member_id()` method that takes a
parameter, a user from the wrapped API point of view, and returns the
canonical user ID, as well as a `get_internal_member_id()` method that
takes a canonical user ID and returns the internal key for that user.

They should also provide concrete implementations for the remaining
methods provided by the #::ManagedService interface.

# Conventions

Utilities must implement the #::Utility interface and managed services
must implement the #::ManagedService interface.
"""

__all__ = [
    'Artifactory',
    'CloudBeesJenkins',
    'Confluence',
    'GitHub',
    'Kubernetes',
    'Jira',
    'SonarQube',
    'SquashTM',
    'Okta',
]


from typing import Any, Dict, Iterable, Optional

import json
import os

from zabel.commons.utils import api_call
from zabel.commons.interfaces import ManagedService, Utility

from zabel.elements import clients

########################################################################
# Helpers


def _get_credential(key: str) -> str:
    value = os.environ.get(key)
    if value is None:
        raise ValueError(f'Environment variable {key} not defined.')
    return value


def _maybe_get_credential(key: str) -> Optional[str]:
    return os.environ.get(key)


def _has_credentials(*keys) -> bool:
    return all(os.environ.get(key) for key in keys)


########################################################################
# Wrappers around low-level APIs


class Artifactory(clients.Artifactory, ManagedService):
    """Abstract base _Artifactory_ class.

    Provides a default implementation for the following three
    #::ManagedService methods:

    - `__init__()`
    - `list_members`
    - `get_member`

    The following environment variables must exist:

    - ARTIFACTORY_URL: a string
    - ARTIFACTORY_USER: a string
    - ARTIFACTORY_TOKEN: a string

    The `ARTIFACTORY_URL` entry refers to the API entry point:

        https://artifactory.example.com/artifactory/api/

    Implementations are expected to extend this class with their
    platform specifics (canonical user IDs, ...).
    """

    # pylint: disable=abstract-method
    def __init__(self) -> None:
        url = _get_credential('ARTIFACTORY_URL')
        user = _get_credential('ARTIFACTORY_USER')
        token = _get_credential('ARTIFACTORY_TOKEN')
        super().__init__(url, user, token)

    def get_internal_member_id(self, member_id: str) -> str:
        raise NotImplementedError

    @api_call
    def list_members(self) -> Dict[str, Dict[str, Any]]:
        """Return the members on the service.

        # Returned values

        A dictionary.  The keys are the canonical IDs and the values are
        the representations of a user for the service.
        """
        return {
            self.get_canonical_member_id(user): user
            for user in self.list_users_details()
        }

    @api_call
    def get_member(self, member_id: str) -> Dict[str, Any]:
        """Return details on user.

        # Required parameters

        - member_id: a string

        `member_id` is the canonical member ID.

        # Returned value

        The representation of the user for the service, which is
        service-specific.
        """
        return self.get_user(self.get_internal_member_id(member_id))


class CloudBeesJenkins(clients.CloudBeesJenkins, ManagedService):
    """Abstract base _CloudBeesJenkins_ class.

    Provides a default implementation for the following three
    #::ManagedService methods:

    - `__init__()`
    - `list_members`
    - `get_member`

    The following environment variables must exist:

    - JENKINS_URL: a string
    - JENKINS_USER: a string
    - JENKINS_TOKEN: a string

    The environment may also contain a `JENKINS_COOKIES` entry.

    The `JENKINS_URL` entry refers to the API entry point:

        https://cbj.example.com
    """

    # pylint: disable=abstract-method
    def __init__(self) -> None:
        url = _get_credential('JENKINS_URL')
        user = _get_credential('JENKINS_USER')
        token = _get_credential('JENKINS_TOKEN')
        cookies = None
        if _has_credentials('JENKINS_COOKIES'):
            cookies = json.loads(_get_credential('JENKINS_COOKIES'))
        super().__init__(url, user, token, cookies)

    def get_internal_member_id(self, member_id: str) -> str:
        raise NotImplementedError

    @api_call
    def list_members(self) -> Dict[str, Dict[str, Any]]:
        """Return the members on the service.

        # Returned values

        A dictionary.  The keys are the canonical IDs and the values are
        the representations of a user for the service.
        """
        return {
            self.get_canonical_member_id(u): u for u in self.list_oc_users()
        }

    @api_call
    def get_member(self, member_id: str) -> Dict[str, Any]:
        """Return details on user.

        # Required parameters

        - member_id: a string

        `member_id` is the canonical member ID.

        # Returned value

        The representation of the user for the service, which is
        service-specific.
        """
        return self.list_members()[member_id]


class Confluence(clients.Confluence, ManagedService):
    """Abstract base _Confluence_ class.

    Provides a default implementation for the following three
    #::ManagedService methods:

    - `__init__()`
    - `list_members`
    - `get_member`

    The following environment variable must exist:

    - CONFLUENCE_URL: a string

    The environment also must have either the two following entries
    (basic auth):

    - CONFLUENCE_USER: a string
    - CONFLUENCE_TOKEN: a string

    Or the four following entries (oauth):

    - CONFLUENCE_KEYCERT: a string
    - CONFLUENCE_CONSUMERKEY: a string
    - CONFLUENCE_ACCESSTOKEN: a string
    - CONFLUENCE_ACCESSSECRET: a string

    The `CONFLUENCE_URL` entry refers to the API entry point:

        https://confluence.example.com

    A _ValueError_ is raised if either none or both the basic and oauth
    credentials are provided.
    """

    # pylint: disable=abstract-method
    def __init__(self) -> None:
        url = _get_credential('CONFLUENCE_URL')
        basic_auth = oauth = None
        if _has_credentials('CONFLUENCE_USER', 'CONFLUENCE_TOKEN'):
            basic_auth = (
                _get_credential('CONFLUENCE_USER'),
                _get_credential('CONFLUENCE_TOKEN'),
            )
        if _has_credentials(
            'CONFLUENCE_KEYCERT',
            'CONFLUENCE_CONSUMERKEY',
            'CONFLUENCE_ACCESSTOKEN',
            'CONFLUENCE_ACCESSSECRET',
        ):
            oauth = {
                'key_cert': _get_credential('CONFLUENCE_KEYCERT'),
                'consumer_key': _get_credential('CONFLUENCE_CONSUMERKEY'),
                'access_token': _get_credential('CONFLUENCE_ACCESSTOKEN'),
                'access_token_secret': _get_credential(
                    'CONFLUENCE_ACCESSSECRET'
                ),
            }
        super().__init__(url, basic_auth=basic_auth, oauth=oauth)

    def get_internal_member_id(self, member_id: str) -> str:
        raise NotImplementedError

    @api_call
    def list_members(self) -> Dict[str, Dict[str, Any]]:
        """Return the members on the service.

        # Returned values

        A dictionary.  The keys are the canonical IDs and the values are
        the representations of a user for the service.
        """
        return {u: self.get_user(u) for u in self.list_users()}

    @api_call
    def get_member(self, member_id: str) -> Dict[str, Any]:
        """Return details on user.

        # Required parameters

        - member_id: a string

        `member_id` is the canonical member ID.

        # Returned value

        The representation of the user for the service, which is
        service-specific.
        """
        return self.get_user(member_id)


class GitHub(clients.GitHub, ManagedService):
    """Abstract base _GitHub_ class.

    Provides a default implementation for the following three
    #::ManagedService methods:

    - `__init__()`
    - `list_members`
    - `get_member`

    The following environment variables must exist:

    - GITHUB_URL: a string
    - GITHUB_USER: a string
    - GITHUB_TOKEN: a string

    The environment may also have a `GITHUB_MNGT` entry (a string).

    The `GITHUB_URL` entry refers to the API entry point:

        https://github.example.com/api/v3/

    The `GITHUB_MNGT` entry is the management entry point:

        https://github.example.com/
    """

    # pylint: disable=abstract-method
    def __init__(self) -> None:
        url = _get_credential('GITHUB_URL')
        user = _get_credential('GITHUB_USER')
        token = _get_credential('GITHUB_TOKEN')
        mngt = None
        if _has_credentials('GITHUB_MNGT'):
            mngt = _get_credential('GITHUB_MNGT')
        super().__init__(url, user, token, mngt)

    def get_internal_member_id(self, member_id: str) -> str:
        raise NotImplementedError

    @api_call
    def list_members(self) -> Dict[str, Dict[str, Any]]:
        """Return the members on the service.

        # Returned values

        A dictionary.  The keys are the canonical IDs and the values are
        the representations of a user for the service.
        """
        return {self.get_canonical_member_id(u): u for u in self.list_users()}

    @api_call
    def get_member(self, member_id: str) -> Dict[str, Any]:
        """Return details on user.

        # Required parameters

        - member_id: a string

        `member_id` is the canonical member ID.

        # Returned value

        The representation of the user for the service, which is
        service-specific.
        """
        return self.get_user(self.get_internal_member_id(member_id))


class Kubernetes(clients.Kubernetes, Utility):
    """Abstract base _Kubernetes_ class.

    Provides a default implementation for the following #::Utility
    method:

    - `__init__()`

    The environment may contain none of the following `KUBERNETES_xxx`
    entries, in which case the current user's `~/.kube/config` config
    file with its default context will be used.

    Alternatively, it may contain some of the following entries:

    - KUBERNETES_CONFIGFILE: a string (a fully qualified file name)
    - KUBERNETES_CONTEXT: a string

    - KUBERNETES_CONFIG_URL: a string (an URL)
    - KUBERNETES_CONFIG_API_KEY: a string
    - KUBERNETES_CONFIG_VERIFY: a string
    - KUBERNETES_CONFIG_SSL_CA_CERT: a string (a base64-encoded
      certificate)

    # Reusing an existing config file

    If `KUBERNETES_CONFIGFILE` and/or `KUBERNETES_CONTEXT` are present,
    there must be no `KUBERNETES_CONFIG_xxx` entries.

    If `KUBERNETES_CONFIGFILE` is present, the specified config file
    will be used.  If not present, the default Kubernetes config file
    will be used (`~/.kube/config`, usually).

    If `KUBERNETES_CONTEXT` is present, the instance will use the
    specified Kubernetes context.  If not present, the default context
    will be used instead.

    # Specifying an explicit configuration (no config file needed)

    If `KUBERNETES_CONFIG_xxx` entries are present, they provide an
    explicit configuration.  The possibly existing `~/.kube/config`
    config file will be ignored.

    In this case, `KUBERNETES_CONFIG_URL` is mandatory.  It is the
    top-level API point.  E.g.:

        https://FOOBARBAZ.example.com

    `KUBERNETES_CONFIG_API_KEY` is also mandatory.  It will typically be
    a JWT token.

    The following two additional entries may be present:

    `KUBERNETES_CONFIG_VERIFY` can be set to 'false' (case insensitive)
    if disabling certificate checks for Kubernetes communication is
    required.  Tons of warnings will occur if this is set to 'false'.

    `KUBERNETES_CONFIG_SSL_CA_CERT` is a base64-encoded certificate.
    """

    # pylint: disable=abstract-method
    def __init__(self) -> None:
        config_file = _maybe_get_credential('KUBERNETES_CONFIGFILE')
        context = _maybe_get_credential('KUBERNETES_CONTEXT')
        url = _maybe_get_credential('KUBERNETES_URL')
        api_key = _maybe_get_credential('KUBERNETES_API_KEY')
        ssl_ca_cert = _maybe_get_credential('KUBERNETES_SSL_CA_CERT')
        verify = _maybe_get_credential('KUBERNETES_VERIFY')

        config: Optional[Dict[str, Any]] = None
        if config_file is None and context is None:
            if url and api_key:
                config = {'url': url, 'api_key': api_key}
                if ssl_ca_cert:
                    config['ssl_ca_cert'] = ssl_ca_cert
                if verify and verify.upper() == 'FALSE':
                    config['verify'] = False
            elif url:
                raise ValueError('URL defined but no API_KEY specified.')
            elif api_key:
                raise ValueError('API_KEY defined but no URL specifics.')
        super().__init__(config_file, context, config)


class Jira(clients.Jira, ManagedService):
    """Abstract base _Jira_ class.

    Provides a default implementation for the following three
    #::ManagedService methods:

    - `__init__()`
    - `list_members`
    - `get_member`

    The following environment variable must exist:

    - JIRA_URL: a string

    The environment also must have either the two following entries
    (basic auth):

    - JIRA_USER: a string
    - JIRA_TOKEN: a string

    Or the four following entries (oauth):

    - JIRA_KEYCERT: a string
    - JIRA_CONSUMERKEY: a string
    - JIRA_ACCESSTOKEN: a string
    - JIRA_ACCESSSECRET: a string

    The `JIRA_URL` entry refers to the API entry point:

        https://jira.example.com

    A _ValueError_ is raised if either none or both the basic and oauth
    credentials are provided.
    """

    # pylint: disable=abstract-method
    def __init__(self) -> None:
        url = _get_credential('JIRA_URL')
        basic_auth = oauth = None
        if _has_credentials('JIRA_USER', 'JIRA_TOKEN'):
            basic_auth = (
                _get_credential('JIRA_USER'),
                _get_credential('JIRA_TOKEN'),
            )
        if _has_credentials(
            'JIRA_KEYCERT',
            'JIRA_CONSUMERKEY',
            'JIRA_ACCESSTOKEN',
            'JIRA_ACCESSSECRET',
        ):
            oauth = {
                'key_cert': _get_credential('JIRA_KEYCERT'),
                'consumer_key': _get_credential('JIRA_CONSUMERKEY'),
                'access_token': _get_credential('JIRA_ACCESSTOKEN'),
                'access_token_secret': _get_credential('JIRA_ACCESSSECRET'),
            }
        super().__init__(url, basic_auth=basic_auth, oauth=oauth)

    def get_internal_member_id(self, member_id: str) -> str:
        raise NotImplementedError

    @api_call
    def list_members(self) -> Dict[str, Dict[str, Any]]:
        """Return the members on the service.

        # Returned values

        A dictionary.  The keys are the canonical IDs and the values are
        the representations of a user for the service.
        """
        return {u: self.get_user(u) for u in self.list_users()}

    @api_call
    def get_member(self, member_id: str) -> Dict[str, Any]:
        """Return details on user.

        # Required parameters

        - member_id: a string

        `member_id` is the canonical member ID.

        # Returned value

        The representation of the user for the service, which is
        service-specific.
        """
        return self.get_user(self.get_internal_member_id(member_id))


class SonarQube(clients.SonarQube, ManagedService):
    """Abstract base _SonarQube_ class.

    Provides a default implementation for the following three
    #::ManagedService methods:

    - `__init__()`
    - `list_members`
    - `get_member`

    The following environment variables must exist:

    - SONARQUBE_URL: a string
    - SONARQUBE_TOKEN: a string

    The `SONARQUBE_URL` entry refers to the API entry point:

        https://sonar.example.com/sonar/api/
    """

    # pylint: disable=abstract-method
    def __init__(self) -> None:
        url = _get_credential('SONARQUBE_URL')
        token = _get_credential('SONARQUBE_TOKEN')
        super().__init__(url, token)

    def get_internal_member_id(self, member_id: str) -> str:
        raise NotImplementedError

    @api_call
    def list_members(self) -> Dict[str, Dict[str, Any]]:
        """Return the members on the service.

        # Returned values

        A dictionary.  The keys are the canonical IDs and the values are
        the representations of a user for the service.
        """
        return {
            self.get_canonical_member_id(u): u for u in self.search_users()
        }

    @api_call
    def get_member(self, member_id: str) -> Dict[str, Any]:
        """Return details on user.

        # Required parameters

        - member_id: a string

        `member_id` is the canonical member ID.

        # Returned value

        The representation of the user for the service, which is
        service-specific.
        """
        return self.get_user(self.get_internal_member_id(member_id))


class SquashTM(clients.SquashTM, ManagedService):
    """Abstract base _SquashTM_ class.

    Provides a default implementation for the following three
    #::ManagedService methods:

    - `__init__()`
    - `list_members`
    - `get_member`

    The following environment variables must exist:

    - SQUASHTM_URL: a string
    - SQUASHTM_USER: a string
    - SQUASHTM_TOKEN: a string

    The `SQUASHTM_URL` entry refers to the API entry point:

        https://squash-tm.example.com/squash/api/rest/latest/
    """

    # pylint: disable=abstract-method
    def __init__(self) -> None:
        url = _get_credential('SQUASHTM_URL')
        user = _get_credential('SQUASHTM_USER')
        token = _get_credential('SQUASHTM_TOKEN')
        super().__init__(url, user, token)

    def get_internal_member_id(self, member_id: str) -> int:
        raise NotImplementedError

    @api_call
    def list_members(self) -> Dict[str, Dict[str, Any]]:
        """Return the members on the service.

        # Returned values

        A dictionary.  The keys are the canonical IDs and the values are
        the representations of a user for the service.
        """
        return {
            self.get_canonical_member_id(u): self.get_user(u['id'])
            for u in self.list_users()
        }

    @api_call
    def get_member(self, member_id: str) -> Dict[str, Any]:
        """Return details on user.

        # Required parameters

        - member_id: a string

        `member_id` is the canonical member ID.

        # Returned value

        The representation of the user for the service, which is
        service-specific.
        """
        return self.get_user(self.get_internal_member_id(member_id))


class Okta(clients.Okta, Utility):
    """Abstract base _Okta_ class.

    Provides a default implementation for the following #::Utility
    method:

    - `__init__()`

    The following environment variables must exist:

    - OKTA_URL: a string
    - OKTA_TOKEN: a string

    The `OKTA_URL` entry refers to the API entry point:

        https://okta.example.com
    """

    def __init__(self) -> None:
        url = _get_credential('OKTA_URL')
        token = _get_credential('OKTA_TOKEN')
        super().__init__(url, token)
