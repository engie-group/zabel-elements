# Copyright (c) 2019-2020 Martin Lafaix (martin.lafaix@external.engie.com)
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

"""
The **zabel.elements** plugins base classes library.

It provides wrappers for the built-in low-level tooling classes (those
defined in the **zabel.elements.clients** module).

Those abstract service wrappers implement an `__init__` constructor with
the following two parameters:

- `name`: a string, the service name
- `env`: a dictionary, the service parameters

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
]


from typing import Any, Dict, Iterable, Optional

from zabel.commons.utils import api_call
from zabel.commons.interfaces import ManagedService, Utility

from zabel.elements import clients

########################################################################


def _get_credential(name: str, item: str, env: Dict[str, Any]) -> str:
    value = env.get(f'{name.upper()}_{item.upper()}')
    if not isinstance(value, str):
        raise ValueError(f'Credentials {item} for {name} must be a string.')
    return value


def _maybe_get_credential(
    name: str, item: str, env: Dict[str, Any]
) -> Optional[str]:
    value = env.get(f'{name.upper()}_{item.upper()}')
    if value is not None and not isinstance(value, str):
        raise ValueError(f'Credentials {item} for {name} must be a string.')
    return value


def _has_credentials(
    name: str, items: Iterable[str], env: Dict[str, Any]
) -> bool:
    return all(env.get(f'{name.upper()}_{item.upper()}') for item in items)


########################################################################
# Wrappers around low-level APIs


class Artifactory(clients.Artifactory, ManagedService):
    """Abstract base _Artifactory_ class.

    Provides a default implementation for the following three
    #::ManagedService methods:

    - `__init__(name, env)`
    - `list_members`
    - `get_member`

    The `env` dictionary must have at least the following entries:

    - {NAME}_URL: a string
    - {NAME}_USER: a string
    - {NAME}_TOKEN: a string

    The `{NAME}_URL` entry refers to the API entry point:

        https://artifactory.example.com/artifactory/api/

    Implementations are expected to extend this class with their
    platform specifics (canonical user IDs, ...).
    """

    # pylint: disable=abstract-method
    def __init__(self, name: str, env: Dict[str, Any]) -> None:
        url = _get_credential(name, 'url', env)
        user = _get_credential(name, 'user', env)
        token = _get_credential(name, 'token', env)
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

    - `__init__(name, env)`
    - `list_members`
    - `get_member`

    The `env` dictionary must have at least the following entries:

    - {NAME}_URL: a string
    - {NAME}_USER: a string
    - {NAME}_TOKEN: a string

    It may also have a `{NAME}_COOKIES` entry (a string).

    The `{NAME}_URL` entry refers to the API entry point:

        https://cbj.example.com
    """

    # pylint: disable=abstract-method
    def __init__(self, name: str, env: Dict[str, Any]) -> None:
        url = _get_credential(name, 'url', env)
        user = _get_credential(name, 'user', env)
        token = _get_credential(name, 'token', env)
        cookies = None
        if _has_credentials(name, ('cookies',), env):
            cookies = _get_credential(name, 'cookies', env)
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

    - `__init__(name, env)`
    - `list_members`
    - `get_member`

    The `env` dictionary must have at least the following entries:

    - {NAME}_URL: a string

    It also must have either the two following entries (basic auth):

    - {NAME}_USER: a string
    - {NAME}_TOKEN: a string

    Or the four following entries (oauth):

    - {NAME}_KEYCERT: a string
    - {NAME}_CONSUMERKEY: a string
    - {NAME}_ACCESSTOKEN: a string
    - {NAME}_ACCESSSECRET: a string

    The `{NAME}_URL` entry refers to the API entry point:

        https://confluence.example.com

    A _ValueError_ is raised if either none or both the basic and oauth
    credentials are provided.
    """

    # pylint: disable=abstract-method
    def __init__(self, name: str, env: Dict[str, Any]) -> None:
        url = _get_credential(name, 'url', env)
        basic_auth = oauth = None
        if _has_credentials(name, ('user', 'token'), env):
            basic_auth = (
                _get_credential(name, 'user', env),
                _get_credential(name, 'token', env),
            )
        if _has_credentials(
            name,
            ('keycert', 'consumerkey', 'accesstoken', 'accesssecret'),
            env,
        ):
            oauth = {
                'key_cert': _get_credential(name, 'keycert', env),
                'consumer_key': _get_credential(name, 'consumerkey', env),
                'access_token': _get_credential(name, 'accesstoken', env),
                'access_token_secret': _get_credential(
                    name, 'accesssecret', env
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

    - `__init__(name, env)`
    - `list_members`
    - `get_member`

    The `env` dictionary must have at least the following entries:

    - {NAME}_URL: a string
    - {NAME}_USER: a string
    - {NAME}_TOKEN: a string

    It may also have a `{NAME}_MNGT` entry (a string).

    The `{NAME}_URL` entry refers to the API entry point:

        https://github.example.com/api/v3/

    The `{NAME}_MNGT` entry is the management entry point:

        https://github.example.com/
    """

    # pylint: disable=abstract-method
    def __init__(self, name: str, env: Dict[str, Any]) -> None:
        url = _get_credential(name, 'url', env)
        user = _get_credential(name, 'user', env)
        token = _get_credential(name, 'token', env)
        mngt = None
        if _has_credentials(name, ('mngt',), env):
            mngt = _get_credential(name, 'mngt', env)
        super().__init__(url, user, token, env.get('mngt'))

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

    - `__init__(name, env)`

    The `env` dictionary may be empty, in which case the current user's
    `~/.kube/config` config file with its default context will be used.

    Alternatively, it may contain some of the following entries:

    - {NAME}_CONFIGFILE: a string (a fully qualified file name)
    - {NAME}_CONTEXT: a string

    - {NAME}_CONFIG_URL: a string (an URL)
    - {NAME}_CONFIG_API_KEY: a string
    - {NAME}_CONFIG_VERIFY: a string
    - {NAME}_CONFIG_SSL_CA_CERT: a string (a base64-encoded certificate)

    # Reusing an existing config file

    If `{NAME}_CONFIGFILE` and/or `{NAME}_CONTEXT` are present, there
    must be no `{NAME}_CONFIG_xxx` entries.

    If `{NAME}_CONFIGFILE` is present, the specified config file
    will be used.  If not present, the default Kubernetes config file
    will be used (`~/.kube/config`, usually).

    If `{NAME}_CONTEXT` is present, the instance will use the specified
    Kubernetes context.  If not present, the default context will be
    used instead.

    # Specifying an explicit configuration (no config file needed)

    If `{NAME}_CONFIG_xxx` entries are present, they provide an explicit
    configuration.  The possibly existing `~/.kube/config` config file
    will be ignored.

    In this case, `{NAME}_CONFIG_URL` is mandatory.  It is the top-level
    API point.  E.g.:

        https://FOOBARBAZ.example.com

    `{NAME}_CONFIG_API_KEY` is also mandatory.  It will typically be a
    JWT token.

    The following two additional entries may be present:

    `{NAME}_CONFIG_VERIFY` can be set to 'false' (case insensitive) if
    disabling certificate checks for Kubernetes communication is
    required.  Tons of warnigns will occur if this is set to 'false'.

    `{NAME}_CONFIG_SSL_CA_CERT` is a base64-encoded certificate.
    """

    # pylint: disable=abstract-method
    def __init__(self, name: str, env: Dict[str, Any]) -> None:
        config_file = _maybe_get_credential(name, 'configfile', env)
        context = _maybe_get_credential(name, 'context', env)
        url = _maybe_get_credential(name, 'url', env)
        api_key = _maybe_get_credential(name, 'api_key', env)
        ssl_ca_cert = _maybe_get_credential(name, 'ssl_ca_cert', env)
        verify = _maybe_get_credential(name, 'verify', env)
        config = None
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

    - `__init__(name, env)`
    - `list_members`
    - `get_member`

    The `env` dictionary must have at least the following entries:

    - {NAME}_URL: a string

    It also must have either the two following entries (basic auth):

    - {NAME}_USER: a string
    - {NAME}_TOKEN: a string

    Or the four following entries (oauth):

    - {NAME}_KEYCERT: a string
    - {NAME}_CONSUMERKEY: a string
    - {NAME}_ACCESSTOKEN: a string
    - {NAME}_ACCESSSECRET: a string

    The `{NAME}_URL` entry refers to the API entry point:

        https://jira.example.com

    A _ValueError_ is raised if either none or both the basic and oauth
    credentials are provided.
    """

    # pylint: disable=abstract-method
    def __init__(self, name: str, env: Dict[str, Any]) -> None:
        url = _get_credential(name, 'url', env)
        basic_auth = oauth = None
        if _has_credentials(name, ('user', 'token'), env):
            basic_auth = (
                _get_credential(name, 'user', env),
                _get_credential(name, 'token', env),
            )
        if _has_credentials(
            name,
            ('keycert', 'consumerkey', 'accesstoken', 'accesssecret'),
            env,
        ):
            oauth = {
                'key_cert': _get_credential(name, 'keycert', env),
                'consumer_key': _get_credential(name, 'consumerkey', env),
                'access_token': _get_credential(name, 'accesstoken', env),
                'access_token_secret': _get_credential(
                    name, 'accesssecret', env
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
        return self.get_user(self.get_internal_member_id(member_id))


class SonarQube(clients.SonarQube, ManagedService):
    """Abstract base _SonarQube_ class.

    Provides a default implementation for the following three
    #::ManagedService methods:

    - `__init__(name, env)`
    - `list_members`
    - `get_member`

    The `env` dictionary must have at least the following entries:

    - {NAME}_URL: a string
    - {NAME}_TOKEN: a string

    The `{NAME}_URL` entry refers to the API entry point:

        https://sonar.example.com/sonar/api/
    """

    # pylint: disable=abstract-method
    def __init__(self, name: str, env: Dict[str, Any]) -> None:
        url = _get_credential(name, 'url', env)
        token = _get_credential(name, 'token', env)
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

    - `__init__(name, env)`
    - `list_members`
    - `get_member`

    The `env` dictionary must have at least the following entries:

    - {NAME}_URL: a string
    - {NAME}_USER: a string
    - {NAME}_TOKEN: a string

    The `{NAME}_URL` entry refers to the API entry point:

        https://squash-tm.example.com/squash/api/rest/latest/
    """

    # pylint: disable=abstract-method
    def __init__(self, name: str, env: Dict[str, Any]) -> None:
        url = _get_credential(name, 'url', env)
        user = _get_credential(name, 'user', env)
        token = _get_credential(name, 'token', env)
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
