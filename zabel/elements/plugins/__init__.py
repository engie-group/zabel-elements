# Copyright (c) 2019 Martin Lafaix (martin.lafaix@external.engie.com)
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

"""
The **zabel.plugins** library abstract base classes.

It provides wrappers for the built-in low-level tooling classes (those
defined in the **zabel.builtins** module).

Those abstract service wrappers implement an `__init__` constructor with
the following three parameters:

- `name`: a string, the service name
- `env`: a dictionary, the service parameters
- `credentials`: a _Credentials_ object

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


from typing import Any, Dict

from zabel.commons.utils import api_call
from zabel.commons.interfaces import Utility, ManagedService
from zabel.commons.credentials import Credentials

from zabel.elements import wrappers

########################################################################


def _get_string_credentials(
    name: str, item: str, credentials: Credentials
) -> str:
    value = credentials.get(name, item)
    if not isinstance(value, str):
        raise ValueError(f'Credentials {item} for {name} must be a string.')
    return value


########################################################################
# Wrappers around low-level APIs


class Artifactory(wrappers.Artifactory, ManagedService):
    """Abstract base _Artifactory_ class.

    Provides a default implementation for the following three
    #::ManagedService methods:

    - `__init__(name, env, credentials)`
    - `list_members`
    - `get_member`

    The `env` dictionary must have at least an `url` entry which refer
    to the API entry point:

        'https://artifactory.example.com/artifactory/api/'

    Credentials for `name` must have two parts: a `user` part (a string)
    and a `token` part (also a string).

    Implementations are expected to extend this class with their
    platform specifics (canonical user IDs, ...).
    """

    # pylint: disable=abstract-method
    def __init__(
        self, name: str, env: Dict[str, Any], credentials: Credentials
    ) -> None:
        user = _get_string_credentials(name, 'user', credentials)
        token = _get_string_credentials(name, 'token', credentials)
        super().__init__(env['url'], user, token)

    def get_internal_member_id(self, member_id: str) -> str:
        ...

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


class CloudBeesJenkins(wrappers.CloudBeesJenkins, ManagedService):
    """Abstract base _CloudBeesJenkins_ class.

    Provides a default implementation for the following three
    #::ManagedService methods:

    - `__init__(name, env, credentials)`
    - `list_members`
    - `get_member`

    The `env` dictionary must have at least an `url` entry which refer
    to the API entry point:

        'https://cbj.example.com'

    Credentials for `name` must have two parts: a `user` part (a string)
    and a `token` part (also a string).
    """

    # pylint: disable=abstract-method
    def __init__(
        self, name: str, env: Dict[str, Any], credentials: Credentials
    ) -> None:
        user = _get_string_credentials(name, 'user', credentials)
        token = _get_string_credentials(name, 'token', credentials)
        super().__init__(env['url'], user, token, env.get('cookies'))

    def get_internal_member_id(self, member_id: str) -> str:
        ...

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


class Confluence(wrappers.Confluence, ManagedService):
    """Abstract base _Confluence_ class.

    Provides a default implementation for the following three
    #::ManagedService methods:

    - `__init__(name, env, credentials)`
    - `list_members`
    - `get_member`

    The `env` dictionary must have at least an `url` entry which refer
    to the API entry point:

        'https://confluence.example.com'

    Credentials for `name` must have either a `basic_auth` part or an
    `oauth` part.

    `basic_auth` is a tuple (a user value and a token value).

    `oauth` is a dictionary with the following entries:

    - `access_token`: a string
    - `access_token_secret`: a string
    - `consumer_key`: a string
    - `key_cert`: a string

    If the provided credentials include both a `basic_auth` part and
    an `oauth` part, a _ValueError_ exception will be raised.
    """

    # pylint: disable=abstract-method
    def __init__(
        self, name: str, env: Dict[str, Any], credentials: Credentials
    ) -> None:
        super().__init__(
            env['url'],
            basic_auth=credentials.get(name, 'basic_auth'),
            oauth=credentials.get(name, 'oauth'),
        )

    def get_internal_member_id(self, member_id: str) -> str:
        ...

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


class GitHub(wrappers.GitHub, ManagedService):
    """Abstract base _GitHub_ class.

    Provides a default implementation for the following three
    #::ManagedService methods:

    - `__init__(name, env, credentials)`
    - `list_members`
    - `get_member`

    The `env` dictionary must have at least an `url` entry which refer
    to the API entry point:

        'https://github.example.com/api/v3/'

    It may also have a `mngt` entry, which is the management entry
    point:

        'https://github.example.com/'

    Credentials for `name` must have two parts: a `user` part (a string)
    and a `token` part (also a string).
    """

    # pylint: disable=abstract-method
    def __init__(
        self, name: str, env: Dict[str, Any], credentials: Credentials
    ) -> None:
        user = _get_string_credentials(name, 'user', credentials)
        token = _get_string_credentials(name, 'token', credentials)
        super().__init__(
            env['url'], user, token, env.get('mngt'),
        )

    def get_internal_member_id(self, member_id: str) -> str:
        ...

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


class Kubernetes(wrappers.Kubernetes, Utility):
    """Abstract base _Kubernetes_ class.

    Provides a default implementation for the following #::Utility
    method:

    - `__init__(name, env, credentials)`

    The `env` dictionary may be empty, in which case the current user's
    `~/.kube/config` configuration file with its default context will be
    used.

    Alternatively, it may contain the following entries:

    - `config_file`: a non-empty string
    - `context`: a non-empty string
    - `config`: a dictionary

    If `config_file` or `context` are present, `config` must not be.

    If neither `config_file` nor `config` are present, the default
    Kubernetes config file will be used.

    If `context` is present, the instance will use the specified
    Kubernetes context.  If not present, the default context will be
    used instead.

    If `config` is present, it must be a dictionary with the following
    entries:

    - `url`: a non-empty string (an URL)

    If may also contain the following entries:

    - `verify`: a boolean (True by default)
    - `ssl_ca_cert`: a string (a base64-encoded certificate)

    The `url` parameter is the top-level API point. E.g.:

        https://FOOBARBAZ.example.com

    `verify` can be set to False if disabling certificate checks for
    Kubernetes communication is required.  Tons of warnings will
    occur if this is set to False.

    Credentials is only used if `config` is specified.  It then must
    have one part: an `api_key`part (a string).
    """

    # pylint: disable=abstract-method
    def __init__(
        self, name: str, env: Dict[str, Any], credentials: Credentials
    ) -> None:
        config_file = env.get('config_file')
        context = env.get('context')
        config = env.get('config')
        if config is not None and config_file is None and context is None:
            config['api_key'] = credentials.get(name, 'api_key')
        super().__init__(
            config_file, context, config,
        )


class Jira(wrappers.Jira, ManagedService):
    """Abstract base _Jira_ class.

    Provides a default implementation for the following three
    #::ManagedService methods:

    - `__init__(name, env, credentials)`
    - `list_members`
    - `get_member`

    The `env` dictionary must have at least an `url` entry which refer
    to the API entry point:

        'https://jira.example.com'

    Credentials for `name` must have either a `basic_auth` part or an
    `oauth` part.

    `basic_auth` is a tuple (a user value and a token value).

    `oauth` is a dictionary with the following entries:

    - `access_token`: a string
    - `access_token_secret`: a string
    - `consumer_key`: a string
    - `key_cert`: a string

    If the provided credentials includes both a `basic_auth` part and
    an `oauth` part, a _ValueError_ exception will be raised.
    """

    # pylint: disable=abstract-method
    def __init__(
        self, name: str, env: Dict[str, Any], credentials: Credentials
    ) -> None:
        super().__init__(
            env['url'],
            basic_auth=credentials.get(name, 'basic_auth'),
            oauth=credentials.get(name, 'oauth'),
        )

    def get_internal_member_id(self, member_id: str) -> str:
        ...

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


class SonarQube(wrappers.SonarQube, ManagedService):
    """Abstract base _SonarQube_ class.

    Provides a default implementation for the following three
    #::ManagedService methods:

    - `__init__(name, env, credentials)`
    - `list_members`
    - `get_member`

    The `env` dictionary must have at least an `url` entry which refer
    to the API entry point:

        'https://sonar.example.com/sonar/api/'

    Credentials for `name` must have a `token` part (a string).
    """

    # pylint: disable=abstract-method
    def __init__(
        self, name: str, env: Dict[str, Any], credentials: Credentials
    ) -> None:
        token = _get_string_credentials(name, 'token', credentials)
        super().__init__(env['url'], token)

    def get_internal_member_id(self, member_id: str) -> str:
        ...

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


class SquashTM(wrappers.SquashTM, ManagedService):
    """Abstract base _SquashTM_ class.

    Provides a default implementation for the following three
    #::ManagedService methods:

    - `__init__(name, env, credentials)`
    - `list_members`
    - `get_member`

    The `env` dictionary must have at least an `url` entry which refer
    to the API entry point:

        'https://squash-tm.example.com/squash/api/rest/latest/'

    Credentials for `name` must have two parts: a `user` part (a string)
    and a `token` part (also a string).
    """

    # pylint: disable=abstract-method
    def __init__(
        self, name: str, env: Dict[str, Any], credentials: Credentials
    ) -> None:
        user = _get_string_credentials(name, 'user', credentials)
        token = _get_string_credentials(name, 'token', credentials)
        super().__init__(env['url'], user, token)

    def get_internal_member_id(self, member_id: str) -> int:
        ...

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
