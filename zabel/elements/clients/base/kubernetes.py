# Copyright (c) 2019 Martin Lafaix (martin.lafaix@external.engie.com)
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

"""A base class wrapping Kubernetes APIs.

There can be as many _Kubernetes_ instances as needed.

This module depends on the public **kubernetes** library.  It also
depends on one **zabel-commons** module, #::zabel.commons.utils.

A base class wrapper only implements 'simple' API requests.  It handles
pagination if appropriate, but does not process the results or compose
API requests.
"""

from typing import Any, Dict, List, Optional

from zabel.commons.utils import api_call, ensure_nonemptystring

########################################################################
########################################################################

# Kubernetes low-level api


DEFAULT_NAMESPACE = 'default'


class Kubernetes:
    """Kubernetes Base-Level Wrapper.

    !!! warning
        Preliminary work.  Not stable.  May change at any time.

    # Reference URL
    ...

    # Implemented features

    - `namespaces`
    - `resource quota`

    # Sample use

    Using the default context as defined in the `~/.kube/config`
    configuration file:

    ```python
    from zabel.elements.clients import Kubernetes

    k8s = Kubernetes()
    namespaces = k8s.list_namespaces()
    ```

    Using explicit configuration:

    ```python
    from zabel.elements.clients import Kubernetes

    K8S_URL = 'https://kubernetes.example.com'
    k8s = Kubernetes(
        config={
            'url': K8S_URL,
            'api_key': '...',
            'verify': False,
        }
    )
    namespaces = k8s.list_namespaces()
    ```
    """

    def __init__(
        self,
        config_file: Optional[str] = None,
        context: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Create a Kubernetes instance object.

        By default, will use the standard context in Kubernetes config
        file.

        # Optional parameters

        - config_file: a non-empty string or None (None by default)
        - context: a non-empty string or None (None by default)
        - config: a dictionary or None (None by default)

        If `config_file` or `context` are specified, `config` must
        be None.

        If neither `config_file` nor `config` are specified, the default
        Kubernetes config file will be used.

        If `context` is specified, the instance will use the
        specified Kubernetes context.  If not specified, the default
        context will be use instead.

        If `config` is specified, it must be a dictionary with the
        following entries:

        - url: a non-empty string
        - api_key: a non-empty string (a JWT token)

        If may also contain the following entries:

        - verify: a boolean (True by default)
        - ssl_ca_cert: a string (a base64-encoded certificate)
        - ssl_ca_cert_file: a string (an existing file name)

        The `url` parameter is the top-level API point. E.g.:

            https://FOOBARBAZ.example.com

        `verify` can be set to False if disabling certificate checks for
        Kubernetes communication is required.  Tons of warnings will
        occur if this is set to False.

        If both `ssl_ca_cert` and `ssl_ca_cert_file` are specified,
        `ssl_ca_cert_file` will be ignored.
        """
        from kubernetes import client as klient, config as konfig

        self._klient = klient
        if config is not None and (
            config_file is not None or context is not None
        ):
            raise ValueError(
                'config cannot be set if config_file or context are set'
            )

        _config = klient.Configuration()
        if config is not None:
            _config.api_key_prefix['authorization'] = 'Bearer'
            _config.api_key['authorization'] = config.get('api_key')
            _config.host = config.get('url')
            _config.verify_ssl = config.get('verify', True)
            if 'ssl_ca_cert' in config or 'ssl_ca_cert_file' in config:
                _config.ssl_ca_cert = konfig.kube_config.FileOrData(
                    config, 'ssl_ca_cert_file', 'ssl_ca_cert'
                ).as_file()
        else:
            konfig.load_kube_config(
                config_file=config_file,
                context=context,
                client_configuration=_config,
            )
        self._config = _config
        self._apiclient = self._v1client = self._rbacv1_client = None

    def __str__(self) -> str:
        return f'{self.__class__.__name__}: {self._config.host}'

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__}: {self._config.host!r}>'

    ####################################################################
    # create_namespace
    # delete_namespace
    # read_namespace
    # list_namespaces
    #
    # list_resourcequotas
    # patch_resourcequota
    #
    # ? create_role
    # ? create_role_binding
    # ? create_service_account
    #
    # list_configmaps
    # read_configmap

    @api_call
    def create_namespace(self, namespace: str) -> Dict[str, Any]:
        """Create namespace.

        # Required parameters

        - namespace: a non-empty string

        # Returned value

        A dictionary with the following entries:

        - api_version: a string
        - kind: a string
        - metadata: a dictionary
        - spec: a dictionary
        - status: a dictionary
        """
        ensure_nonemptystring('namespace')

        metadata = self._klient.V1ObjectMeta()
        metadata.name = namespace
        metadata.labels = {'name': namespace}
        _namespace = self._klient.V1Namespace()
        _namespace.metadata = metadata

        return self._get_v1_client().create_namespace(_namespace).to_dict()  # type: ignore

    @api_call
    def read_namespace(self, namespace: str) -> Dict[str, Any]:
        """Read namespace.

        # Required parameters

        - namespace: a non-empty string

        # Returned value

        A dictionary with the following entries:

        - api_version: a string
        - kind: a string
        - metadata: a dictionary
        - spec: a dictionary
        - status: a dictionary
        """
        ensure_nonemptystring('namespace')

        return self._get_v1_client().read_namespace(namespace).to_dict()  # type: ignore

    @api_call
    def delete_namespace(self, namespace: str) -> Dict[str, Any]:
        """Delete namespace.

        # Required parameters

        - namespace: a non-empty string

        # Returned value

        A dictionary with the following entries:

        - api_version: a string
        - code: ... or None
        - details: ... or None
        - kind: a string
        - message: ... or None
        - metadata: a dictionary
        - reason: ... or None
        - status: a dictionary
        """
        ensure_nonemptystring('namespace')

        return self._get_v1_client().delete_namespace(namespace).to_dict()  # type: ignore

    @api_call
    def list_namespaces(self) -> List[Dict[str, Any]]:
        """Return a list of namespaces.

        # Returned value

        A list of _namespaces_.  Each namespace in the returned list is
        a dictionary with the following entries:

        - api_version: a string
        - kind: a string
        - metadata: a dictionary
        - spec: a dictionary
        - status: a dictionary
        """
        return [
            item.to_dict()
            for item in self._get_v1_client().list_namespace().items
        ]

    @api_call
    def list_resourcequotas(
        self, *, namespace: str = DEFAULT_NAMESPACE
    ) -> List[Dict[str, Any]]:
        """Return a list of resource quota in namespace.

        # Optional parameters

        - namespace: a string

        # Returned value

        A list of _resource quota_.  Each resource quota is a dictionary
        with the following entries:

        - api_version: a string
        - kind: a string
        - metadata: a dictionary
        - spec: a dictionary
        - status: a dictionary
        """
        return [
            item.to_dict()
            for item in self._get_v1_client()
            .list_namespaced_resource_quota(namespace)
            .items
        ]

    @api_call
    def patch_resourcequota(
        self,
        name: str,
        body: Dict[str, Any],
        *,
        namespace: str = DEFAULT_NAMESPACE,
    ) -> Dict[str, Any]:
        """Patch a resource quota in a namespace.

        # Required parameters

        - name: a string
        - body: a dictionary

        # Optional parameters

        - namespace: a string

        # Returned value

        A dictionary.
        """
        result = (
            self._get_v1_client()
            .patch_namespaced_resource_quota(
                namespace=namespace, name=name, body=body
            )
            .to_dict()
        )
        return result  # type: ignore

    @api_call
    def list_configmaps(
        self, namespace: str = DEFAULT_NAMESPACE
    ) -> List[Dict[str, Any]]:
        """Return a list of configmaps in namespace.

        # Optional parameters

        - namespace: a string

        # Returned value

        A list of _configmaps_.  Each configmap is a dictionary with the
        following entries:

        - api_version: a string
        - data: a dictionary
        - kind: a string
        - metadata: a dictionary
        """
        return [
            item.to_dict()
            for item in self._get_v1_client()
            .list_namespaced_config_map(namespace)
            .items
        ]

    @api_call
    def read_configmap(
        self, name: str, namespace: str = DEFAULT_NAMESPACE
    ) -> Dict[str, Any]:
        """Read a configmap in a namespace.

        # Required parameters

        - name: a string

        # Optional parameters

        - namespace: a string

        # Returned value

        A dictionary.
        """
        return (
            self._get_v1_client()
            .read_namespaced_config_map(name, namespace)
            .to_dict()
        )

    ####################################################################
    # kubernetes clients

    def _get_apiclient(self) -> Any:
        """Return the API client."""
        if self._apiclient is None:
            self._apiclient = self._klient.ApiClient(self._config)
        return self._apiclient

    def _get_v1_client(self) -> Any:
        """Return Core v1 API client."""
        if self._v1client is None:
            self._v1client = self._klient.CoreV1Api(self._get_apiclient())
        return self._v1client

    def _get_rbacv1_client(self) -> Any:
        """Return RbacAuthorizationV1Api client."""
        if self._rbacv1_client is None:
            self._rbacv1_client = self._klient.RbacAuthorizationV1Api(
                self._get_apiclient()
            )
        return self._rbacv1_client
