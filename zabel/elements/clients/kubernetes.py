# Copyright (c) 2019 Martin Lafaix (martin.lafaix@external.engie.com)
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

"""Kubernetes.

A class wrapping Kubernetes APIs.

There can be as many Kubernetes instances as needed.

This module depends on the #::.base.Kubernetes module.
"""

from typing import Any, IO, Union

from .base.kubernetes import Kubernetes as Base


class Kubernetes(Base):
    """Kubernetes Low-Level Wrapper.

    !!! warning
        Preliminary work.  Not stable.  May change at any time.

    There can be as many _Kubernetes_ instances as needed.

    This module depends on the public **kubernetes** library.  It also
    depends on one **zabel-commons** module, #::zabel.commons.utils.

    # Reference URL

    - <https://github.com/kubernetes-client/python>

    # Implemented features

    - namespaces
    - resource quota
    - create and patch from YAML manifests

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

    def create_from_yaml(
        self,
        source: Union[str, IO[str]],
        namespace: str = 'default',
        **kwargs: Any,
    ) -> None:
        """Create Kubernetes object(s) as defined in source stream.

        If more than one object is specified in `source`, it will
        attempt to create all objects.  If one creation fails, the
        remaining operations will be attempted nonetheless.

        # Required parameters

        - source: a non-empty string or an IO object

        # Optional parameters

        - namespace: a non-empty string (`default` by default)
        - ...

        Other keywords parameters can be specified.  They will be passed
        as-is to the Kubernetes API.

        # Returned value

        None.

        # Raised exceptions

        If at least one Kubernetes operation fails, a _KubernetesError_
        exception is raised.  Its `api_exceptions` attribute contain the
        list of exceptions raised by the failed Kubernetes operations.
        """
        from .kubehelpers import _map, _create_from_dict

        _map(
            _create_from_dict,
            source,
            self._get_apiclient(),
            namespace=namespace,
            **kwargs,
        )

    def apply_from_yaml(
        self,
        source: Union[str, IO[str]],
        namespace: str = 'default',
        **kwargs: Any,
    ) -> None:
        """Apply Kubernetes object(s) as defined in source stream.

        If more than one object is specified in `source`, it will
        attempt to apply all objects.  If one apply fails, the
        remaining operations will be attempted nonetheless.

        # Required parameters

        - source: a non-empty string or an IO object

        # Optional parameters

        - namespace: a non-empty string (`default` by default)
        - ...

        Other keywords parameters can be specified.  They will be passed
        as-is to the Kubernetes API.

        # Returned value

        None.

        # Raised exceptions

        If at least one Kubernetes operation fails, a _KubernetesError_
        exception is raised.  Its `api_exceptions` attribute contain the
        list of exceptions raised by the failed Kubernetes operations.
        """
        from .kubehelpers import _map, _apply_from_dict

        _map(
            _apply_from_dict,
            source,
            self._get_apiclient(),
            namespace=namespace,
            **kwargs,
        )
